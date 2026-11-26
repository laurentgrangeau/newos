//! Userspace-only, lock-free SPSC shared-memory ring buffer.
//!
//! EL1 never parses ring buffers. Two EL0 protection domains share a mapped
//! `Frame` containing an `SpscRing` and use a 64-bit kernel `Notification` capability for wakeups.
//!
//! ```
//! use newos_abi::ring::SpscRing;
//!
//! let ring = SpscRing::<8>::new();
//! assert!(ring.try_push(0x5E14).is_ok());
//! assert_eq!(ring.try_pop(), Some(0x5E14));
//! assert!(ring.is_empty());
//! ```

use crate::SysError;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[repr(C, align(64))]
struct ConsumerLine {
    head: AtomicUsize,
    cached_tail: AtomicUsize,
}

#[repr(C, align(64))]
struct ProducerLine {
    tail: AtomicUsize,
    cached_head: AtomicUsize,
}

/// Lock-free, wait-free Single-Producer Single-Consumer ring buffer of 64-bit words.
///
/// Capacity `N` must be a power of two (`N >= 2`). One slot distinguishes full from empty,
/// so up to `N - 1` items may be buffered simultaneously.
#[repr(C)]
pub struct SpscRing<const N: usize> {
    consumer: ConsumerLine,
    producer: ProducerLine,
    slots: [AtomicU64; N],
}

impl<const N: usize> Default for SpscRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::fmt::Debug for SpscRing<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpscRing")
            .field("capacity", &self.capacity())
            .field("len", &self.len())
            .field(
                "head",
                &(self.consumer.head.load(Ordering::Acquire) & (N - 1)),
            )
            .field(
                "tail",
                &(self.producer.tail.load(Ordering::Acquire) & (N - 1)),
            )
            .finish_non_exhaustive()
    }
}

impl<const N: usize> SpscRing<N> {
    const ASSERT_POW2: () = assert!(
        N >= 2 && N.is_power_of_two(),
        "SpscRing capacity must be power of two >= 2"
    );

    const FRAME_MAGIC: u64 = 0x5249_4E47;

    #[must_use]
    pub const fn new() -> Self {
        let () = Self::ASSERT_POW2;
        Self {
            consumer: ConsumerLine {
                head: AtomicUsize::new(0),
                cached_tail: AtomicUsize::new(0),
            },
            producer: ProducerLine {
                tail: AtomicUsize::new(0),
                cached_head: AtomicUsize::new(0),
            },
            slots: [const { AtomicU64::new(0) }; N],
        }
    }

    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N - 1
    }

    /// Push one 64-bit word into the ring without blocking (`Release` publish).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::WouldBlock`] if the ring is full.
    #[inline]
    pub fn try_push(&self, word: u64) -> Result<(), SysError> {
        let tail = self.producer.tail.load(Ordering::Relaxed) & (N - 1);
        let next_tail = (tail + 1) & (N - 1);
        let mut head = self.producer.cached_head.load(Ordering::Relaxed) & (N - 1);
        if next_tail == head {
            head = self.consumer.head.load(Ordering::Acquire) & (N - 1);
            self.producer.cached_head.store(head, Ordering::Relaxed);
            if next_tail == head {
                return Err(SysError::WouldBlock);
            }
        }
        self.slots[tail].store(word, Ordering::Relaxed);
        self.producer.tail.store(next_tail, Ordering::Release);
        Ok(())
    }

    /// Pop one 64-bit word from the ring without blocking (`Acquire` consume).
    #[inline]
    pub fn try_pop(&self) -> Option<u64> {
        let head = self.consumer.head.load(Ordering::Relaxed) & (N - 1);
        let mut tail = self.consumer.cached_tail.load(Ordering::Relaxed) & (N - 1);
        if head == tail {
            tail = self.producer.tail.load(Ordering::Acquire) & (N - 1);
            self.consumer.cached_tail.store(tail, Ordering::Relaxed);
            if head == tail {
                return None;
            }
        }
        let word = self.slots[head].load(Ordering::Relaxed);
        let next_head = (head + 1) & (N - 1);
        self.consumer.head.store(next_head, Ordering::Release);
        Some(word)
    }

    /// Push up to `src.len()` words in a single batch with one `Release` commit.
    #[inline]
    pub fn try_push_slice(&self, src: &[u64]) -> usize {
        if src.is_empty() {
            return 0;
        }
        let tail = self.producer.tail.load(Ordering::Relaxed) & (N - 1);
        let mut head = self.producer.cached_head.load(Ordering::Relaxed) & (N - 1);
        let mut free = head.wrapping_sub(tail).wrapping_sub(1) & (N - 1);
        if free < src.len() {
            head = self.consumer.head.load(Ordering::Acquire) & (N - 1);
            self.producer.cached_head.store(head, Ordering::Relaxed);
            free = head.wrapping_sub(tail).wrapping_sub(1) & (N - 1);
            if free == 0 {
                return 0;
            }
        }

        let count = src.len().min(free);
        let first_chunk = count.min(N - tail);
        for (slot, &word) in self.slots[tail..tail + first_chunk]
            .iter()
            .zip(&src[..first_chunk])
        {
            slot.store(word, Ordering::Relaxed);
        }
        let second_chunk = count - first_chunk;
        if second_chunk > 0 {
            for (slot, &word) in self.slots[..second_chunk]
                .iter()
                .zip(&src[first_chunk..count])
            {
                slot.store(word, Ordering::Relaxed);
            }
        }

        let new_tail = (tail + count) & (N - 1);
        self.producer.tail.store(new_tail, Ordering::Release);
        count
    }

    /// Pop up to `dst.len()` words in a single batch with one `Release` commit.
    #[inline]
    pub fn try_pop_slice(&self, dst: &mut [u64]) -> usize {
        if dst.is_empty() {
            return 0;
        }
        let head = self.consumer.head.load(Ordering::Relaxed) & (N - 1);
        let mut tail = self.consumer.cached_tail.load(Ordering::Relaxed) & (N - 1);
        let mut avail = tail.wrapping_sub(head) & (N - 1);
        if avail < dst.len() {
            tail = self.producer.tail.load(Ordering::Acquire) & (N - 1);
            self.consumer.cached_tail.store(tail, Ordering::Relaxed);
            avail = tail.wrapping_sub(head) & (N - 1);
            if avail == 0 {
                return 0;
            }
        }

        let count = dst.len().min(avail);
        let first_chunk = count.min(N - head);
        for (out, slot) in dst[..first_chunk]
            .iter_mut()
            .zip(&self.slots[head..head + first_chunk])
        {
            *out = slot.load(Ordering::Relaxed);
        }
        let second_chunk = count - first_chunk;
        if second_chunk > 0 {
            for (out, slot) in dst[first_chunk..count]
                .iter_mut()
                .zip(&self.slots[..second_chunk])
            {
                *out = slot.load(Ordering::Relaxed);
            }
        }

        let new_head = (head + count) & (N - 1);
        self.consumer.head.store(new_head, Ordering::Release);
        count
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        let head = self.consumer.head.load(Ordering::Acquire);
        let tail = self.producer.tail.load(Ordering::Acquire);
        tail.wrapping_sub(head) & (N - 1)
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let head = self.consumer.head.load(Ordering::Acquire) & (N - 1);
        let tail = self.producer.tail.load(Ordering::Acquire) & (N - 1);
        head == tail
    }

    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        let head = self.consumer.head.load(Ordering::Acquire) & (N - 1);
        let tail = self.producer.tail.load(Ordering::Acquire) & (N - 1);
        ((tail + 1) & (N - 1)) == head
    }

    /// Push a length-prefixed byte frame into the word ring with a single `Release` tail commit.
    ///
    /// Format: 1 header word `((0x5249_4E47 << 32) | byte_len)` followed by `ceil(byte_len / 8)`
    /// little-endian 64-bit payload words.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::WouldBlock`] if the ring does not have space for the entire frame
    /// (no partial writes), or [`SysError::InvalidArgument`] if `data` exceeds the ring's
    /// maximum frame capacity or `u32::MAX` bytes.
    pub fn try_push_bytes(&self, data: &[u8]) -> Result<usize, SysError> {
        let payload_words = data.len().div_ceil(8);
        let total_words = 1usize.saturating_add(payload_words);
        if total_words > self.capacity() || data.len() > u32::MAX as usize {
            return Err(SysError::InvalidArgument);
        }

        let tail = self.producer.tail.load(Ordering::Relaxed) & (N - 1);
        let mut head = self.producer.cached_head.load(Ordering::Relaxed) & (N - 1);
        let mut used = tail.wrapping_sub(head) & (N - 1);
        let mut free = (N - 1) - used;
        if free < total_words {
            head = self.consumer.head.load(Ordering::Acquire) & (N - 1);
            self.producer.cached_head.store(head, Ordering::Relaxed);
            used = tail.wrapping_sub(head) & (N - 1);
            free = (N - 1) - used;
            if free < total_words {
                return Err(SysError::WouldBlock);
            }
        }

        let header = (Self::FRAME_MAGIC << 32) | (data.len() as u64);
        self.slots[tail].store(header, Ordering::Relaxed);
        let mut idx = (tail + 1) & (N - 1);
        let mut off = 0usize;
        while off < data.len() {
            let mut buf = [0u8; 8];
            let chunk = (data.len() - off).min(8);
            buf[..chunk].copy_from_slice(&data[off..off + chunk]);
            self.slots[idx].store(u64::from_le_bytes(buf), Ordering::Relaxed);
            idx = (idx + 1) & (N - 1);
            off += chunk;
        }
        self.producer.tail.store(idx, Ordering::Release);
        Ok(data.len())
    }

    /// Pop one length-prefixed byte frame written by [`Self::try_push_bytes`] with a single
    /// `Acquire` load and `Release` head commit.
    ///
    /// Returns `None` if empty or if the frame header is corrupted (safely resynchronizing head
    /// to tail on corrupted peer headers without panicking). Truncates to `out.len()` if `out` is
    /// smaller than the framed payload while still consuming the full frame from the ring.
    pub fn try_pop_bytes(&self, out: &mut [u8]) -> Option<usize> {
        let head = self.consumer.head.load(Ordering::Relaxed) & (N - 1);
        let mut tail = self.consumer.cached_tail.load(Ordering::Relaxed) & (N - 1);
        if head == tail {
            tail = self.producer.tail.load(Ordering::Acquire) & (N - 1);
            self.consumer.cached_tail.store(tail, Ordering::Relaxed);
            if head == tail {
                return None;
            }
        }

        let avail = tail.wrapping_sub(head) & (N - 1);
        let header = self.slots[head].load(Ordering::Relaxed);
        if (header >> 32) != Self::FRAME_MAGIC {
            // Corrupted peer header: drop ring contents safely without panicking.
            self.consumer.head.store(tail, Ordering::Release);
            return None;
        }
        let byte_len = (header & 0xFFFF_FFFF) as usize;
        let payload_words = byte_len.div_ceil(8);
        let total_words = 1usize.saturating_add(payload_words);
        if total_words > avail || total_words > self.capacity() {
            // Incomplete or bogus frame length from corrupted peer: resync safely.
            self.consumer.head.store(tail, Ordering::Release);
            return None;
        }

        let copy_len = byte_len.min(out.len());
        let mut idx = (head + 1) & (N - 1);
        let mut copied = 0usize;
        for _ in 0..payload_words {
            let w = self.slots[idx].load(Ordering::Relaxed).to_le_bytes();
            if copied < copy_len {
                let n = (copy_len - copied).min(8);
                out[copied..copied + n].copy_from_slice(&w[..n]);
                copied += n;
            }
            idx = (idx + 1) & (N - 1);
        }
        self.consumer.head.store(idx, Ordering::Release);
        Some(copy_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsc_ring_bytes_roundtrip_wraparound_and_corrupted_header() {
        let ring = SpscRing::<16>::new();
        assert_eq!(ring.try_pop_bytes(&mut [0u8; 32]), None);

        // Push & pop across wraparound multiple times
        for i in 0..10u8 {
            let msg = [
                i,
                i + 1,
                i + 2,
                i + 3,
                i + 4,
                i + 5,
                i + 6,
                i + 7,
                i + 8,
                i + 9,
            ];
            assert_eq!(ring.try_push_bytes(&msg), Ok(msg.len()));
            let mut out = [0u8; 32];
            assert_eq!(ring.try_pop_bytes(&mut out), Some(msg.len()));
            assert_eq!(&out[..msg.len()], &msg);
        }

        // Oversized payload rejected with InvalidArgument
        assert_eq!(
            ring.try_push_bytes(&[0xAA; 256]),
            Err(SysError::InvalidArgument)
        );

        // Corrupted peer header is safely dropped without panicking
        assert_eq!(ring.try_push(0xDEAD_BEEF_0000_0010), Ok(()));
        assert_eq!(ring.try_pop_bytes(&mut [0u8; 32]), None);
        assert!(ring.is_empty());
    }

    #[test]
    fn spsc_ring_debug_format_includes_metadata() {
        use core::fmt::Write as _;

        struct StackWriter {
            buf: [u8; 128],
            len: usize,
        }

        impl core::fmt::Write for StackWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let avail = self.buf.len().saturating_sub(self.len);
                let copy = bytes.len().min(avail);
                self.buf[self.len..self.len + copy].copy_from_slice(&bytes[..copy]);
                self.len += copy;
                Ok(())
            }
        }

        let ring = SpscRing::<8>::new();
        assert_eq!(ring.try_push(42), Ok(()));
        assert_eq!(ring.try_push(99), Ok(()));

        let mut writer = StackWriter {
            buf: [0u8; 128],
            len: 0,
        };
        assert!(write!(&mut writer, "{ring:?}").is_ok());
        let formatted = core::str::from_utf8(&writer.buf[..writer.len]).unwrap_or("");
        assert!(formatted.contains("SpscRing"));
        assert!(formatted.contains("capacity: 7"));
        assert!(formatted.contains("len: 2"));
        assert!(formatted.contains("head: 0"));
        assert!(formatted.contains("tail: 2"));
    }

    #[test]
    fn spsc_ring_bytes_empty_truncation_wouldblock_and_bogus_len() {
        let ring = SpscRing::<8>::new();
        // Empty byte frame roundtrip
        assert_eq!(ring.try_push_bytes(&[]), Ok(0));
        let mut out = [0xFFu8; 8];
        assert_eq!(ring.try_pop_bytes(&mut out), Some(0));
        assert!(ring.is_empty());

        // Fill ring nearly full (capacity = 7 words); a 16-byte frame needs 3 words.
        assert_eq!(ring.try_push_bytes(&[1u8; 24]), Ok(24)); // 1 + 3 = 4 words
        assert_eq!(ring.len(), 4);
        // Remaining free = 3 words; a 24-byte frame needs 4 words -> WouldBlock with no partial write.
        assert_eq!(ring.try_push_bytes(&[2u8; 24]), Err(SysError::WouldBlock));
        assert_eq!(ring.len(), 4);

        // Truncated pop: out.len() < byte_len copies out.len() bytes and consumes the full frame.
        let mut small = [0u8; 5];
        assert_eq!(ring.try_pop_bytes(&mut small), Some(5));
        assert_eq!(small, [1u8; 5]);
        assert!(ring.is_empty());

        // Valid magic with bogus length exceeding available words triggers safe resync.
        let bogus_header = (SpscRing::<8>::FRAME_MAGIC << 32) | 0x28;
        assert_eq!(ring.try_push(bogus_header), Ok(()));
        assert_eq!(ring.try_pop_bytes(&mut out), None);
        assert!(ring.is_empty());
    }

    #[test]
    fn spsc_ring_fill_overflow_and_wraparound() {
        let ring = SpscRing::<4>::new();
        assert_eq!(ring.capacity(), 3);
        assert!(ring.is_empty());

        assert_eq!(ring.try_push(10), Ok(()));
        assert_eq!(ring.try_push(20), Ok(()));
        assert_eq!(ring.try_push(30), Ok(()));
        assert_eq!(ring.try_push(40), Err(SysError::WouldBlock));

        assert_eq!(ring.try_pop(), Some(10));
        assert_eq!(ring.try_push(40), Ok(()));
        assert_eq!(ring.try_pop(), Some(20));
        assert_eq!(ring.try_pop(), Some(30));
        assert_eq!(ring.try_pop(), Some(40));
        assert_eq!(ring.try_pop(), None);
        assert!(ring.is_empty());
    }

    #[test]
    fn spsc_ring_len_and_is_full_states() {
        let ring = SpscRing::<4>::new();
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
        assert!(!ring.is_full());

        assert_eq!(ring.try_push(1), Ok(()));
        assert_eq!(ring.len(), 1);
        assert!(!ring.is_empty());
        assert!(!ring.is_full());

        assert_eq!(ring.try_push(2), Ok(()));
        assert_eq!(ring.try_push(3), Ok(()));
        assert_eq!(ring.len(), 3);
        assert!(ring.is_full());

        // Pop 2, push 2 to wrap indices around N=4.
        assert_eq!(ring.try_pop(), Some(1));
        assert_eq!(ring.try_pop(), Some(2));
        assert_eq!(ring.len(), 1);
        assert!(!ring.is_full());

        assert_eq!(ring.try_push(4), Ok(()));
        assert_eq!(ring.try_push(5), Ok(()));
        assert_eq!(ring.len(), 3);
        assert!(ring.is_full());
        assert_eq!(ring.try_push(6), Err(SysError::WouldBlock));
    }

    #[test]
    fn spsc_ring_min_capacity_n2() {
        let ring = SpscRing::<2>::new();
        assert_eq!(ring.capacity(), 1);
        assert!(ring.is_empty());
        assert!(!ring.is_full());

        for i in 0..8u64 {
            assert_eq!(ring.try_push(i), Ok(()));
            assert!(ring.is_full());
            assert_eq!(ring.len(), 1);
            assert_eq!(ring.try_push(99), Err(SysError::WouldBlock));
            assert_eq!(ring.try_pop(), Some(i));
            assert!(ring.is_empty());
        }

        // Slice ops on N=2 across multiple wraps.
        for i in 10..16u64 {
            assert_eq!(ring.try_push_slice(&[i, i + 100]), 1);
            assert_eq!(ring.try_push_slice(&[999]), 0);
            let mut out = [0u64; 2];
            assert_eq!(ring.try_pop_slice(&mut out), 1);
            assert_eq!(out[0], i);
            assert_eq!(ring.try_pop_slice(&mut out), 0);
        }
    }

    #[test]
    fn spsc_ring_slice_empty_and_partial_fill_drain() {
        let ring = SpscRing::<8>::new();
        assert_eq!(ring.try_push_slice(&[]), 0);
        assert_eq!(ring.try_pop_slice(&mut []), 0);

        let src = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(ring.try_push_slice(&src), 7);
        assert!(ring.is_full());
        assert_eq!(ring.try_push_slice(&src), 0);

        let mut dst = [0u64; 4];
        assert_eq!(ring.try_pop_slice(&mut dst), 4);
        assert_eq!(dst, [1, 2, 3, 4]);
        assert_eq!(ring.len(), 3);

        let mut rest = [0u64; 10];
        assert_eq!(ring.try_pop_slice(&mut rest), 3);
        assert_eq!(&rest[..3], &[5, 6, 7]);
        assert!(ring.is_empty());
        assert_eq!(ring.try_pop_slice(&mut rest), 0);
    }

    #[test]
    fn spsc_ring_slice_wraparound_exact_order() {
        let ring = SpscRing::<8>::new();
        // Advance head and tail to index 5 (near end of 8-slot backing array).
        assert_eq!(ring.try_push_slice(&[10, 11, 12, 13, 14]), 5);
        let mut tmp = [0u64; 5];
        assert_eq!(ring.try_pop_slice(&mut tmp), 5);
        assert_eq!(tmp, [10, 11, 12, 13, 14]);
        assert!(ring.is_empty());

        // Push & pop slices spanning the wrap boundary multiple times.
        let mut next_val = 100u64;
        for _ in 0..6 {
            let batch = [
                next_val,
                next_val + 1,
                next_val + 2,
                next_val + 3,
                next_val + 4,
                next_val + 5,
            ];
            assert_eq!(ring.try_push_slice(&batch), 6);
            assert_eq!(ring.len(), 6);

            let mut out = [0u64; 6];
            assert_eq!(ring.try_pop_slice(&mut out), 6);
            assert_eq!(out, batch);
            assert!(ring.is_empty());
            next_val += 6;
        }
    }

    #[test]
    fn spsc_ring_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SpscRing<64>>();
        assert_eq!(core::mem::align_of::<SpscRing<64>>(), 64);
    }

    #[test]
    fn spsc_ring_survives_corrupted_peer_indices_without_panicking() {
        let ring = SpscRing::<8>::new();
        // Simulate a malicious peer sharing the RW frame writing out-of-range indices >= N
        // and boundary values like usize::MAX (which would overflow `tail + 1` if unmasked).
        ring.producer.tail.store(usize::MAX, Ordering::Relaxed);
        ring.consumer.head.store(usize::MAX, Ordering::Relaxed);
        assert!(ring.is_empty());
        assert!(!ring.is_full());
        assert_eq!(ring.len(), 0);

        // Unmasked values congruent mod N: tail = N + 3, head = 3 => empty.
        ring.producer.tail.store(8 + 3, Ordering::Relaxed);
        ring.consumer.head.store(3, Ordering::Relaxed);
        assert!(ring.is_empty());
        assert!(!ring.is_full());
        assert_eq!(ring.len(), 0);

        // Unmasked values representing full ring: tail = usize::MAX (mod 8 == 7), head = 8 (mod 8 == 0).
        ring.producer.tail.store(usize::MAX, Ordering::Relaxed);
        ring.consumer.head.store(8, Ordering::Relaxed);
        assert!(!ring.is_empty());
        assert!(ring.is_full());
        assert_eq!(ring.len(), 7);

        ring.producer.tail.store(usize::MAX - 3, Ordering::Relaxed);
        ring.consumer.head.store(12345, Ordering::Relaxed);
        let _ = ring.is_empty();
        let _ = ring.is_full();
        let _ = ring.len();
        let _ = ring.try_push(0xAA);
        let _ = ring.try_push_slice(&[]);
        let _ = ring.try_push_slice(&[1, 2, 3, 4]);
        let mut out = [0u64; 4];
        let _ = ring.try_pop();
        let _ = ring.try_pop_slice(&mut []);
        let _ = ring.try_pop_slice(&mut out);
    }

    #[cfg(not(loom))]
    #[test]
    fn spsc_ring_concurrent_producer_consumer_10k_items() {
        extern crate std;
        use std::sync::Arc;
        use std::thread;

        const COUNT: u64 = 10_000;
        let ring = Arc::new(SpscRing::<64>::new());
        let prod_ring = Arc::clone(&ring);

        let producer = thread::spawn(move || {
            for i in 0..COUNT {
                while prod_ring.try_push(i ^ 0x5E14_C0DE_0000_0000).is_err() {
                    thread::yield_now();
                }
            }
        });

        for i in 0..COUNT {
            loop {
                if let Some(v) = ring.try_pop() {
                    assert_eq!(v, i ^ 0x5E14_C0DE_0000_0000);
                    break;
                }
                thread::yield_now();
            }
        }
        assert!(producer.join().is_ok());
        assert!(ring.is_empty());
    }

    #[cfg(loom)]
    #[test]
    fn loom_spsc_ring_acquire_release_interleavings() {
        use loom::sync::Arc;
        use loom::thread;

        loom::model(|| {
            let ring = Arc::new(SpscRing::<4>::new());
            let prod = Arc::clone(&ring);
            let t = thread::spawn(move || {
                for v in 1u64..=3 {
                    while prod.try_push(v).is_err() {
                        thread::yield_now();
                    }
                }
            });
            let mut got = [0u64; 3];
            for slot in &mut got {
                loop {
                    if let Some(v) = ring.try_pop() {
                        *slot = v;
                        break;
                    }
                    thread::yield_now();
                }
            }
            assert!(t.join().is_ok());
            assert_eq!(got, [1, 2, 3]);
        });
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove that `SpscRing<4>` never panics or overflows even under arbitrary corrupted peer
    /// indices, and preserves exact FIFO ordering for valid producer/consumer sequences.
    #[kani::proof]
    fn spsc_ring_fifo_and_corrupted_peer_safety() {
        let ring = SpscRing::<4>::new();
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        let c: u64 = kani::any();

        assert_eq!(ring.try_push(a), Ok(()));
        assert_eq!(ring.try_push(b), Ok(()));
        assert_eq!(ring.try_push(c), Ok(()));
        assert_eq!(ring.try_push(0), Err(SysError::WouldBlock));
        assert_eq!(ring.try_pop(), Some(a));
        assert_eq!(ring.try_pop(), Some(b));
        assert_eq!(ring.try_pop(), Some(c));
        assert_eq!(ring.try_pop(), None);

        // Corrupt producer/consumer indices arbitrarily (untrusted peer model)
        let bad_tail: usize = kani::any();
        let bad_head: usize = kani::any();
        ring.producer.tail.store(bad_tail, Ordering::Relaxed);
        ring.consumer.head.store(bad_head, Ordering::Relaxed);
        let _ = ring.len();
        let _ = ring.is_empty();
        let _ = ring.is_full();
        let _ = ring.try_push(a);
        let _ = ring.try_pop();
    }
}
