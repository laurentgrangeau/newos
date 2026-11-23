//! Userspace-only, lock-free SPSC shared-memory ring buffer (`#![forbid(unsafe_code)]`, `no_alloc`).
//!
//! Pure seL4 design: EL1 never parses ring buffers. Two EL0 processes share a mapped
//! `Frame` containing an `SpscRing` and use a 64-bit kernel `Notification` capability for wakeups.

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

impl<const N: usize> SpscRing<N> {
    const _ASSERT_POW2: () = assert!(
        N >= 2 && (N & (N - 1)) == 0,
        "SpscRing capacity must be power of two >= 2"
    );

    pub const fn new() -> Self {
        let () = Self::_ASSERT_POW2;
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
    pub const fn capacity(&self) -> usize {
        N - 1
    }

    /// Push one 64-bit word into the ring without blocking (`Release` publish).
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
    pub fn len(&self) -> usize {
        let head = self.consumer.head.load(Ordering::Acquire);
        let tail = self.producer.tail.load(Ordering::Acquire);
        tail.wrapping_sub(head) & (N - 1)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        let head = self.consumer.head.load(Ordering::Acquire) & (N - 1);
        let tail = self.producer.tail.load(Ordering::Acquire) & (N - 1);
        head == tail
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        let head = self.consumer.head.load(Ordering::Acquire) & (N - 1);
        let tail = self.producer.tail.load(Ordering::Acquire) & (N - 1);
        ((tail + 1) & (N - 1)) == head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
