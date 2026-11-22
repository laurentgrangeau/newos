//! Userspace-only, lock-free SPSC shared-memory ring buffer (`#![forbid(unsafe_code)]`, `no_alloc`).
//!
//! Pure seL4 design: Ring 0 never parses ring buffers. Two Ring-3 processes share a mapped
//! `Frame` containing an `SpscRing` and use a 64-bit kernel `Notification` capability for wakeups.

use crate::SysError;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[repr(C, align(64))]
struct CachePaddedIndex(AtomicUsize);

/// Lock-free, wait-free Single-Producer Single-Consumer ring buffer of 64-bit words.
///
/// Capacity `N` must be a power of two (`N >= 2`). One slot distinguishes full from empty,
/// so up to `N - 1` items may be buffered simultaneously.
#[repr(C)]
pub struct SpscRing<const N: usize> {
    head: CachePaddedIndex,
    tail: CachePaddedIndex,
    slots: [AtomicU64; N],
}

impl<const N: usize> Default for SpscRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SpscRing<N> {
    const _ASSERT_POW2: () = assert!(N >= 2 && (N & (N - 1)) == 0, "SpscRing capacity must be power of two >= 2");

    pub const fn new() -> Self {
        let () = Self::_ASSERT_POW2;
        Self {
            head: CachePaddedIndex(AtomicUsize::new(0)),
            tail: CachePaddedIndex(AtomicUsize::new(0)),
            slots: [const { AtomicU64::new(0) }; N],
        }
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        N - 1
    }

    /// Push one 64-bit word into the ring without blocking (`Release` publish).
    pub fn try_push(&self, word: u64) -> Result<(), SysError> {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let next_tail = (tail + 1) & (N - 1);
        let head = self.head.0.load(Ordering::Acquire);
        if next_tail == head {
            return Err(SysError::WouldBlock);
        }
        self.slots[tail].store(word, Ordering::Relaxed);
        self.tail.0.store(next_tail, Ordering::Release);
        Ok(())
    }

    /// Pop one 64-bit word from the ring without blocking (`Acquire` consume).
    pub fn try_pop(&self) -> Option<u64> {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let word = self.slots[head].load(Ordering::Relaxed);
        let next_head = (head + 1) & (N - 1);
        self.head.0.store(next_head, Ordering::Release);
        Some(word)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.0.load(Ordering::Acquire) == self.tail.0.load(Ordering::Acquire)
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
}
