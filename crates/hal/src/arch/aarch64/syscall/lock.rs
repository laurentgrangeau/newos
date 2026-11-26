//! IRQ-disabling spinlock protecting kernel globals across EL0 syscalls, EL0 IRQs, and SMP cores.
//!
//! Lock hierarchy (always acquire in this order when holding more than one):
//! `DOMAINS` -> `IPC_STATE` -> `RUNTIME_UNTYPED` -> `FRAME_MAPPINGS`.
//! Leaf locks (`IRQ_TABLE`, `PL011_LOCK`, `BOARD_IRQS`, `BOOT_MODULES`, `EXTRA_MMIO_MAPS`)
//! are never held while acquiring `DOMAINS` or `IPC_STATE`.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// IRQ-disabling spinlock with RAII `DAIF` restore on drop.
pub(in crate::arch::aarch64) struct IrqSpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: `IrqSpinLock` serializes all access with `Acquire`/`Release` atomics and masks local IRQs.
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

/// RAII guard for [`IrqSpinLock`] that releases the lock and restores saved `DAIF` on drop.
pub(in crate::arch::aarch64) struct IrqSpinLockGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    saved_daif: u64,
}

impl<T> IrqSpinLock<T> {
    #[must_use]
    pub(in crate::arch::aarch64) const fn new(val: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(val),
        }
    }

    #[inline]
    pub(in crate::arch::aarch64) fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let saved_daif: u64;
        // SAFETY: Saving `DAIF` and masking local IRQs (`daifset #2`) in EL1 prevents same-CPU
        // IRQ re-entrancy deadlocks while the spinlock is held.
        unsafe {
            asm!("mrs {}, daif", out(reg) saved_daif, options(nomem, nostack));
            asm!("msr daifset, #2", options(nomem, nostack));
        }
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        IrqSpinLockGuard {
            lock: self,
            saved_daif,
        }
    }
}

impl<T> Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: The guard holds exclusive ownership of `self.lock`.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqSpinLockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: The guard holds exclusive ownership of `self.lock`.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for IrqSpinLockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        // SAFETY: Restoring `DAIF` to its pre-lock value in EL1 after releasing the spinlock.
        unsafe {
            asm!("msr daif, {}", in(reg) self.saved_daif, options(nomem, nostack));
        }
    }
}
