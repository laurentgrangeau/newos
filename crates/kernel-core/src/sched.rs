//! Zero-heap, `#![forbid(unsafe_code)]` priority + round-robin microkernel scheduler.

use newos_abi::SysError;

/// Unique kernel thread identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ThreadId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Blocked,
    Exited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadControlBlock {
    pub id: ThreadId,
    pub priority: u8,
    pub state: ThreadState,
    pub yields: u64,
}

/// Fixed-capacity, `no_alloc` priority + round-robin scheduler.
pub struct Scheduler<const MAX_THREADS: usize> {
    threads: [Option<ThreadControlBlock>; MAX_THREADS],
    current: Option<usize>,
    next_id: u32,
}

impl<const MAX_THREADS: usize> Default for Scheduler<MAX_THREADS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_THREADS: usize> Scheduler<MAX_THREADS> {
    pub const fn new() -> Self {
        Self {
            threads: [None; MAX_THREADS],
            current: None,
            next_id: 1,
        }
    }

    /// Spawn a new runnable thread with `priority` (higher value = higher priority).
    pub fn spawn(&mut self, priority: u8) -> Result<ThreadId, SysError> {
        for slot in &mut self.threads {
            if slot.is_none() {
                let id = ThreadId(self.next_id);
                self.next_id = self.next_id.wrapping_add(1);
                *slot = Some(ThreadControlBlock {
                    id,
                    priority,
                    state: ThreadState::Ready,
                    yields: 0,
                });
                return Ok(id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Pick the highest-priority runnable thread (round-robin among equal priorities).
    pub fn schedule_next(&mut self) -> Option<ThreadId> {
        let start = self.current.map(|c| (c + 1) % MAX_THREADS).unwrap_or(0);

        if let Some(cur) = self.current
            && let Some(tcb) = &mut self.threads[cur]
            && tcb.state == ThreadState::Running
        {
            tcb.state = ThreadState::Ready;
        }

        let mut best: Option<(usize, u8)> = None;
        for offset in 0..MAX_THREADS {
            let idx = (start + offset) % MAX_THREADS;
            if let Some(tcb) = &self.threads[idx]
                && tcb.state == ThreadState::Ready
            {
                let is_better = match best {
                    None => true,
                    Some((_, best_prio)) => tcb.priority > best_prio,
                };
                if is_better {
                    best = Some((idx, tcb.priority));
                }
            }
        }

        if let Some((idx, _)) = best {
            self.current = Some(idx);
            if let Some(tcb) = &mut self.threads[idx] {
                tcb.state = ThreadState::Running;
                return Some(tcb.id);
            }
        }
        None
    }

    /// Record a cooperative yield for the currently running thread and re-schedule.
    pub fn yield_current(&mut self) -> Option<u64> {
        let cur = self.current?;
        let yields = if let Some(tcb) = &mut self.threads[cur] {
            tcb.yields = tcb.yields.saturating_add(1);
            tcb.yields
        } else {
            return None;
        };
        let _ = self.schedule_next();
        Some(yields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_and_round_robin_scheduling() {
        let mut sched = Scheduler::<8>::new();
        let low = sched.spawn(1).unwrap();
        let high_a = sched.spawn(10).unwrap();
        let high_b = sched.spawn(10).unwrap();

        assert_eq!(sched.schedule_next(), Some(high_a));
        assert_eq!(sched.schedule_next(), Some(high_b));
        assert_eq!(sched.schedule_next(), Some(high_a));
        assert_ne!(low, high_a);
    }

    #[test]
    fn yield_increments_counter() {
        let mut sched = Scheduler::<4>::new();
        let _ = sched.spawn(5).unwrap();
        let _ = sched.schedule_next();
        assert_eq!(sched.yield_current(), Some(1));
        assert_eq!(sched.yield_current(), Some(2));
    }
}
