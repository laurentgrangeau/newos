//! Zero-heap, `#![forbid(unsafe_code)]` priority + round-robin microkernel scheduler
//! with preemptive time-slice accounting and per-CPU SMP runqueues with work-stealing.

use newos_abi::SysError;

/// Default preemptive time slice in timer ticks before round-robin preemption.
pub const DEFAULT_TIME_SLICE: u32 = 4;

/// Default priority assigned to normal userspace processes.
pub const DEFAULT_PRIORITY: u8 = 16;

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
    pub quantum_remaining: u32,
    pub cpu_affinity: u8,
    pub preemptions: u64,
}

/// Fixed-capacity, `no_alloc` priority + round-robin scheduler.
pub struct Scheduler<const MAX_THREADS: usize> {
    threads: [Option<ThreadControlBlock>; MAX_THREADS],
    priorities: [u8; MAX_THREADS],
    ready_mask: u64,
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
            priorities: [0; MAX_THREADS],
            ready_mask: 0,
            current: None,
            next_id: 1,
        }
    }

    /// Spawn a new runnable thread on CPU 0 with `priority` (higher value = higher priority).
    pub fn spawn(&mut self, priority: u8) -> Result<ThreadId, SysError> {
        self.spawn_on_cpu(priority, 0)
    }

    /// Spawn a new runnable thread with `priority` and preferred `cpu_affinity`.
    pub fn spawn_on_cpu(&mut self, priority: u8, cpu_affinity: u8) -> Result<ThreadId, SysError> {
        for (idx, slot) in self.threads.iter_mut().enumerate() {
            if slot.is_none() {
                let id = ThreadId(self.next_id);
                self.next_id = self.next_id.wrapping_add(1);
                *slot = Some(ThreadControlBlock {
                    id,
                    priority,
                    state: ThreadState::Ready,
                    yields: 0,
                    quantum_remaining: DEFAULT_TIME_SLICE,
                    cpu_affinity,
                    preemptions: 0,
                });
                self.priorities[idx] = priority;
                if idx < 64 {
                    self.ready_mask |= 1u64 << idx;
                }
                return Ok(id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Return the currently executing slot index, if any.
    #[inline]
    pub const fn current_slot(&self) -> Option<usize> {
        self.current
    }

    /// Inspect a thread control block by slot index.
    #[inline]
    pub fn tcb(&self, slot: usize) -> Option<&ThreadControlBlock> {
        self.threads.get(slot)?.as_ref()
    }

    /// Count active (non-exited) threads managed by this runqueue.
    pub fn active_count(&self) -> usize {
        self.threads
            .iter()
            .filter(|t| matches!(t, Some(tcb) if tcb.state != ThreadState::Exited))
            .count()
    }

    /// Count currently `Ready` (runnable, not running) threads.
    #[inline]
    pub fn ready_count(&self) -> usize {
        if MAX_THREADS <= 64 {
            self.ready_mask.count_ones() as usize
        } else {
            self.threads
                .iter()
                .filter(|t| matches!(t, Some(tcb) if tcb.state == ThreadState::Ready))
                .count()
        }
    }

    /// Update the priority of the thread at `slot`.
    pub fn set_priority(&mut self, slot: usize, priority: u8) -> Result<(), SysError> {
        let tcb = self
            .threads
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(SysError::InvalidArgument)?;
        tcb.priority = priority;
        self.priorities[slot] = priority;
        Ok(())
    }

    /// Transition `slot` to `Blocked` (e.g., waiting on synchronous IPC) and remove from `ready_mask`.
    #[inline]
    pub fn block_slot(&mut self, slot: usize) -> Result<(), SysError> {
        let tcb = self
            .threads
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(SysError::InvalidArgument)?;
        tcb.state = ThreadState::Blocked;
        if slot < 64 {
            self.ready_mask &= !(1u64 << slot);
        }
        if self.current == Some(slot) {
            self.current = None;
        }
        Ok(())
    }

    /// Wake a `Blocked` thread at `slot` back to `Ready` and mark it runnable in `ready_mask`.
    #[inline]
    pub fn wake_slot(&mut self, slot: usize) -> Result<(), SysError> {
        let tcb = self
            .threads
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(SysError::InvalidArgument)?;
        if tcb.state == ThreadState::Blocked {
            tcb.state = ThreadState::Ready;
            if slot < 64 {
                self.ready_mask |= 1u64 << slot;
            }
        }
        Ok(())
    }

    /// Mark `slot` as `Exited` and remove it from scheduling.
    #[inline]
    pub fn exit_slot(&mut self, slot: usize) -> Result<(), SysError> {
        let tcb = self
            .threads
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(SysError::InvalidArgument)?;
        tcb.state = ThreadState::Exited;
        if slot < 64 {
            self.ready_mask &= !(1u64 << slot);
        }
        if self.current == Some(slot) {
            self.current = None;
        }
        Ok(())
    }

    /// Directly mark `slot` as the `Running` thread (used by direct-switch IPC fastpaths).
    #[inline]
    pub fn select_slot(&mut self, slot: usize) {
        if !matches!(self.threads.get(slot), Some(Some(tcb)) if tcb.state != ThreadState::Exited) {
            return;
        }
        if let Some(prev) = self.current
            && prev != slot
            && let Some(prev_tcb) = &mut self.threads[prev]
            && prev_tcb.state == ThreadState::Running
        {
            prev_tcb.state = ThreadState::Ready;
            if prev < 64 {
                self.ready_mask |= 1u64 << prev;
            }
        }
        if let Some(tcb) = &mut self.threads[slot] {
            tcb.state = ThreadState::Running;
            tcb.quantum_remaining = DEFAULT_TIME_SLICE;
            if slot < 64 {
                self.ready_mask &= !(1u64 << slot);
            }
            self.current = Some(slot);
        }
    }

    /// Account one hardware timer tick on the currently running thread.
    ///
    /// Returns `true` when the thread's quantum expires and at least one other `Ready` thread
    /// with equal or higher priority is waiting to preempt it.
    #[inline]
    pub fn on_timer_tick(&mut self) -> bool {
        let Some(cur) = self.current else {
            return false;
        };
        let cur_prio = {
            let Some(tcb) = &mut self.threads[cur] else {
                return false;
            };
            if tcb.state != ThreadState::Running {
                return false;
            }
            if tcb.quantum_remaining > 1 {
                tcb.quantum_remaining -= 1;
                return false;
            }
            tcb.quantum_remaining = DEFAULT_TIME_SLICE;
            tcb.priority
        };

        let has_preemptor = self.has_ready_with_min_priority(cur_prio);
        if has_preemptor && let Some(tcb) = &mut self.threads[cur] {
            tcb.preemptions = tcb.preemptions.saturating_add(1);
        }
        has_preemptor
    }

    #[inline]
    fn has_ready_with_min_priority(&self, min_priority: u8) -> bool {
        if MAX_THREADS <= 64 {
            let mut mask = self.ready_mask;
            if mask == 0 {
                return false;
            }
            if mask.is_power_of_two() {
                return self.priorities[mask.trailing_zeros() as usize] >= min_priority;
            }
            while mask != 0 {
                let idx = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                if self.priorities[idx] >= min_priority {
                    return true;
                }
            }
            false
        } else {
            self.threads.iter().any(|slot| {
                matches!(slot, Some(tcb) if tcb.state == ThreadState::Ready && tcb.priority >= min_priority)
            })
        }
    }

    /// Steal one `Ready` thread from this runqueue (for SMP work-stealing by an idle core).
    pub fn steal_ready(&mut self) -> Option<ThreadControlBlock> {
        let victim_idx = if MAX_THREADS <= 64 {
            if self.ready_mask == 0 {
                return None;
            }
            self.ready_mask.trailing_zeros() as usize
        } else {
            self.threads
                .iter()
                .position(|s| matches!(s, Some(tcb) if tcb.state == ThreadState::Ready))?
        };
        if victim_idx < 64 {
            self.ready_mask &= !(1u64 << victim_idx);
        }
        self.priorities[victim_idx] = 0;
        self.threads[victim_idx].take()
    }

    /// Enqueue a stolen/migrated `ThreadControlBlock` onto this CPU's runqueue.
    pub fn enqueue_migrated(
        &mut self,
        mut tcb: ThreadControlBlock,
        new_cpu: u8,
    ) -> Result<usize, SysError> {
        for (idx, slot) in self.threads.iter_mut().enumerate() {
            if slot.is_none() {
                tcb.state = ThreadState::Ready;
                tcb.cpu_affinity = new_cpu;
                tcb.quantum_remaining = DEFAULT_TIME_SLICE;
                self.priorities[idx] = tcb.priority;
                *slot = Some(tcb);
                if idx < 64 {
                    self.ready_mask |= 1u64 << idx;
                }
                return Ok(idx);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Pick the highest-priority runnable thread (round-robin among equal priorities).
    #[inline]
    pub fn schedule_next(&mut self) -> Option<ThreadId> {
        if MAX_THREADS == 0 {
            return None;
        }
        let start = match self.current {
            Some(c) => {
                let next = c + 1;
                if next == MAX_THREADS { 0 } else { next }
            }
            None => 0,
        };

        if let Some(cur) = self.current
            && let Some(tcb) = &mut self.threads[cur]
            && tcb.state == ThreadState::Running
        {
            tcb.state = ThreadState::Ready;
            if cur < 64 {
                self.ready_mask |= 1u64 << cur;
            }
        }

        if MAX_THREADS <= 64 {
            let rm = self.ready_mask;
            if rm == 0 {
                return None;
            }
            let best_idx = if rm.is_power_of_two() {
                rm.trailing_zeros() as usize
            } else {
                let mut mask = rm.rotate_right(start as u32);
                let first_off = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                let mut best_idx = (start + first_off) & 63;
                let mut best_prio = self.priorities[best_idx];
                while mask != 0 {
                    let off = mask.trailing_zeros() as usize;
                    mask &= mask - 1;
                    let idx = (start + off) & 63;
                    let prio = self.priorities[idx];
                    if prio > best_prio {
                        best_idx = idx;
                        best_prio = prio;
                    }
                }
                best_idx
            };
            self.current = Some(best_idx);
            self.ready_mask = rm & !(1u64 << best_idx);
            if let Some(tcb) = &mut self.threads[best_idx] {
                tcb.state = ThreadState::Running;
                tcb.quantum_remaining = DEFAULT_TIME_SLICE;
                return Some(tcb.id);
            }
            return None;
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
            if idx < 64 {
                self.ready_mask &= !(1u64 << idx);
            }
            if let Some(tcb) = &mut self.threads[idx] {
                tcb.state = ThreadState::Running;
                tcb.quantum_remaining = DEFAULT_TIME_SLICE;
                return Some(tcb.id);
            }
        }
        None
    }

    /// Record a cooperative yield for the currently running thread and re-schedule.
    #[inline]
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

/// Multi-core SMP scheduler managing per-CPU runqueues with least-loaded placement and work-stealing.
pub struct SmpScheduler<const MAX_CPUS: usize, const MAX_THREADS_PER_CPU: usize> {
    per_cpu: [Scheduler<MAX_THREADS_PER_CPU>; MAX_CPUS],
    online_cpus: usize,
}

impl<const MAX_CPUS: usize, const MAX_THREADS_PER_CPU: usize>
    SmpScheduler<MAX_CPUS, MAX_THREADS_PER_CPU>
{
    pub const fn new(online_cpus: usize) -> Self {
        let clamped = if MAX_CPUS == 0 {
            0
        } else if online_cpus == 0 {
            1
        } else if online_cpus > MAX_CPUS {
            MAX_CPUS
        } else {
            online_cpus
        };
        Self {
            per_cpu: [const { Scheduler::new() }; MAX_CPUS],
            online_cpus: clamped,
        }
    }

    #[inline]
    pub const fn online_cpus(&self) -> usize {
        self.online_cpus
    }

    #[inline]
    pub fn cpu_mut(&mut self, cpu_id: usize) -> Option<&mut Scheduler<MAX_THREADS_PER_CPU>> {
        if cpu_id < self.online_cpus {
            Some(&mut self.per_cpu[cpu_id])
        } else {
            None
        }
    }

    /// Spawn a thread on the least-loaded online CPU core, returning `(cpu_id, thread_id)`.
    pub fn spawn_balanced(&mut self, priority: u8) -> Result<(usize, ThreadId), SysError> {
        if self.online_cpus == 0 {
            return Err(SysError::OutOfMemory);
        }
        let mut best_cpu = 0usize;
        let mut best_load = usize::MAX;
        for (cpu, rq) in self.per_cpu.iter().enumerate().take(self.online_cpus) {
            let load = rq.active_count();
            if load < best_load {
                best_load = load;
                best_cpu = cpu;
            }
        }
        let tid = self.per_cpu[best_cpu].spawn_on_cpu(priority, best_cpu as u8)?;
        Ok((best_cpu, tid))
    }

    /// Schedule next thread on `cpu_id`, stealing a `Ready` thread from the busiest peer if idle.
    pub fn schedule_or_steal(&mut self, cpu_id: usize) -> Option<ThreadId> {
        if cpu_id >= self.online_cpus {
            return None;
        }
        if let Some(tid) = self.per_cpu[cpu_id].schedule_next() {
            return Some(tid);
        }

        // Work-stealing: find busiest peer CPU with at least 1 Ready thread.
        let mut busiest: Option<(usize, usize)> = None;
        for (peer, rq) in self.per_cpu.iter().enumerate().take(self.online_cpus) {
            if peer == cpu_id {
                continue;
            }
            let ready = rq.ready_count();
            if ready > 0 && busiest.is_none_or(|(_, best)| ready > best) {
                busiest = Some((peer, ready));
            }
        }

        let (victim_cpu, _) = busiest?;
        let stolen = self.per_cpu[victim_cpu].steal_ready()?;
        if self.per_cpu[cpu_id]
            .enqueue_migrated(stolen, cpu_id as u8)
            .is_ok()
        {
            self.per_cpu[cpu_id].schedule_next()
        } else {
            // Restore stolen thread back to victim CPU so it is never lost.
            let _ = self.per_cpu[victim_cpu].enqueue_migrated(stolen, victim_cpu as u8);
            None
        }
    }

    /// Account a timer tick on `cpu_id`; returns `true` if `cpu_id` should preempt immediately.
    #[inline]
    pub fn on_timer_tick(&mut self, cpu_id: usize) -> bool {
        if cpu_id < self.online_cpus {
            self.per_cpu[cpu_id].on_timer_tick()
        } else {
            false
        }
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

    #[test]
    fn scheduler_edge_sizes_zero_sixty_four_and_over_sixty_four() {
        let mut s0 = Scheduler::<0>::new();
        assert_eq!(s0.schedule_next(), None);
        assert_eq!(s0.spawn(1), Err(SysError::OutOfMemory));

        // Scheduler::<64> round-robin wrap-around at slot 63 -> slot 0.
        let mut s64 = Scheduler::<64>::new();
        let mut ids64 = [ThreadId(0); 64];
        for id_slot in &mut ids64 {
            *id_slot = s64.spawn(5).unwrap();
        }
        assert_eq!(s64.spawn(5), Err(SysError::OutOfMemory));
        for &expected in &ids64 {
            assert_eq!(s64.schedule_next(), Some(expected));
        }
        // Wraps cleanly from slot 63 back to slot 0.
        assert_eq!(s64.schedule_next(), Some(ids64[0]));

        // Scheduler::<80> exercises fallback for slots >= 64.
        let mut s80 = Scheduler::<80>::new();
        for _ in 0..64 {
            let _ = s80.spawn(1).unwrap();
        }
        let high_64 = s80.spawn(10).unwrap();
        let high_65 = s80.spawn(10).unwrap();
        assert_eq!(s80.schedule_next(), Some(high_64));
        assert_eq!(s80.schedule_next(), Some(high_65));
        assert_eq!(s80.schedule_next(), Some(high_64));
    }

    #[test]
    fn timer_tick_preemption_and_block_wake_lifecycle() {
        let mut sched = Scheduler::<8>::new();
        let a = sched.spawn(10).unwrap();
        let b = sched.spawn(10).unwrap();
        let low = sched.spawn(2).unwrap();

        assert_eq!(sched.schedule_next(), Some(a));
        // Quantum is DEFAULT_TIME_SLICE (4): first 3 ticks do not preempt; 4th does.
        for _ in 0..(DEFAULT_TIME_SLICE - 1) {
            assert!(!sched.on_timer_tick());
        }
        assert!(sched.on_timer_tick());
        assert_eq!(sched.tcb(0).unwrap().preemptions, 1);

        // Preempting switches to equal-priority `b`.
        assert_eq!(sched.schedule_next(), Some(b));

        // Block `a`: now only `low` (priority 2 < 10) is Ready, so `b` should not be preempted.
        sched.block_slot(0).unwrap();
        for _ in 0..DEFAULT_TIME_SLICE {
            assert!(!sched.on_timer_tick());
        }

        // Wake `a` and boost `low` above `b`: `low` wins next schedule.
        sched.wake_slot(0).unwrap();
        sched.set_priority(2, 20).unwrap();
        assert_eq!(sched.schedule_next(), Some(low));

        // Exit `low` removes it permanently.
        sched.exit_slot(2).unwrap();
        assert_eq!(sched.schedule_next(), Some(a));
    }

    #[test]
    fn smp_scheduler_balances_and_steals_work() {
        let mut smp = SmpScheduler::<4, 8>::new(2);
        let (cpu0, _t0) = smp.spawn_balanced(10).unwrap();
        let (cpu1, _t1) = smp.spawn_balanced(10).unwrap();
        assert_ne!(cpu0, cpu1);

        // Put two extra threads directly on CPU 0 and leave CPU 1 empty.
        let mut smp2 = SmpScheduler::<4, 8>::new(2);
        let t_a = smp2.cpu_mut(0).unwrap().spawn_on_cpu(10, 0).unwrap();
        let t_b = smp2.cpu_mut(0).unwrap().spawn_on_cpu(10, 0).unwrap();
        assert_eq!(smp2.schedule_or_steal(0), Some(t_a));
        // CPU 1 has no local threads -> steals `t_b` from CPU 0!
        assert_eq!(smp2.schedule_or_steal(1), Some(t_b));
        assert_eq!(smp2.cpu_mut(1).unwrap().tcb(0).unwrap().cpu_affinity, 1);
    }

    #[test]
    fn single_ready_fastpath_and_priority_sync() {
        let mut sched = Scheduler::<8>::new();
        let a = sched.spawn(5).unwrap();
        assert_eq!(sched.schedule_next(), Some(a));
        assert_eq!(sched.ready_count(), 0);
        // Single ready thread fastpath when rescheduling `a`.
        assert_eq!(sched.schedule_next(), Some(a));

        // Spawn `b`, block it, change its priority while blocked, then wake it.
        let b = sched.spawn(1).unwrap();
        sched.block_slot(1).unwrap();
        sched.set_priority(1, 50).unwrap();
        sched.wake_slot(1).unwrap();
        for _ in 0..(DEFAULT_TIME_SLICE - 1) {
            assert!(!sched.on_timer_tick());
        }
        assert!(sched.on_timer_tick());
        assert_eq!(sched.schedule_next(), Some(b));
    }

    #[test]
    fn boundary_invalid_slot_operations() {
        let mut sched = Scheduler::<4>::new();
        assert_eq!(sched.set_priority(0, 10), Err(SysError::InvalidArgument));
        assert_eq!(sched.set_priority(99, 10), Err(SysError::InvalidArgument));
        assert_eq!(sched.block_slot(0), Err(SysError::InvalidArgument));
        assert_eq!(sched.wake_slot(0), Err(SysError::InvalidArgument));
        assert_eq!(sched.exit_slot(0), Err(SysError::InvalidArgument));
        assert_eq!(sched.tcb(99), None);
        assert_eq!(sched.yield_current(), None);
        assert!(!sched.on_timer_tick());
        sched.select_slot(99);
        assert_eq!(sched.current_slot(), None);
    }

    #[test]
    fn zero_cpu_and_out_of_bounds_smp_scheduler() {
        let mut smp0 = SmpScheduler::<0, 8>::new(0);
        assert_eq!(smp0.online_cpus(), 0);
        assert!(smp0.cpu_mut(0).is_none());
        assert_eq!(smp0.spawn_balanced(10), Err(SysError::OutOfMemory));
        assert_eq!(smp0.schedule_or_steal(0), None);
        assert!(!smp0.on_timer_tick(0));

        // Work-stealing when thief's runqueue is full of Blocked threads must restore victim thread.
        let mut smp = SmpScheduler::<2, 2>::new(2);
        let _ = smp.cpu_mut(0).unwrap().spawn_on_cpu(10, 0).unwrap();
        let victim = smp.cpu_mut(0).unwrap().spawn_on_cpu(10, 0).unwrap();
        let _ = smp.cpu_mut(0).unwrap().schedule_next(); // slot 0 Running, slot 1 (`victim`) Ready

        // Fill CPU 1 with 2 Blocked threads so enqueue_migrated returns OutOfMemory.
        let _ = smp.cpu_mut(1).unwrap().spawn_on_cpu(5, 1).unwrap();
        let _ = smp.cpu_mut(1).unwrap().spawn_on_cpu(5, 1).unwrap();
        smp.cpu_mut(1).unwrap().block_slot(0).unwrap();
        smp.cpu_mut(1).unwrap().block_slot(1).unwrap();

        assert_eq!(smp.schedule_or_steal(1), None);
        // `victim` must still be Ready on CPU 0!
        assert_eq!(smp.cpu_mut(0).unwrap().ready_count(), 1);
        assert_eq!(smp.cpu_mut(0).unwrap().schedule_next(), Some(victim));
    }

    #[test]
    fn steal_ready_and_enqueue_migrated_syncs_priorities() {
        let mut src = Scheduler::<8>::new();
        let high = src.spawn_on_cpu(200, 0).unwrap();
        let stolen = src.steal_ready().unwrap();
        assert_eq!(stolen.id, high);
        assert_eq!(src.ready_count(), 0);

        let mut dst = Scheduler::<8>::new();
        let _low = dst.spawn_on_cpu(10, 1).unwrap();
        dst.enqueue_migrated(stolen, 1).unwrap();
        // Migrated high-priority thread must beat local low-priority thread.
        assert_eq!(dst.schedule_next(), Some(high));
    }

    #[test]
    fn select_slot_rejects_empty_and_exited_slots_without_corrupting_current() {
        let mut sched = Scheduler::<8>::new();
        let t0 = sched.spawn(10).unwrap();
        let t1 = sched.spawn(10).unwrap();
        assert_eq!(sched.schedule_next(), Some(t0));
        assert_eq!(sched.current_slot(), Some(0));
        assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Running);

        // Empty slot 5 must be a no-op and must not demote current slot 0.
        sched.select_slot(5);
        assert_eq!(sched.current_slot(), Some(0));
        assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Running);
        assert_eq!(sched.ready_count(), 1);

        // Exited slot 1 must not be resurrected to Running.
        sched.exit_slot(1).unwrap();
        assert_eq!(sched.tcb(1).unwrap().state, ThreadState::Exited);
        assert_eq!(sched.tcb(1).unwrap().id, t1);
        sched.select_slot(1);
        assert_eq!(sched.current_slot(), Some(0));
        assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Running);
        assert_eq!(sched.tcb(1).unwrap().state, ThreadState::Exited);
    }
}
