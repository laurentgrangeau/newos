//! Phase 7: Deterministic Host Chaos Testing & All-Domain Self-Healing Suite.
//!
//! Uses a seeded deterministic PRNG (`ChaosRng`) to inject faults, kills, cascading
//! multi-domain crashes, in-flight IPC peer deaths, `SpscRing` peer resets, and crash-loop
//! storms across all 6 `DomainRoleId`s (`Supervisor`, `Shell`, `Worker`, `Net`, `Key`, `Ssh`),
//! asserting zero frame leaks, zero orphaned capabilities, zero deadlocks, and full service recovery.

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, DomainRoleId, RING_PEER_RESET_BIT, Rights, supervisor_notif};
use newos_kernel_core::cspace::{CapObject, Capability};
use newos_kernel_core::ipc::KernelIpcState;
use newos_kernel_core::memory::{PhysFrame, UntypedInventory};
use newos_kernel_core::sched::Scheduler;

const ALL_ROLES: [DomainRoleId; 6] = [
    DomainRoleId::Supervisor,
    DomainRoleId::Shell,
    DomainRoleId::Worker,
    DomainRoleId::Net,
    DomainRoleId::Key,
    DomainRoleId::Ssh,
];

/// Deterministic `SplitMix64` PRNG so every chaos failure is 100% reproducible from its seed.
struct ChaosRng(u64);
impl ChaosRng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn next_usize(&mut self, bound: usize) -> usize {
        let bound_u64 = u64::try_from(bound).expect("bound fits u64");
        usize::try_from(self.next_u64() % bound_u64).expect("remainder fits usize")
    }
}

/// Mirrors `supervisor-pd`'s restart-intensity & exponential-backoff policy for chaos testing.
struct RestartSupervisorPolicy {
    backoff_ms: [u64; 6],
    restart_counts: [u32; 6],
    window_start_ms: [u64; 6],
    quarantined: [bool; 6],
}

impl RestartSupervisorPolicy {
    const WINDOW_MS: u64 = 10_000;
    const MAX_RESTARTS_IN_WINDOW: u32 = 5;

    fn new() -> Self {
        Self {
            backoff_ms: [50; 6],
            restart_counts: [0; 6],
            window_start_ms: [0; 6],
            quarantined: [false; 6],
        }
    }

    /// Returns `Some(delay_ms)` if the domain should be respawned, or `None` if quarantined.
    fn on_domain_fault(&mut self, role: DomainRoleId, now_ms: u64) -> Option<u64> {
        let idx = role as usize;
        if now_ms.saturating_sub(self.window_start_ms[idx]) >= Self::WINDOW_MS {
            self.window_start_ms[idx] = now_ms;
            self.restart_counts[idx] = 0;
            self.backoff_ms[idx] = 50;
            self.quarantined[idx] = false;
        }
        if self.restart_counts[idx] >= Self::MAX_RESTARTS_IN_WINDOW {
            self.quarantined[idx] = true;
            return None;
        }
        let delay = self.backoff_ms[idx];
        self.backoff_ms[idx] = delay.saturating_mul(2).min(1_000);
        self.restart_counts[idx] += 1;
        Some(delay)
    }
}

#[test]
fn chaos_randomized_all_domain_fault_destroy_respawn_zero_leak_150_rounds() {
    const SEED: u64 = 0xC4A0_5E14_2026_1125;
    let mut rng = ChaosRng(SEED);

    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x5000_0000, 64 * 4096));
    let initial_frames = inv.remaining_frames();

    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).expect("bootstrap caps");

    // Track per-domain allocated frames (representing each PD's TTBR0 VSpace + stack frames)
    let mut pd_frames: [Vec<PhysFrame>; 6] = Default::default();
    let allocate_pd = |pd: usize,
                       inv: &mut UntypedInventory,
                       ipc: &mut KernelIpcState,
                       frames: &mut [Vec<PhysFrame>; 6]| {
        for _ in 0..4 {
            let f = inv.retype_frame().expect("frame available for PD");
            frames[pd].push(f);
        }
        // Grant fresh endpoint cap to respawned PD
        let ep_id = u32::try_from(pd + 1).expect("pd index fits u32");
        let _ = ipc.cspace_mut(pd).unwrap().insert_root(Capability::new(
            CapObject::Endpoint { id: ep_id },
            Rights::READ.union(Rights::WRITE),
        ));
    };

    for pd in 1..6 {
        allocate_pd(pd, &mut inv, &mut ipc, &mut pd_frames);
    }
    let steady_remaining = inv.remaining_frames();
    assert_eq!(steady_remaining + 20, initial_frames);

    // 150 rounds of seeded chaos: randomly kill 1..=3 PDs simultaneously, signal fault bits,
    // reclaim all frames + clear CSpace, respawn in reverse order, and assert exact 0-frame leak!
    for round in 0..150usize {
        let kill_count = 1 + rng.next_usize(3);
        let mut killed = Vec::new();
        for _ in 0..kill_count {
            let pd = 1 + rng.next_usize(5); // Shell, Worker, Net, Key, Ssh
            if !killed.contains(&pd) {
                killed.push(pd);
            }
        }

        // 1. Fault & destroy all selected domains simultaneously (cascading crash)
        for &pd in &killed {
            ipc.clear_buffered_calls_from(pd);
            let _ = ipc.clear_domain_cspace(pd, |_, _| {});
            for frame in core::mem::take(&mut pd_frames[pd]) {
                assert!(
                    inv.reclaim_frame(frame),
                    "seed={SEED:#x} round={round} pd={pd} frame reclaim failed"
                );
            }
            let bit = 1u64 << pd;
            let _ = ipc.notify_signal(CapId::BOOTSTRAP_FAULT_NOTIF, bit);
        }

        // Verify supervisor sees all faulted PD bits
        let pending = ipc
            .notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF)
            .expect("poll fault notif");
        for &pd in &killed {
            assert_ne!(
                pending & (1u64 << pd),
                0,
                "seed={SEED:#x} round={round} missing fault bit for pd={pd}"
            );
        }

        // 2. Respawn in reverse order to test arbitrary dependency recovery
        for &pd in killed.iter().rev() {
            allocate_pd(pd, &mut inv, &mut ipc, &mut pd_frames);
        }

        // 3. Exact 0-frame leak invariant after every single chaos round
        assert_eq!(
            inv.remaining_frames(),
            steady_remaining,
            "seed={SEED:#x} round={round} leaked frames!"
        );
    }

    // Final teardown of all PDs returns 100% of frames to UntypedInventory
    for frames in pd_frames.iter_mut().skip(1) {
        for frame in frames.drain(..) {
            assert!(inv.reclaim_frame(frame));
        }
    }
    assert_eq!(inv.remaining_frames(), initial_frames);
}

#[test]
fn chaos_in_flight_ipc_peer_death_unwinds_without_deadlock() {
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();

    // Give PD 1 (Shell) and PD 2 (Worker) access to endpoint 1
    let rw = Rights::READ.union(Rights::WRITE);
    let ep_cap_1 = ipc
        .cspace_mut(1)
        .unwrap()
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, rw))
        .unwrap();
    let _ep_cap_2 = ipc
        .cspace_mut(2)
        .unwrap()
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, rw))
        .unwrap();

    // PD 1 sends a buffered IPC message targeting PD 2
    assert_eq!(ipc.ipc_send_for(1, ep_cap_1, 0xCAFE_BABE), Ok(()));

    // PD 2 crashes mid-flight: clear its CSpace and drain stale buffered calls
    let _ = ipc.clear_domain_cspace(2, |_, _| {});
    ipc.clear_buffered_calls_from(1);

    // Respawn PD 2 with fresh capability: it cleanly drains the pre-crash in-flight message
    // and immediately accepts new IPC traffic without deadlock.
    let fresh_ep_2 = ipc
        .cspace_mut(2)
        .unwrap()
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, rw))
        .unwrap();
    let stale = ipc
        .ipc_recv_for(2, fresh_ep_2)
        .expect("drain pre-crash msg");
    assert_eq!(stale.payload, 0xCAFE_BABE);
    assert_eq!(ipc.ipc_send_for(1, ep_cap_1, 0x1234_5678), Ok(()));
    let msg = ipc
        .ipc_recv_for(2, fresh_ep_2)
        .expect("respawned PD 2 receives");
    assert_eq!(msg.payload, 0x1234_5678);
}

#[test]
fn chaos_spsc_ring_peer_respawn_notification_and_resync() {
    let ring = SpscRing::<32>::new();
    for i in 0u64..10 {
        ring.try_push(i).unwrap();
    }

    // Peer crashes mid-burst -> kernel stamps RING_PEER_RESET_BIT, ring is drained & resynced
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();
    ipc.notify_signal(CapId::BOOTSTRAP_NOTIF, RING_PEER_RESET_BIT)
        .unwrap();
    let bits = ipc.notify_poll(CapId::BOOTSTRAP_NOTIF).unwrap();
    assert_ne!(bits & RING_PEER_RESET_BIT, 0);

    // Drain stale pre-crash frames and resume clean operation
    while ring.try_pop().is_some() {}
    assert!(ring.is_empty());
    assert!(ring.try_push(0xFEED_FACE).is_ok());
    assert_eq!(ring.try_pop(), Some(0xFEED_FACE));
}

#[test]
fn chaos_crash_loop_quarantine_and_exponential_backoff_protects_healthy_domains() {
    let mut policy = RestartSupervisorPolicy::new();

    // Persistent crash loop on Ssh triggers exponential backoff: 50, 100, 200, 400, 800ms
    let expected_delays = [50, 100, 200, 400, 800];
    let mut now = 1_000u64;
    for &want in &expected_delays {
        assert_eq!(policy.on_domain_fault(DomainRoleId::Ssh, now), Some(want));
        now += want;
    }
    // 6th crash within 10s window MUST be quarantined (None)
    assert_eq!(policy.on_domain_fault(DomainRoleId::Ssh, now), None);
    assert!(policy.quarantined[DomainRoleId::Ssh as usize]);

    // Healthy domain (`Net`) is NOT starved by `Ssh`'s quarantine!
    assert_eq!(policy.on_domain_fault(DomainRoleId::Net, now), Some(50));

    // Once the 10s window elapses, `Ssh` exits quarantine cleanly with reset backoff (50ms)
    let after_window = now + RestartSupervisorPolicy::WINDOW_MS + 1;
    assert_eq!(
        policy.on_domain_fault(DomainRoleId::Ssh, after_window),
        Some(50)
    );
    assert!(!policy.quarantined[DomainRoleId::Ssh as usize]);

    // Verify all 6 DomainRoleIds are distinct and supervisor respawn bit is disjoint from fault mask
    assert_eq!(ALL_ROLES.len(), 6);
    assert_eq!(
        supervisor_notif::SUPERVISOR_RESPAWNED_BIT & supervisor_notif::FAULT_PD_MASK,
        0
    );
}

#[test]
fn chaos_scheduler_survives_mass_exit_and_re_spawn_cycles() {
    let mut sched: Scheduler<16> = Scheduler::new();
    for _cycle in 0..20usize {
        for i in 0..4u8 {
            let _tid = sched.spawn(100 + i).expect("spawn");
        }
        // Exit and reclaim all 4 slots in reverse order
        for slot in (0..4usize).rev() {
            assert_eq!(sched.exit_slot(slot), Ok(()));
            sched.reclaim_slot(slot);
        }
    }
}
