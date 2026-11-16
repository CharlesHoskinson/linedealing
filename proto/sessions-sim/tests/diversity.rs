use sessions_sim::{
    experiments::*,
    oracle::{Event, LossReading},
    CrashPoint, Params,
};
use std::collections::BTreeSet;

#[test]
fn single_kind_seeds_change_outcomes() {
    for (n, f) in [(4, 1), (7, 2)] {
        for kind in [
            FailureKind::SealdCrash,
            FailureKind::VmReboot,
            FailureKind::ReplaceSlot,
            FailureKind::ByzantinePeer,
            FailureKind::LedgerReadFailure,
        ] {
            let mut outcomes = BTreeSet::new();
            let mut totals = Totals::default();
            let mut cuts = BTreeSet::new();
            let mut seats = BTreeSet::new();
            let mut steps = BTreeSet::new();
            let mut subsets = BTreeSet::new();
            let mut uninterrupted = 0;
            for seed in 0..30 {
                let r = run_case(Params::new(n, f), seed, kind, false, LossReading::Literal);
                let mut t = Totals::default();
                t.add(&r);
                outcomes.insert((t.releases, t.refusals, t.burned, t.voided, t.reopened));
                totals.add(&r);
                uninterrupted += usize::from(
                    !r.sim
                        .trace
                        .iter()
                        .any(|e| matches!(e, Event::CrashCut { .. })),
                );
                for event in &r.sim.trace {
                    if let Event::CrashCut { seat, step, point } = event {
                        seats.insert(*seat);
                        steps.insert(*step);
                        cuts.insert(match point {
                            CrashPoint::AfterFsync => 1,
                            CrashPoint::AfterWitnessAcks { peers } => {
                                assert!(peers.len() < r.sim.params.w);
                                assert!(!peers.contains(seat));
                                subsets.insert(peers.clone());
                                2
                            }
                            CrashPoint::AfterSlotAcks => 3,
                            CrashPoint::DuringRestore => 4,
                        });
                    }
                }
            }
            assert!(outcomes.len() > 1, "identical {kind:?} n={n} outcomes");
            assert!(totals.outcomes.len() >= outcomes.len());
            assert_eq!(cuts.len(), 4, "missing cuts {kind:?} n={n}: {cuts:?}");
            assert!(seats.len() > 1 && steps.len() > 1 && subsets.len() > 1);
            assert!(uninterrupted > 0);
            if kind == FailureKind::ByzantinePeer {
                assert!(
                    totals.byzantine_fired.iter().all(|count| *count > 0),
                    "{:?}",
                    totals.byzantine_fired
                );
            }
        }
    }
}
