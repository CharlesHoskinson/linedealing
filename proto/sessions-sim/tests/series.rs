use sessions_sim::{experiments::*, oracle::LossReading, *};

#[test]
fn owner_statement_prevents_series_safety_counterexamples() {
    for (n, f) in SERIES_PARAMS {
        for kind in SeriesKind::ALL {
            let result = replacement_series(
                Params::new(n, f),
                731,
                kind,
                Knobs {
                    fetch_owner_statement: true,
                    old_fetch_w_sources: true,
                    old_no_replica_fetch: true,
                    ..Knobs::default()
                },
                LossReading::Concurrent,
            );
            assert!(!result.resurrected && !result.second_release);
            assert_eq!(result.open_result, Err(Error::GroupUnavailable));
            assert!(result
                .sim
                .oracle
                .violations
                .iter()
                .any(|v| v.starts_with("G1:")));
            assert!(!result
                .sim
                .oracle
                .violations
                .iter()
                .any(|v| v.contains("G4") || v.contains("G2/G3")));
        }
    }
}

#[test]
fn checkpoint_after_replacements_closes_series_exposure_window() {
    for (n, f) in SERIES_PARAMS {
        for kind in SeriesKind::ALL {
            for reading in [LossReading::Literal, LossReading::Concurrent] {
                let r = replacement_series_tail(
                    Params::new(n, f),
                    731,
                    kind,
                    false,
                    reading,
                    SeriesTail::CheckpointThenRollback,
                );
                assert!(
                    r.open_result.is_ok(),
                    "{n}/{f} {kind:?}: {:?}",
                    r.open_result
                );
                assert!(!r.resurrected && !r.second_release);
                assert!(
                    r.sim.oracle.violations.is_empty(),
                    "{:?}",
                    r.sim.oracle.violations
                );
                assert!(
                    r.sim.oracle.expected.is_empty(),
                    "{:?}",
                    r.sim.oracle.expected
                );
            }
        }
    }
}

#[test]
fn blank_owner_after_holder_replacements_reopens_latest() {
    for (n, f) in SERIES_PARAMS {
        for kind in SeriesKind::ALL {
            let r = replacement_series_tail(
                Params::new(n, f),
                731,
                kind,
                false,
                LossReading::Concurrent,
                SeriesTail::ReplaceOwner,
            );
            println!("blank owner {n}/{f} {kind:?}: {:?}, resurrected={}, second_release={}, violations={:?}", r.open_result, r.resurrected, r.second_release, r.sim.oracle.violations);
            assert!(r.sim.in_bound());
            // SS-102/126: a completed replacement now carries the latest replica.
            assert!(r.open_result.is_ok());
            assert!(!r.resurrected && !r.second_release);
            assert!(r.sim.oracle.violations.is_empty());
        }
    }
}

#[test]
fn concurrent_loss_peak_and_overlapping_unavailability_are_counted() {
    let mut s = Sim::new(Params::new(4, 1), 1);
    s.oracle.reading = LossReading::Concurrent;
    s.inject(Fault::ReplaceSlot(1));
    s.sync(1).unwrap();
    assert!(s.oracle.active_lost.is_empty());
    s.inject(Fault::ReplaceSlot(2));
    s.sync(2).unwrap();
    assert_eq!(s.oracle.peak_lost, 1);
    assert!(s.in_bound());
    s.inject(Fault::ByzantinePeer(3));
    s.inject(Fault::VmReboot(0));
    assert_eq!(s.oracle.max_down, 2);
    assert!(!s.in_bound());
}

#[test]
fn rollback_loss_survives_a_later_completed_fetch() {
    let mut s = Sim::new(Params::new(4, 1), 731);
    assert_eq!(s.oracle.reading, LossReading::Concurrent);
    let snap = s.snapshot();
    s.inject(Fault::RollbackSeat(1, snap));
    s.sync(1).unwrap();
    s.post_checkpoint().unwrap();
    s.inject(Fault::ReplaceSlot(1));
    s.sync(1).unwrap();
    // Design G2/SS-102: only replacement losses retire; rollback stays conservative.
    assert!(s.oracle.active_lost.contains(&1));
    s.inject(Fault::ReplaceSlot(2));
    assert_eq!(s.oracle.peak_lost, 2);
    assert!(!s.in_bound());
}
