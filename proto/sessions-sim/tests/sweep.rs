use sessions_sim::{experiments::*, oracle::LossReading, *};

#[test]
fn randomized_200_seeds_both_profiles_fixed_and_old_rules() {
    for old in [false, true] {
        for (n, f) in [(4, 1), (7, 2)] {
            let mut totals = Totals::default();
            let mut series_runs = 0;
            let mut absent_account_runs = 0;
            for seed in 0..200 {
                let result = run_case(
                    Params::new(n, f),
                    seed,
                    FailureKind::Mixed,
                    if old {
                        Knobs::old_rules()
                    } else {
                        Knobs::default()
                    },
                    LossReading::Concurrent,
                );
                series_runs += usize::from(result.series);
                absent_account_runs += usize::from(result.absent_account_keys.iter().any(|k| {
                    result
                        .sim
                        .oracle
                        .releases
                        .get(k)
                        .is_some_and(|ds| ds.len() > 1)
                }));
                if !old {
                    // SS-102/120..135: the fixed sweep has no allowed violation classes.
                    assert!(
                        result.sim.oracle.violations.is_empty(),
                        "seed={seed} n={n}: {:?}",
                        result.sim.oracle.violations
                    );
                    if result.sim.in_bound() {
                        assert!(result
                            .sim
                            .oracle
                            .expected
                            .iter()
                            .all(|v| !v.contains("G2/G3") && !v.contains("G4")));
                    }
                }
                totals.add(&result);
            }
            assert!(series_runs > 0);
            assert_eq!(totals.a_class > 0, old && n == 4);
            assert_eq!(absent_account_runs > 0, old);
            if old {
                assert!(totals.violations[0][1] > 0); // SS-128: absent-share reuse outside the bound.
                assert_eq!(totals.violations[1][0] > 0, n == 4); // SS-102: stale open.
                assert!(totals.violations[2][0] > 0); // SS-126: lost replicas / G1.
            }
            println!("sweep old={old} n={n} seeds=200 series={series_runs} A={} Q11={absent_account_runs} violations={:?}", totals.a_class, totals.violations);
        }
    }
}
