use line_dealing::simulation::{run, Config};

#[test]
fn actual_signatures_complete_for_every_suite_mode_and_batching() {
    for suite in 1..=3 {
        for sealed in [false, true] {
            let config = Config {
                requests: 3,
                suite,
                sealed,
                batch_size: if sealed { 8 } else { 1 },
                ..Config::default()
            };
            let result = run(&config).unwrap();
            assert_eq!(result.completed, 3);
            assert!(result.p99_ms >= result.p50_ms);
            assert!(result.requests_per_second > 0.0);
            assert_eq!(result.posts, 3 * 9 * if sealed { 3 } else { 4 });
        }
    }
}

#[test]
fn invalid_simulation_options_are_rejected() {
    assert!(run(&Config {
        requests: 0,
        ..Config::default()
    })
    .is_err());
    assert!(run(&Config {
        threshold: 4,
        ..Config::default()
    })
    .is_err());
    assert!(run(&Config {
        batch_size: 0,
        ..Config::default()
    })
    .is_err());
}

#[test]
fn link_latency_applies_in_both_directions_and_t2_completes() {
    let report = run(&Config {
        requests: 2,
        threshold: 7,
        latency_ms: 25,
        batch_size: 16,
        board_ms: 0,
        ..Config::default()
    })
    .unwrap();
    // Four open-mode board exchanges require eight one-way deliveries.
    assert!(report.p50_ms >= 200.0);
    assert_eq!(report.completed, 2);
    assert!(report.board_batches < report.posts);
}
