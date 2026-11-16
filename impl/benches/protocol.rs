use criterion::{black_box, criterion_group, criterion_main, Criterion};
use line_dealing::experiment::{SecpSetup, SeededRng};
use std::time::Duration;

fn sizes() -> Vec<u16> {
    match std::env::var("LD_BENCH_N") {
        Ok(value) => {
            let n = value.parse().expect("LD_BENCH_N must be 9, 16, 64, or 256");
            assert!([9, 16, 64, 256].contains(&n));
            vec![n]
        }
        Err(_) => vec![9, 16, 64, 256],
    }
}

fn protocol(c: &mut Criterion) {
    for n in sizes() {
        let f = (n - 1) / 3;
        for t in [f + 1, n - f] {
            for suite in [1, 2] {
                for sealed in [false, true] {
                    let setup = SecpSetup::new(n, t, suite, sealed, 42).unwrap();
                    let mut rng = SeededRng::new(42);
                    let message = setup.owner_message(&mut rng).unwrap();
                    let accepted = message.step_a(&setup).unwrap();
                    let shares: Vec<_> = (1..=t)
                        .map(|i| accepted.decrypt(i, setup.secrets[i as usize - 1]).unwrap())
                        .collect();
                    let package = setup.package(&accepted).unwrap();
                    let partials: Vec<_> =
                        shares.iter().map(|s| package.partial(s).unwrap()).collect();
                    let name = format!(
                        "{}/{}/n{n}/t{t}",
                        if suite == 1 { "ecdsa" } else { "bip340" },
                        if sealed { "sealed-k8" } else { "open" }
                    );
                    let mut group = c.benchmark_group(name);
                    group
                        .sample_size(10)
                        .warm_up_time(Duration::from_millis(100))
                        .measurement_time(Duration::from_secs(1));
                    group.bench_function("owner_deal_encrypt", |b| {
                        b.iter(|| black_box(setup.owner_message(&mut rng).unwrap()))
                    });
                    group.bench_function("step_a", |b| {
                        b.iter(|| black_box(message.step_a(&setup).unwrap()))
                    });
                    group.bench_function("decrypt", |b| {
                        b.iter(|| black_box(accepted.decrypt(1, setup.secrets[0]).unwrap()))
                    });
                    group.bench_function("partial", |b| {
                        b.iter(|| black_box(package.partial(&shares[0]).unwrap()))
                    });
                    group.bench_function("verify_partial", |b| {
                        b.iter(|| assert!(black_box(package.verify_partial(&partials[0]))))
                    });
                    group.bench_function("combine", |b| {
                        b.iter(|| black_box(package.combine(&partials).unwrap()))
                    });
                    group.finish();
                }
            }
        }
    }
}
criterion_group!(benches, protocol, ed25519);
criterion_main!(benches);

fn ed25519(c: &mut Criterion) {
    use line_dealing::experiment::EdSetup;
    for n in sizes() {
        let f = (n - 1) / 3;
        for t in [f + 1, n - f] {
            for sealed in [false, true] {
                let setup = EdSetup::new(n, t, sealed, 42).unwrap();
                let mut rng = SeededRng::new(42);
                let message = setup.owner_message(&mut rng).unwrap();
                let accepted = message.step_a(&setup).unwrap();
                let shares: Vec<_> = (1..=t)
                    .map(|i| accepted.decrypt(i, setup.secrets[i as usize - 1]).unwrap())
                    .collect();
                let package = setup.package(&accepted).unwrap();
                let partials: Vec<_> = shares.iter().map(|s| package.partial(s).unwrap()).collect();
                let mut group = c.benchmark_group(format!(
                    "ed25519/{}/n{n}/t{t}",
                    if sealed { "sealed-k8" } else { "open" }
                ));
                group
                    .sample_size(10)
                    .warm_up_time(Duration::from_millis(100))
                    .measurement_time(Duration::from_secs(1));
                group.bench_function("owner_deal_encrypt", |b| {
                    b.iter(|| black_box(setup.owner_message(&mut rng).unwrap()))
                });
                group.bench_function("step_a", |b| {
                    b.iter(|| black_box(message.step_a(&setup).unwrap()))
                });
                group.bench_function("decrypt", |b| {
                    b.iter(|| black_box(accepted.decrypt(1, setup.secrets[0]).unwrap()))
                });
                group.bench_function("partial", |b| {
                    b.iter(|| black_box(package.partial(&shares[0]).unwrap()))
                });
                group.bench_function("verify_partial", |b| {
                    b.iter(|| assert!(black_box(package.verify_partial(&partials[0]))))
                });
                group.bench_function("combine", |b| {
                    b.iter(|| black_box(package.combine(&partials).unwrap()))
                });
                group.finish();
            }
        }
    }
}
