//! One-shot phase diagnostics. Run explicitly with --ignored --nocapture.
//! Each duration measures one operation, with fixtures prepared before timing.
use line_dealing::{
    experiment::SeededRng,
    split::{
        group::{Edwards, Secp},
        prf,
        request::{contribution_frame, seal_contributions},
        schnorr::SchnorrSuite,
    },
};
use std::{hint::black_box, time::Instant};
use zeroize::Zeroizing;
#[allow(dead_code)]
#[path = "../benches/support/mod.rs"]
mod support;

fn measure<T>(label: &str, operation: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = black_box(operation());
    let elapsed = start.elapsed();
    eprintln!(
        "PROFILE {label} {:.3} us",
        elapsed.as_secs_f64() * 1_000_000.0
    );
    value
}

fn profile<S: SchnorrSuite>(n: u16, k: u8, l: u8, actors: u16, suite: &str) {
    let prefix = format!("n{n}/{suite}/actors{actors}");
    let setup = support::schnorr::<S>(n, k, l, actors);
    let t = support::threshold(n);
    let mut rng = SeededRng::new(321);
    let draft = measure(&format!("{prefix}/wallet_build_request/build"), || {
        setup.build(&mut rng).unwrap()
    });
    let request = measure(&format!("{prefix}/wallet_build_request/finish"), || {
        draft.finish(&mut rng).unwrap()
    });
    let shares: Vec<_> = (1..=n)
        .map(|i| {
            request
                .envelope
                .decrypt_share(
                    i,
                    setup.transport_secrets[usize::from(i - 1)],
                    &setup.transport_keys,
                )
                .unwrap()
        })
        .collect();
    let header_partials: Vec<_> = (1..=t)
        .map(|i| {
            prf::partial(
                shares[usize::from(i - 1)],
                i,
                &request.envelope.dd(),
                prf::Label::Hdr,
            )
            .unwrap()
        })
        .collect();
    let z = measure(&format!("{prefix}/header_combine_open/prf_combine"), || {
        prf::combine(&header_partials, usize::from(t)).unwrap()
    });
    let (key, layout_key) = measure(&format!("{prefix}/header_combine_open/keys"), || {
        prf::header_keys(z).unwrap()
    });
    let opened = measure(
        &format!("{prefix}/header_combine_open/decrypt_decode"),
        || {
            request
                .envelope
                .open_with_header_keys(&key, &layout_key)
                .unwrap()
        },
    );
    measure(&format!("{prefix}/header_combine_open/total"), || {
        request.envelope.open_header(&header_partials).unwrap()
    });
    let label = prf::Label::Body {
        variant: u16::from(k),
        generation: 1,
    };
    let body_partials: Vec<_> = (1..=t)
        .map(|i| {
            prf::partial(shares[usize::from(i - 1)], i, &request.envelope.dd(), label).unwrap()
        })
        .collect();
    let mut signature_partials = vec![vec![]; usize::from(l)];
    for i in 1..=t {
        for (j, partial) in request
            .signature_partials(&opened, k, 1, &mut setup.node(i).unwrap())
            .unwrap()
            .into_iter()
            .enumerate()
        {
            signature_partials[j].push(partial);
        }
    }
    let mut payloads = Vec::new();
    for position in 1..=actors as u8 {
        let mut pool = support::fresh_pool(&setup, position);
        let payload = measure(
            &format!("{prefix}/actor_contribution_work/position{position}/total"),
            || {
                request
                    .actor_contribute(
                        position,
                        &setup.actor_secrets[&position],
                        &mut pool,
                        0,
                        20,
                        &mut rng,
                    )
                    .unwrap()
            },
        );
        payloads.push(payload);
    }
    if actors > 0 {
        let view = measure(
            &format!("{prefix}/actor_contribution_work/open_actor"),
            || {
                request
                    .envelope
                    .open_actor(&setup.actor_secrets[&1], 1)
                    .unwrap()
            },
        );
        let mut requests = measure(
            &format!("{prefix}/actor_contribution_work/reconstruct"),
            || {
                request
                    .context
                    .reconstruct(view.opened.header(), &view.capsules, 1)
                    .unwrap()
            },
        );
        for request in &mut requests {
            request.exp_c = 20;
        }
        let mut pool = support::fresh_pool(&setup, 1);
        // This public API recomputes transcripts. The production request path
        // reuses reconstructed transcripts; its exact span is in the unit profile.
        let values = Zeroizing::new(measure(
            &format!("{prefix}/actor_contribution_work/contribute_batch_uncached_api"),
            || {
                pool.contribute_batch(&request.context.key, &requests, 0)
                    .unwrap()
            },
        ));
        measure(&format!("{prefix}/actor_contribution_work/seal"), || {
            seal_contributions::<S>(
                view.opened.header(),
                request.envelope.dd(),
                1,
                &values,
                &mut rng,
            )
            .unwrap()
        });
    }
    let selected = measure(&format!("{prefix}/combine_{suite}/open_selected"), || {
        request
            .envelope
            .open_selected(&opened, k, 1, &body_partials)
            .unwrap()
    });
    measure(
        &format!("{prefix}/combine_{suite}/reconstruct_body"),
        || {
            request
                .context
                .reconstruct_body(opened.header(), &selected.capsule, 1, k, 1)
                .unwrap()
        },
    );
    let mut slots = setup.slots.clone();
    measure(&format!("{prefix}/combine_{suite}/total"), || {
        request
            .combine(
                &opened,
                k,
                1,
                &body_partials,
                &signature_partials,
                &payloads,
                &setup.committee,
                &mut slots,
            )
            .unwrap()
    });
    if suite == "bip340" && actors == 2 {
        let (frame, _) = contribution_frame(
            opened.header(),
            payloads[0].clone(),
            &setup.transport_keys,
            usize::from(t),
            1,
            100,
            &mut rng,
        )
        .unwrap();
        let mut remote: Vec<_> = (2..=t)
            .map(|i| {
                let share = frame
                    .decrypt_share(
                        i,
                        setup.transport_secrets[usize::from(i - 1)],
                        &setup.transport_keys,
                    )
                    .unwrap();
                prf::partial(share, i, &frame.dd(), prf::Label::Hdr).unwrap()
            })
            .collect();
        measure(
            &format!("{prefix}/contrib_frame_open/verify_public"),
            || {
                frame
                    .verify_public(&setup.transport_keys, usize::from(t), 1, 0)
                    .unwrap()
            },
        );
        let share = measure(
            &format!("{prefix}/contrib_frame_open/decrypt_share"),
            || {
                frame
                    .decrypt_share(1, setup.transport_secrets[0], &setup.transport_keys)
                    .unwrap()
            },
        );
        let partial = measure(&format!("{prefix}/contrib_frame_open/own_partial"), || {
            prf::partial(share, 1, &frame.dd(), prf::Label::Hdr).unwrap()
        });
        remote.insert(0, partial);
        measure(&format!("{prefix}/contrib_frame_open/open_header"), || {
            frame.open_header(&remote).unwrap()
        });
        measure(&format!("{prefix}/contrib_frame_open/total"), || {
            frame
                .verify_public(&setup.transport_keys, usize::from(t), 1, 0)
                .unwrap();
            let share = frame
                .decrypt_share(1, setup.transport_secrets[0], &setup.transport_keys)
                .unwrap();
            let mut replies = vec![prf::partial(share, 1, &frame.dd(), prf::Label::Hdr).unwrap()];
            replies.extend_from_slice(&remote[1..]);
            frame.open_header(&replies).unwrap()
        });
    }
}

#[test]
#[ignore = "single-shot phase diagnostics; no Criterion timing"]
fn split_slow_row_profile() {
    for n in [9, 17] {
        for actors in [0, 2] {
            profile::<Secp>(n, 8, 2, actors, "bip340");
            profile::<Edwards>(n, 1, 1, actors, "ed25519");
        }
    }
}
