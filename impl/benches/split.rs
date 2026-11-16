use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use line_dealing::{
    experiment::SeededRng,
    split::{
        contribution::{ContributionContext, SealedContribution},
        group::{Edwards, Secp, Suite},
        prf,
        request::{check_release_tickets, contribution_frame, decode_ticket},
        schnorr::{self, signature_partial_value, SchnorrSuite},
        slots::{self, CommitteeSlots},
    },
};
use std::{collections::BTreeMap, time::Duration};
mod support;

fn sizes() -> Vec<u16> {
    match std::env::var("SPLIT_BENCH_N") {
        Ok(value) => {
            let n = value.parse().expect("SPLIT_BENCH_N must be 9 or 17");
            assert!([9, 17].contains(&n), "SPLIT_BENCH_N must be 9 or 17");
            vec![n]
        }
        Err(std::env::VarError::NotPresent) => vec![9, 17],
        Err(error) => panic!("invalid SPLIT_BENCH_N: {error}"),
    }
}

fn offline_rows(c: &mut Criterion) {
    for n in sizes() {
        let f = if n == 9 { 2 } else { 5 };
        let t = n - f;
        let mut rng = SeededRng::new(31);
        let secrets: BTreeMap<_, _> = (1..=n).map(|i| (i, Secp::random(&mut rng))).collect();
        let recipients = secrets
            .iter()
            .map(|(&i, &s)| (i, Secp::generator_mul(s)))
            .collect();
        let messages: Vec<_> = (1..=t)
            .map(|dealer| {
                slots::create_dealer_message::<Secp>(
                    dealer,
                    7,
                    t,
                    &[1, 2, 3, 4],
                    &recipients,
                    &mut rng,
                )
                .unwrap()
            })
            .collect();
        let checked = slots::decrypt_and_check(&messages[0], 1, secrets[&1], &mut rng).unwrap();
        let pool = CommitteeSlots::assemble(&messages, &secrets, &mut rng).unwrap();
        assert_eq!(pool.slots[&1].cached_nodes(), 0);
        let q = (n + f + 2) / 2;
        let vote = b"split benchmark: one board block";
        let voters: Vec<_> = (1..=q)
            .map(|i| SigningKey::from_bytes(&[i as u8; 32]))
            .collect();
        let signatures: Vec<_> = voters.iter().map(|key| key.sign(vote)).collect();
        let verification_keys: Vec<_> = voters.iter().map(SigningKey::verifying_key).collect();
        let contribution_keys: Vec<_> = (1..=8)
            .flat_map(|v| (1..=v.min(2)).map(move |g| (v, g)))
            .map(|(v, g)| {
                (
                    Secp::generator_mul(Secp::random(&mut rng)),
                    ContributionContext {
                        dd: [9; 32],
                        position: 1,
                        variant: v,
                        generation: g,
                    },
                    vec![Secp::random(&mut rng), Secp::random(&mut rng)],
                )
            })
            .collect();
        let mut group = c.benchmark_group(format!("split/n{n}"));
        group
            .sample_size(50)
            .warm_up_time(Duration::from_secs(1))
            .measurement_time(Duration::from_secs(5));
        group.bench_function("slot_deal_message", |b| {
            b.iter_with_large_drop(|| {
                black_box(
                    slots::create_dealer_message::<Secp>(
                        1,
                        7,
                        t,
                        &[1, 2, 3, 4],
                        &recipients,
                        &mut rng,
                    )
                    .unwrap(),
                )
            })
        });
        group.bench_function("slot_batch_verify", |b| {
            b.iter_with_large_drop(|| {
                black_box(slots::decrypt_and_check(&messages[0], 1, secrets[&1], &mut rng).unwrap())
            })
        });
        group.bench_function("slot_fallback_verify", |b| {
            b.iter(|| black_box(slots::fallback_check(&messages[0], 1, &checked.shares).unwrap()))
        });
        group.bench_function("slot_lazy_eval", |b| {
            b.iter_batched_ref(
                || pool.slots[&1].clone(),
                |slot| black_box(slot.evaluate(1).unwrap()),
                BatchSize::SmallInput,
            )
        });
        // The pinned dependency has no batch feature. This row measures q strict
        // verifications on one receiver, with signatures made outside the timer.
        group.bench_function("vote_batch_verify_q_single_verify_strict", |b| {
            b.iter(|| {
                for (key, signature) in verification_keys.iter().zip(&signatures) {
                    key.verify_strict(black_box(vote), black_box(signature))
                        .unwrap();
                }
            })
        });
        group.bench_function("contribution_seal", |b| {
            b.iter_with_large_drop(|| {
                black_box(
                    contribution_keys
                        .iter()
                        .map(|(key, context, scalars)| {
                            SealedContribution::seal(*key, context, scalars, &mut rng).unwrap()
                        })
                        .collect::<Vec<_>>(),
                )
            })
        });
        group.finish();
    }
}

fn ecdsa_combine_rows(c: &mut Criterion) {
    for n in sizes() {
        for other_actors in [0, 2] {
            let (mut request, secrets) = support::ecdsa(n, other_actors);
            let t = support::threshold(n);
            let header_partials: Vec<_> = (1..=t)
                .map(|i| {
                    request
                        .header_partial(i, secrets[usize::from(i - 1)])
                        .unwrap()
                })
                .collect();
            let opened = request.open_header(&header_partials).unwrap();
            let body_partials: Vec<_> = (1..=t)
                .map(|i| {
                    request
                        .body_partial(i, secrets[usize::from(i - 1)], 3)
                        .unwrap()
                })
                .collect();
            let mut partials = vec![vec![], vec![]];
            for i in 1..=t {
                for (input, partial) in request
                    .signature_partials(3, i)
                    .unwrap()
                    .into_iter()
                    .enumerate()
                {
                    partials[input].push(partial);
                }
            }
            let mut group = c.benchmark_group(format!("split/n{n}"));
            group
                .sample_size(50)
                .warm_up_time(Duration::from_secs(1))
                .measurement_time(Duration::from_secs(5));
            group.bench_function(format!("combine_ecdsa/actors{other_actors}"), |b| {
                b.iter_with_large_drop(|| {
                    black_box(
                        request
                            .combine(&opened, 3, &body_partials, &partials)
                            .unwrap(),
                    )
                })
            });
            group.finish();
        }
    }
}

fn schnorr_rows<S: SchnorrSuite>(c: &mut Criterion, n: u16, k: u8, l: u8, name: &str) {
    for other_actors in [0, 2] {
        // Birth, slot dealing, transport keys and transaction fixtures are offline.
        // None of these operations belong to a timed request row.
        let mut setup = support::schnorr::<S>(n, k, l, other_actors);
        let mut rng = SeededRng::new(321);
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let t = support::threshold(n);
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
        let opened = request.envelope.open_header(&header_partials).unwrap();
        let label = prf::Label::Body {
            variant: u16::from(k),
            generation: 1,
        };
        let body_partials: Vec<_> = (1..=t)
            .map(|i| {
                prf::partial(shares[usize::from(i - 1)], i, &request.envelope.dd(), label).unwrap()
            })
            .collect();
        let mut partials = vec![vec![]; usize::from(l)];
        for i in 1..=t + 1 {
            for (j, partial) in request
                .signature_partials(&opened, k, 1, &mut setup.node(i).unwrap())
                .unwrap()
                .into_iter()
                .enumerate()
            {
                partials[j].push(partial);
            }
        }
        let optimistic: Vec<_> = partials
            .iter()
            .map(|p| p[..usize::from(t)].to_vec())
            .collect();
        let mut damaged = partials.clone();
        damaged[0][0].value = damaged[0][0].value + S::scalar_one();
        let payloads: Vec<_> = (1..=other_actors as u8)
            .map(|position| {
                request
                    .actor_contribute(
                        position,
                        &setup.actor_secrets[&position],
                        setup
                            .pools
                            .get_mut(&setup.set[usize::from(position)])
                            .unwrap(),
                        0,
                        20,
                        &mut rng,
                    )
                    .unwrap()
            })
            .collect();
        // Prepare authenticated, decoded inputs for the signature-only row.
        // The full envelope pipeline remains a separate row below.
        let selected = request
            .envelope
            .open_selected(&opened, k, 1, &body_partials)
            .unwrap();
        let selected_requests = request
            .context
            .reconstruct_body(opened.header(), &selected.capsule, 1, k, 1)
            .unwrap();
        let mut contributions: Vec<_> = selected
            .scalars
            .iter()
            .map(|value| {
                BTreeMap::from([(
                    setup.set[0].clone(),
                    S::decode_scalar(&value.to_bytes().into()).unwrap(),
                )])
            })
            .collect();
        let selected_index = opened
            .header()
            .labels()
            .iter()
            .position(|label| *label == (k, 1))
            .unwrap();
        for payload in &payloads {
            opened
                .header()
                .validate_contribution(&request.envelope.hd(), payload)
                .unwrap();
            let actor = &selected.capsule.actors[usize::from(payload.position - 1)];
            let leaf = request.context.leaf(actor.leaf).unwrap();
            let values = payload.sealed[selected_index]
                .open_for_suite(
                    S::SUITE_ID,
                    selected.contribution_secret,
                    opened.header().contribution_keys[selected_index],
                    &ContributionContext {
                        dd: request.envelope.dd(),
                        position: payload.position,
                        variant: k,
                        generation: 1,
                    },
                    usize::from(l),
                )
                .unwrap();
            for (input, value) in values.iter().enumerate() {
                contributions[input].insert(
                    leaf.clone(),
                    S::decode_scalar(&value.to_bytes().into()).unwrap(),
                );
            }
        }
        let mut group = c.benchmark_group(format!("split/n{n}"));
        group
            .sample_size(50)
            .warm_up_time(Duration::from_secs(1))
            .measurement_time(Duration::from_secs(5));
        group.bench_function(format!("combine_{name}/actors{other_actors}"), |b| {
            b.iter_batched_ref(
                || setup.slots.clone(),
                |slots| {
                    black_box(
                        selected_requests
                            .iter()
                            .enumerate()
                            .map(|(input, selected_request)| {
                                // This safe public entry point derives a transcript,
                                // interpolates partials and verifies the signature.
                                schnorr::combine(
                                    &setup.key,
                                    selected_request,
                                    &setup.committee,
                                    slots.slots.get_mut(&selected_request.slot).unwrap(),
                                    &optimistic[input],
                                    &contributions[input],
                                )
                                .unwrap()
                            })
                            .collect::<Vec<_>>(),
                    )
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_function(
            format!("open_body_reconstruct_combine_{name}/actors{other_actors}"),
            |b| {
                b.iter_batched_ref(
                    // Preserve a cold lazy-evaluation cache without timing its clone.
                    || setup.slots.clone(),
                    |slots| {
                        black_box(
                            request
                                .combine(
                                    &opened,
                                    k,
                                    1,
                                    &body_partials,
                                    &optimistic,
                                    &payloads,
                                    &setup.committee,
                                    slots,
                                )
                                .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        if name == "bip340" && other_actors == 0 {
            group.bench_function("wallet_build_request", |b| {
                // Build the request and its envelope from existing birth/slot state.
                b.iter_with_large_drop(|| {
                    black_box(setup.build(&mut rng).unwrap().finish(&mut rng).unwrap())
                })
            });
            group.bench_function("pi_check", |b| {
                b.iter(|| {
                    black_box(&request.envelope)
                        .verify_public(&setup.transport_keys, usize::from(t), 1, 0)
                        .unwrap()
                })
            });
            group.bench_function("outer_share_check", |b| {
                b.iter(|| {
                    black_box(
                        request
                            .envelope
                            .decrypt_share(1, setup.transport_secrets[0], &setup.transport_keys)
                            .unwrap(),
                    )
                })
            });
            group.bench_function("header_partial", |b| {
                b.iter(|| {
                    black_box(
                        prf::partial(
                            black_box(shares[0]),
                            1,
                            &request.envelope.dd(),
                            prf::Label::Hdr,
                        )
                        .unwrap(),
                    )
                })
            });
            group.bench_function("header_combine_open", |b| {
                b.iter_with_large_drop(|| {
                    black_box(
                        request
                            .envelope
                            .open_header(black_box(&header_partials))
                            .unwrap(),
                    )
                })
            });
            let label_index = opened
                .header()
                .labels()
                .iter()
                .position(|x| *x == (k, 1))
                .unwrap();
            let tickets: Vec<_> = opened.header().tickets
                [label_index * usize::from(l)..(label_index + 1) * usize::from(l)]
                .iter()
                .map(|b| decode_ticket::<S>(b).unwrap())
                .collect();
            group.bench_function("release_ticket_checks", |b| {
                b.iter(|| {
                    check_release_tickets::<S>(1, black_box(&tickets), &setup.context.slots)
                        .unwrap()
                })
            });
            let selected = request
                .envelope
                .open_selected(&opened, k, 1, &body_partials)
                .unwrap();
            let selected_requests = request
                .context
                .reconstruct_body(opened.header(), &selected.capsule, 1, k, 1)
                .unwrap();
            let arithmetic: Vec<_> = selected_requests
                .iter()
                .enumerate()
                .map(|(j, r)| {
                    let transcript = r.transcript(&setup.key).unwrap();
                    let (d, e) = setup.slots.slots[&r.slot].shares[&1];
                    let inputs = (
                        setup.committee.shares[0],
                        d,
                        e,
                        transcript.committee_binding,
                        transcript.sigma,
                        transcript.ticket.challenge,
                    );
                    assert_eq!(
                        signature_partial_value::<S>(
                            inputs.0, inputs.1, inputs.2, inputs.3, inputs.4, inputs.5
                        ),
                        partials[j][0].value
                    );
                    inputs
                })
                .collect();
            group.bench_function("own_signature_partials", |b| {
                b.iter(|| {
                    for inputs in &arithmetic {
                        let (share, d, e, rho, sigma, challenge) = black_box(*inputs);
                        black_box(signature_partial_value::<S>(
                            share, d, e, rho, sigma, challenge,
                        ));
                    }
                })
            });
            group.bench_function("variant_key", |b| {
                b.iter_batched_ref(
                    || body_partials.clone(),
                    |replies| {
                        let own =
                            prf::partial(shares[0], 1, &request.envelope.dd(), label).unwrap();
                        replies[0] = own;
                        black_box(
                            prf::body_key(prf::combine(replies, usize::from(t)).unwrap()).unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                )
            });
            group.bench_function("combine_failure_path", |b| {
                b.iter_batched_ref(
                    || {
                        let slots = setup.slots.clone();
                        assert!(slots.slots.values().all(|slot| slot.cached_nodes() == 0));
                        slots
                    },
                    |slots| {
                        let result = request
                            .combine(
                                &opened,
                                k,
                                1,
                                &body_partials,
                                &damaged,
                                &payloads,
                                &setup.committee,
                                slots,
                            )
                            .unwrap();
                        assert_eq!(result[0].rejected_partials.as_slice(), &[1]);
                        black_box(result)
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        if name == "bip340" && other_actors == 2 {
            group.bench_function("actor_contribution_work", |b| {
                b.iter_batched_ref(
                    // Nonces are consumed once. Recreate fixture pools outside timing.
                    || support::fresh_pool(&setup, 1),
                    |pool| {
                        black_box(
                            request
                                .actor_contribute(
                                    1,
                                    &setup.actor_secrets[&1],
                                    pool,
                                    0,
                                    20,
                                    &mut rng,
                                )
                                .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                )
            });
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
            let remote: Vec<_> = (2..=t)
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
            group.bench_function("contrib_frame_open", |b| {
                // Receiver work: public proof, own outer share and header partial,
                // then threshold header opening. Remote replies are prepared above.
                b.iter_with_large_drop(|| {
                    frame
                        .verify_public(&setup.transport_keys, usize::from(t), 1, 0)
                        .unwrap();
                    let share = frame
                        .decrypt_share(1, setup.transport_secrets[0], &setup.transport_keys)
                        .unwrap();
                    let mut replies =
                        vec![prf::partial(share, 1, &frame.dd(), prf::Label::Hdr).unwrap()];
                    replies.extend_from_slice(&remote);
                    black_box(frame.open_header(&replies).unwrap())
                })
            });
        }
        group.finish();
    }
}

fn request_rows(c: &mut Criterion) {
    for n in sizes() {
        schnorr_rows::<Secp>(c, n, 8, 2, "bip340");
        schnorr_rows::<Edwards>(c, n, 1, 1, "ed25519");
    }
}

criterion_group!(benches, offline_rows, ecdsa_combine_rows, request_rows);
criterion_main!(benches);
