mod common;
#[allow(dead_code)]
#[path = "../benches/support/mod.rs"]
mod support;
use common::{node_secret, TestRng, G};
use k256::Scalar;
use line_dealing::split::{envelope::*, prf};

fn committee(n: u16) -> Vec<k256::ProjectivePoint> {
    (1..=n).map(|i| G * node_secret(i)).collect()
}

#[test]
fn outer_dealing_is_context_bound_and_shares_verify() {
    let mut rng = TestRng::new();
    let keys = committee(9);
    let public = Public::new(7, keylist_hash(&keys).unwrap(), 100);
    assert_eq!(public.encode().len(), 96);
    let prepared = PreparedEnvelope::new(public, &keys, 7, &mut rng).unwrap();
    assert_eq!(prepared.outer_bytes().len(), 7 * 33 + 9 * 32 + 33);
    let (header, bodies, capsules) = fixture(RequestType::Spend, 2, 2, 1);
    let frame = prepared
        .build(header, bodies, capsules, vec![], &mut rng)
        .unwrap()
        .authorize(Some([42; 32]), &mut rng)
        .unwrap();
    assert_eq!(frame.as_bytes().len(), 16384);
    frame.verify_public(&keys, 7, 7, 99).unwrap();
    let parsed = Envelope::decode(frame.as_bytes(), 9, 7).unwrap();
    assert_eq!(parsed.hd(), frame.hd());
    for i in 1..=9 {
        parsed.decrypt_share(i, node_secret(i), &keys).unwrap();
        assert!(parsed.complain(i, node_secret(i), &keys, &mut rng).is_err());
    }
    let mut bytes = frame.as_bytes().to_vec();
    bytes[46] ^= 1;
    let changed = Envelope::decode(&bytes, 9, 7).unwrap();
    assert_eq!(changed.dd(), frame.dd());
    assert_eq!(changed.hd(), frame.hd());
    assert!(changed.verify_public(&keys, 7, 7, 99).is_err());
    let mut seen = SeenDealings::default();
    seen.accept(&frame).unwrap();
    assert!(seen.accept(&changed).is_err());
}

fn fixture(kind: RequestType, suite: u8, k: u8, l: u8) -> (Header, Vec<Vec<Scalar>>, Vec<Capsule>) {
    let mut header = Header::request(kind, suite, k, l).unwrap();
    header.slots = (1..=header.slot_count()).map(|i| i as u32).collect();
    for (v, g) in header.labels() {
        for j in 0..l as usize {
            let mut ticket = vec![0; header.ticket_len()];
            let slot = if suite == 1 {
                (v as usize - 1) * l as usize + j
            } else {
                (g as usize - 1) * l as usize + j
            };
            ticket[..4].copy_from_slice(&header.slots[slot].to_be_bytes());
            header.tickets.push(ticket);
        }
    }
    let bodies = header
        .labels()
        .iter()
        .map(|_| vec![Scalar::from(13u64); l as usize])
        .collect();
    let point = if suite == 3 {
        line_dealing::ed25519::encode_point(curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .unwrap()
            .to_vec()
    } else {
        line_dealing::algebra::encode_point(G).unwrap().to_vec()
    };
    let capsules = (1..=k)
        .map(|v| Capsule {
            transaction: vec![v; 120],
            prevouts: vec![v; 50],
            destination: vec![v; 40],
            nonces: vec![
                point.clone();
                if suite == 1 {
                    l as usize
                } else {
                    v.min(header.g) as usize * l as usize
                }
            ],
            salt: [v; 32],
            initiator_term: point.clone(),
            initiator: 1,
            signing_set: vec![1],
            actors: vec![],
        })
        .collect();
    (header, bodies, capsules)
}

fn partials(
    frame: &Envelope,
    keys: &[k256::ProjectivePoint],
    label: prf::Label,
) -> Vec<prf::Partial> {
    (1..=frame.threshold() as u16)
        .map(|i| {
            prf::partial(
                frame.decrypt_share(i, node_secret(i), keys).unwrap(),
                i,
                &frame.dd(),
                label,
            )
            .unwrap()
        })
        .collect()
}
fn make_frame(
    kind: RequestType,
    suite: u8,
    k: u8,
    l: u8,
) -> (Envelope, Vec<k256::ProjectivePoint>) {
    let keys = committee(9);
    let mut rng = TestRng::new();
    let prepared = PreparedEnvelope::new(
        Public::new(7, keylist_hash(&keys).unwrap(), 100),
        &keys,
        7,
        &mut rng,
    )
    .unwrap();
    let (header, bodies, capsules) = fixture(kind, suite, k, l);
    (
        prepared
            .build(header, bodies, capsules, vec![], &mut rng)
            .unwrap()
            .authorize(None, &mut rng)
            .unwrap(),
        keys,
    )
}

#[test]
fn authenticated_layout_has_fixed_size_and_is_bound_only_to_hd() {
    for (suite, k, l) in [(1, 3, 2), (2, 8, 2), (3, 1, 1)] {
        let (frame, keys) = make_frame(RequestType::Spend, suite, k, l);
        let parts = partials(&frame, &keys, prf::Label::Hdr);
        let point = prf::combine(&parts, frame.threshold()).unwrap();
        let encoded = line_dealing::algebra::encode_point(point).unwrap();
        let key = prf::derive_key(&encoded, b"layout").unwrap();
        let start = PUBLIC_SIZE + 7 * 33 + 9 * 32 + 33;
        let layout = key
            .decrypt(&frame.as_bytes()[start..start + 64], &frame.dd())
            .expect("one fixed authenticated layout immediately follows the outer dealing");
        assert_eq!(layout.len(), 48);
        let lengths: Vec<_> = layout
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
            .collect();
        let opened = frame.open_header(&parts).unwrap();
        assert_eq!(lengths[0], opened.header().encode().unwrap().len() + 16);
        let count = opened.header().labels().len();
        assert!(lengths[1..1 + count]
            .iter()
            .all(|len| *len == 32 * l as usize + 48));
        assert!(lengths[1 + count..16].iter().all(|len| *len == 0));
        assert_eq!(
            lengths[16..16 + k as usize],
            opened
                .header()
                .capsule_lengths()
                .iter()
                .map(|v| *v as usize)
                .collect::<Vec<_>>()
        );
        assert!(lengths[16 + k as usize..].iter().all(|len| *len == 0));
        assert!(prf::header_key(point)
            .unwrap()
            .decrypt(&frame.as_bytes()[start..start + 64], &frame.dd())
            .is_err());
        let mut bytes = frame.as_bytes().to_vec();
        bytes[start] ^= 1;
        let changed = Envelope::decode(&bytes, 9, 7).unwrap();
        assert_eq!(changed.dd(), frame.dd());
        assert_ne!(changed.hd(), frame.hd());
        assert!(changed.open_header(&parts).is_err());
        assert!(changed.verify_public(&keys, 7, 7, 99).is_err());
    }
}

#[test]
fn authenticated_layout_rejects_noncanonical_lengths_and_padding() {
    let (frame, keys) = make_frame(RequestType::Spend, 2, 2, 1);
    let parts = partials(&frame, &keys, prf::Label::Hdr);
    let point = prf::combine(&parts, frame.threshold()).unwrap();
    let encoded = line_dealing::algebra::encode_point(point).unwrap();
    let start = PUBLIC_SIZE + 7 * 33 + 9 * 32 + 33;
    let original = prf::derive_key(&encoded, b"layout")
        .unwrap()
        .decrypt(&frame.as_bytes()[start..start + LAYOUT_SIZE], &frame.dd())
        .unwrap();
    // Model a dealer that authenticates an invalid layout. These are independent
    // malformed test frames, not permitted key reuse by the builder.
    for (field, value) in [
        (0, 0u16),
        (0, u16::MAX),
        (1, 79),
        (4, 80),
        (16, 16),
        (18, 16),
    ] {
        let mut layout = original.clone();
        layout[field * 2..field * 2 + 2].copy_from_slice(&value.to_be_bytes());
        let ciphertext = prf::derive_key(&encoded, b"layout")
            .unwrap()
            .encrypt(&layout, &frame.dd())
            .unwrap();
        let mut bytes = frame.as_bytes().to_vec();
        bytes[start..start + LAYOUT_SIZE].copy_from_slice(&ciphertext);
        let changed = Envelope::decode(&bytes, 9, 7).unwrap();
        assert!(
            changed.open_header(&parts).is_err(),
            "field {field}, value {value}"
        );
    }
}

#[test]
fn actor_capsule_size_is_fixed_across_suites_and_variant_counts() {
    for suite in 1..=3 {
        for k in [1, 8] {
            let mut rng = TestRng::new();
            let keys = committee(9);
            let prepared = PreparedEnvelope::new(
                Public::new(7, keylist_hash(&keys).unwrap(), 100),
                &keys,
                7,
                &mut rng,
            )
            .unwrap();
            let (mut header, bodies, mut capsules) = fixture(RequestType::Spend, suite, k, 1);
            let recipients = add_actors(&mut header, &mut capsules, 2, false);
            let frame = prepared
                .build(header, bodies, capsules, recipients, &mut rng)
                .unwrap()
                .authorize(None, &mut rng)
                .unwrap();
            for position in 1..=2 {
                let view = frame.open_actor(&[7; 32], position).unwrap();
                assert_eq!(view.capsules.len(), k as usize);
                assert_eq!(
                    frame.wire_sizes(&view.opened).unwrap().actor_capsules,
                    2 * ACTOR_CAPSULE_SIZE
                );
                let end = FRAME_SIZE - (position as usize - 1) * ACTOR_CAPSULE_SIZE;
                let plain = line_dealing::split::hpke::open(
                    &[7; 32],
                    &frame.as_bytes()[end - ACTOR_CAPSULE_SIZE..end],
                )
                .unwrap();
                assert_eq!(plain.len(), 337);
                assert!(plain[81 + 32 * k as usize..].iter().all(|byte| *byte == 0));
            }
        }
    }
}
#[test]
fn all_request_kinds_and_suites_roundtrip_and_only_selected_body_opens() {
    for kind in [
        RequestType::Birth,
        RequestType::Spend,
        RequestType::SlotRefill,
        RequestType::Exit,
        RequestType::P0Spend,
    ] {
        for suite in 1..=3 {
            let (frame, keys) = make_frame(kind, suite, 2, 2);
            assert_ne!(frame.public().auth_ref, [0; 32]);
            let opened = frame
                .open_header(&partials(&frame, &keys, prf::Label::Hdr))
                .unwrap();
            assert_eq!(opened.header().kind, kind);
            assert_eq!(
                Header::decode(&opened.header().encode().unwrap()).unwrap(),
                *opened.header()
            );
            let generation = if suite == 1 { 0 } else { 1 };
            let released = partials(
                &frame,
                &keys,
                prf::Label::Body {
                    variant: 1,
                    generation,
                },
            );
            let selected = frame
                .open_selected(&opened, 1, generation as u8, &released)
                .unwrap();
            assert_eq!(selected.scalars, vec![Scalar::from(13u64); 2]);
            assert_eq!(selected.capsule.transaction, vec![1; 120]);
            assert!(frame
                .open_selected(&opened, 2, generation as u8, &released)
                .is_err());
            assert!(Envelope::decode(&frame.as_bytes()[..16383], 9, 7).is_err());
            let mut extra = opened.header().encode().unwrap();
            extra.push(0);
            assert!(Header::decode(&extra).is_err());
        }
    }
}
#[test]
fn tag_tampering_and_swapping_bodies_fail() {
    let (frame, keys) = make_frame(RequestType::Spend, 2, 2, 1);
    let hdrparts = partials(&frame, &keys, prf::Label::Hdr);
    let opened = frame.open_header(&hdrparts).unwrap();
    let start = 96 + 7 * 33 + 9 * 32 + 33 + LAYOUT_SIZE + 196;
    let headerlen = opened.header().encode().unwrap().len() + 16;
    let bodylen = 80;
    let mut bytes = frame.as_bytes().to_vec();
    bytes[start + headerlen - 1] ^= 1;
    let bad = Envelope::decode(&bytes, 9, 7).unwrap();
    assert!(bad.verify_public(&keys, 7, 7, 0).is_err());
    assert!(bad.open_header(&hdrparts).is_err());
    let mut bytes = frame.as_bytes().to_vec();
    let first = bytes[start + headerlen..start + headerlen + bodylen].to_vec();
    let second = bytes[start + headerlen + bodylen..start + headerlen + 2 * bodylen].to_vec();
    bytes[start + headerlen..start + headerlen + bodylen].copy_from_slice(&second);
    bytes[start + headerlen + bodylen..start + headerlen + 2 * bodylen].copy_from_slice(&first);
    let swapped = Envelope::decode(&bytes, 9, 7).unwrap();
    let opened = swapped.open_header(&hdrparts).unwrap();
    assert!(swapped
        .open_selected(
            &opened,
            1,
            1,
            &partials(
                &frame,
                &keys,
                prf::Label::Body {
                    variant: 1,
                    generation: 1
                }
            )
        )
        .is_err());
}
fn add_actors(
    header: &mut Header,
    capsules: &mut [Capsule],
    count: usize,
    tee: bool,
) -> Vec<ActorRecipient> {
    let mut recipients = vec![];
    let public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([7; 32])).to_bytes();
    let point = if header.suite == 3 {
        line_dealing::ed25519::encode_point(curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .unwrap()
            .to_vec()
    } else {
        line_dealing::algebra::encode_point(G).unwrap().to_vec()
    };
    for i in 1..=count {
        let token = [i as u8; 16];
        header.actors.push(ActorSlot {
            position: i as u8,
            token_hash: token_hash(&token),
            party_index: if header.suite == 1 {
                Some(i as u16)
            } else {
                None
            },
            embedded: None,
        });
        recipients.push(ActorRecipient {
            position: i as u8,
            token,
            public_key: public,
        });
        for (v, cap) in capsules.iter_mut().enumerate() {
            let halves = if header.suite == 1 {
                header.l as usize
            } else {
                (v + 1).min(header.g as usize) * header.l as usize
            };
            cap.signing_set.push((i + 1) as u16);
            cap.actors.push(CapsuleActor {
                leaf: (i + 1) as u16,
                pool_id: if header.suite == 1 {
                    None
                } else {
                    Some(i as u32)
                },
                pair_indices: if header.suite == 1 {
                    vec![]
                } else {
                    vec![1; halves]
                },
                weighted_point: point.clone(),
            })
        }
    }
    if tee {
        header.tee = Some(TeeFields {
            intent: vec![0; 24],
            public_key: point.clone(),
            leaf_root: [1; 32],
            r_ic: [2; 32],
            salts: vec![[3; 32]; header.k as usize],
            actors: (0..count)
                .map(|_| TeeActor {
                    weighted_point: point.clone(),
                    pair_ids: if header.suite == 1 {
                        vec![]
                    } else {
                        vec![1; header.half_count()]
                    },
                })
                .collect(),
        })
    }
    recipients
}
#[test]
fn actor_capsule_opens_header_and_capsules_but_cannot_open_body() {
    let mut rng = TestRng::new();
    let keys = committee(9);
    let prepared = PreparedEnvelope::new(
        Public::new(7, keylist_hash(&keys).unwrap(), 100),
        &keys,
        7,
        &mut rng,
    )
    .unwrap();
    let (mut header, bodies, mut capsules) = fixture(RequestType::Spend, 2, 2, 1);
    let recipients = add_actors(&mut header, &mut capsules, 1, true);
    let frame = prepared
        .build(header, bodies, capsules, recipients, &mut rng)
        .unwrap()
        .authorize(None, &mut rng)
        .unwrap();
    let actor = frame.open_actor(&[7; 32], 1).unwrap();
    assert_eq!(actor.token, [1; 16]);
    assert_eq!(actor.capsules.len(), 2);
    assert!(actor.opened.header().tee.is_some());
    assert!(frame.open_actor(&[8; 32], 1).is_err());
    assert!(frame.open_actor(&[7; 32], 2).is_err());
    let bodyparts = partials(
        &frame,
        &keys,
        prf::Label::Body {
            variant: 1,
            generation: 1,
        },
    );
    let start = 96
        + 7 * 33
        + 9 * 32
        + 33
        + LAYOUT_SIZE
        + 196
        + actor.opened.header().encode().unwrap().len()
        + 16;
    let actor_size = ACTOR_CAPSULE_SIZE;
    let plain =
        line_dealing::split::hpke::open(&[7; 32], &frame.as_bytes()[FRAME_SIZE - actor_size..])
            .unwrap();
    assert_eq!(plain.len(), 81 + 32 * K_MAX);
    assert_eq!(&plain[81 + 32 * 2..], &[0; 32 * (K_MAX - 2)]);
    let header_key = prf::OneShotKey::from_bytes(plain[..32].try_into().unwrap());
    let layout_key = prf::OneShotKey::from_bytes(plain[32..64].try_into().unwrap());
    let capsule_key = prf::OneShotKey::from_bytes(plain[81..113].try_into().unwrap());
    assert!(header_key
        .decrypt(&frame.as_bytes()[start..start + 80], &frame.dd())
        .is_err());
    assert!(capsule_key
        .decrypt(&frame.as_bytes()[start..start + 80], &frame.dd())
        .is_err());
    assert!(layout_key
        .decrypt(&frame.as_bytes()[start..start + 80], &frame.dd())
        .is_err());
    frame
        .open_selected(&actor.opened, 1, 1, &bodyparts)
        .unwrap();
}
#[test]
fn contributions_embedded_before_post_and_framed_after_post_open_at_release() {
    use line_dealing::split::contribution::{ContributionContext, SealedContribution};
    for embedded in [true, false] {
        let mut rng = TestRng::new();
        let keys = committee(9);
        let prepared = PreparedEnvelope::new(
            Public::new(7, keylist_hash(&keys).unwrap(), 100),
            &keys,
            7,
            &mut rng,
        )
        .unwrap();
        let dd = prepared.dd();
        let (mut header, bodies, mut capsules) = fixture(RequestType::Spend, 2, 2, 1);
        let mut recipients = add_actors(&mut header, &mut capsules, 1, false);
        header.contribution_keys = header
            .labels()
            .iter()
            .map(|(v, g)| prepared.contribution_public(*v, *g).unwrap())
            .collect();
        let seal = |rng: &mut TestRng| {
            header
                .labels()
                .iter()
                .map(|(v, g)| {
                    SealedContribution::seal(
                        prepared.contribution_public(*v, *g).unwrap(),
                        &ContributionContext {
                            dd,
                            position: 1,
                            variant: *v,
                            generation: *g,
                        },
                        &[Scalar::from(21u64)],
                        rng,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let before = if embedded { Some(seal(&mut rng)) } else { None };
        if let Some(ref sealed) = before {
            header.actors[0].embedded = Some(EmbeddedContribution {
                token: [1; 16],
                sealed: sealed.clone(),
            });
            recipients.clear();
        }
        let frame = prepared
            .build(header.clone(), bodies, capsules, recipients, &mut rng)
            .unwrap()
            .authorize(None, &mut rng)
            .unwrap();
        let sealed = if let Some(sealed) = before {
            sealed
        } else {
            // Actor learns the advertised keys only after the request is posted.
            let actor = frame.open_actor(&[7; 32], 1).unwrap();
            let opened = actor.opened.header();
            let sealed = opened
                .labels()
                .iter()
                .zip(&opened.contribution_keys)
                .map(|((v, g), p)| {
                    SealedContribution::seal(
                        *p,
                        &ContributionContext {
                            dd,
                            position: 1,
                            variant: *v,
                            generation: *g,
                        },
                        &[Scalar::from(21u64)],
                        &mut rng,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let payload = ContributionPayload {
                target_hd: frame.hd(),
                position: 1,
                token: [1; 16],
                sealed,
            };
            opened.validate_contribution(&frame.hd(), &payload).unwrap();
            let contribution_header = Header::contribution(opened, payload).unwrap();
            // DECISIONS 54(2), DESIGN §4.6: a CONTRIB frame carries 32 random bytes in
            // auth_ref, as every envelope without an authorization. A caller-chosen
            // value (zero marks the frame as a contribution) is refused.
            for fixed in [[0; 32], [42; 32]] {
                let refused = PreparedEnvelope::new(
                    Public::new(7, keylist_hash(&keys).unwrap(), 100),
                    &keys,
                    7,
                    &mut rng,
                )
                .unwrap()
                .build(
                    contribution_header.clone(),
                    vec![],
                    vec![],
                    vec![],
                    &mut rng,
                )
                .unwrap()
                .authorize(Some(fixed), &mut rng);
                assert!(refused.is_err(), "CONTRIB frame took a fixed auth_ref");
            }
            let contribution = PreparedEnvelope::new(
                Public::new(7, keylist_hash(&keys).unwrap(), 100),
                &keys,
                7,
                &mut rng,
            )
            .unwrap()
            .build(contribution_header, vec![], vec![], vec![], &mut rng)
            .unwrap()
            .authorize(None, &mut rng)
            .unwrap();
            assert_ne!(contribution.dd(), dd);
            assert_ne!(contribution.public().auth_ref, [0; 32]);
            contribution.verify_public(&keys, 7, 7, 0).unwrap();
            let opened = contribution
                .open_header(&partials(&contribution, &keys, prf::Label::Hdr))
                .unwrap();
            assert_eq!(opened.header().kind, RequestType::Contrib);
            let payload = opened.header().contribution.as_ref().unwrap();
            header.validate_contribution(&frame.hd(), payload).unwrap();
            payload.sealed.clone()
        };
        let opened = frame
            .open_header(&partials(&frame, &keys, prf::Label::Hdr))
            .unwrap();
        let selected = frame
            .open_selected(
                &opened,
                1,
                1,
                &partials(
                    &frame,
                    &keys,
                    prf::Label::Body {
                        variant: 1,
                        generation: 1,
                    },
                ),
            )
            .unwrap();
        assert_eq!(
            sealed[0]
                .open(
                    selected.contribution_secret,
                    header.contribution_keys[0],
                    &ContributionContext {
                        dd,
                        position: 1,
                        variant: 1,
                        generation: 1
                    },
                    1
                )
                .unwrap(),
            vec![Scalar::from(21u64)]
        );
        assert!(sealed[1]
            .open(
                selected.contribution_secret,
                header.contribution_keys[1],
                &ContributionContext {
                    dd,
                    position: 1,
                    variant: 2,
                    generation: 1
                },
                1
            )
            .is_err());
    }
}
#[test]
fn parsers_reject_bad_counts_lengths_slots_and_oversized_committees() {
    let (mut h, _, mut caps) = fixture(RequestType::Spend, 2, 2, 1);
    h.tickets[1][0] ^= 1;
    assert!(h.encode().is_err());
    h.tickets[1][0] ^= 1;
    let bytes = h.encode().unwrap();
    for len in 0..bytes.len() {
        assert!(Header::decode(&bytes[..len]).is_err())
    }
    let cap = caps.remove(0);
    let bytes = cap.encode(2, 1).unwrap();
    for len in 0..bytes.len() {
        assert!(Capsule::decode(&bytes[..len], 2, 1).is_err())
    }
    let keys = vec![G; 1000];
    assert!(PreparedEnvelope::new(
        Public::new(7, keylist_hash(&keys).unwrap(), 100),
        &keys,
        7,
        &mut TestRng::new()
    )
    .is_err());
}

#[test]
fn failed_header_tag_requests_proofs_recombines_and_attributes_dealer_fault() {
    let (frame, keys) = make_frame(RequestType::Spend, 2, 1, 1);
    let mut rng = TestRng::new();
    let mut parts = (1..=9)
        .map(|i| {
            prf::partial(
                frame.decrypt_share(i, node_secret(i), &keys).unwrap(),
                i,
                &frame.dd(),
                prf::Label::Hdr,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut calls = 0;
    assert!(matches!(
        frame
            .open_header_with_fallback(&parts, |_| {
                calls += 1;
                None
            })
            .unwrap(),
        prf::OpenOutcome::Opened { .. }
    ));
    assert_eq!(calls, 0);
    parts[0].point += G;
    let outcome = frame
        .open_header_with_fallback(&parts, |p| {
            Some(
                prf::prove(
                    frame
                        .decrypt_share(p.index, node_secret(p.index), &keys)
                        .unwrap(),
                    p.index,
                    &frame.dd(),
                    prf::Label::Hdr,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .unwrap();
    assert!(matches!(outcome,prf::OpenOutcome::Opened{rejected,..} if rejected==vec![1]));
    let mut bytes = frame.as_bytes().to_vec();
    let start = 96 + 7 * 33 + 9 * 32 + 33 + LAYOUT_SIZE + 196;
    bytes[start] ^= 1;
    let bad = Envelope::decode(&bytes, 9, 7).unwrap();
    let outcome = bad
        .open_header_with_fallback(&parts, |p| {
            Some(
                prf::prove(
                    frame
                        .decrypt_share(p.index, node_secret(p.index), &keys)
                        .unwrap(),
                    p.index,
                    &frame.dd(),
                    prf::Label::Hdr,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .unwrap();
    assert!(matches!(outcome,prf::OpenOutcome::DealerFault{rejected} if rejected==vec![1]));
}

#[test]
fn malformed_suite_points_and_noncanonical_scalars_are_rejected() {
    for suite in 1..=3 {
        let (header, bodies, mut caps) = fixture(RequestType::Spend, suite, 1, 1);
        caps[0].nonces[0].fill(0);
        assert!(caps[0].encode(suite, 1).is_err());
        let keys = committee(3);
        let mut rng = TestRng::new();
        let p = PreparedEnvelope::new(
            Public::new(1, keylist_hash(&keys).unwrap(), 10),
            &keys,
            2,
            &mut rng,
        )
        .unwrap();
        assert!(p.build(header, bodies, caps, vec![], &mut rng).is_err());
    }
    let (header, _, caps) = fixture(RequestType::Spend, 3, 1, 1);
    let keys = committee(3);
    let mut rng = TestRng::new();
    let p = PreparedEnvelope::new(
        Public::new(1, keylist_hash(&keys).unwrap(), 10),
        &keys,
        2,
        &mut rng,
    )
    .unwrap();
    assert!(p
        .build(header, vec![vec![-Scalar::ONE]], caps, vec![], &mut rng)
        .is_err());
}

// The host fields of each capsule (transaction, prevouts, destination record)
// come from the fee variants that `split_sizes` measures: P2TR for BIP340
// (`SchnorrSetup`, `fixture_variants`), P2WPKH for ECDSA. The capacity test
// and the sizes table use one fixture.
fn sized_fixture(suite: u8, k: u8, l: u8) -> (Header, Vec<Vec<Scalar>>, Vec<Capsule>) {
    let (h, b, mut c) = fixture(RequestType::Spend, suite, k, l);
    let hosts: Vec<_> = match suite {
        1 => {
            let mut script = vec![0, 20];
            script.extend([9; 20]);
            line_dealing::split::request::ecdsa::fixture_variants(&script, k, l)
                .unwrap()
                .into_iter()
                .map(|v| (v.transaction, v.prevouts, v.destination))
                .collect()
        }
        2 => support::schnorr::<line_dealing::split::group::Secp>(9, k, l, 0)
            .variants
            .into_iter()
            .map(|v| (v.transaction, v.prevouts, v.destination))
            .collect(),
        _ => panic!("no measured host fixture for suite {suite}"),
    };
    for (v, (cap, (transaction, prevouts, destination))) in c.iter_mut().zip(hosts).enumerate() {
        cap.transaction = transaction;
        cap.prevouts = prevouts;
        cap.destination = destination;
        let halves = cap.nonces.len();
        assert_eq!(
            cap.encode(suite, halves).unwrap().len(),
            capsule_len(suite, h.g, l, v as u8 + 1)
        );
    }
    (h, b, c)
}
// design/enhancement/vectors/sizes.py `HOST`: the encoded host fields of one
// capsule with their three 2-byte length prefixes.
fn host_bytes(suite: u8, l: u8) -> usize {
    match (suite, l) {
        (1, 1) => HOST_ECDSA_1,
        (1, 2) => HOST_ECDSA_2,
        (2, 1) => HOST_P2TR_1,
        (2, 2) => HOST_P2TR_2,
        _ => panic!("no measured host fixture"),
    }
}
const HOST_ECDSA_1: usize = 173;
const HOST_ECDSA_2: usize = 246;
const HOST_P2TR_1: usize = 221;
const HOST_P2TR_2: usize = 306;
// sizes.py `cap`: one capsule without actors and without its AEAD tag. Variant
// `v` carries one nonce point per half (L on ECDSA, min(v, G)·L on Schnorr),
// the salt seed 32, T_0 33, the initiator 2 and the signing set {initiator} 4.
fn capsule_len(suite: u8, g: u8, l: u8, v: u8) -> usize {
    let nonces = if suite == 1 { l } else { v.min(g) * l };
    host_bytes(suite, l) + 33 * nonces as usize + 32 + 33 + 2 + 4
}
// The fixed TEE header fields: intent 24, public key 33, leaf_root 32, r_ic 32
// and one 32-byte salt per variant (sizes.py `tee_header`).
fn tee_header(k: u8) -> usize {
    24 + 33 + 32 + 32 + 32 * k as usize
}
#[test]
fn reference_and_real_serialization_budgets_cover_every_grid_and_committee() {
    // Rows of design/enhancement/vectors/sizes.py: the base frame at n = 9, the
    // bytes per other actor (non-TEE, TEE) and the largest |S| (n = 9 non-TEE,
    // TEE, n = 17 non-TEE, TEE). Both K = L = 1 suites are included.
    let rows = [
        (8, 2, 2, 11422, 790, 943, 6, 5, 6, 4),
        (8, 1, 2, 7532, 760, 853, 11, 10, 11, 9),
        (5, 2, 2, 7387, 649, 754, 14, 12, 13, 11),
        (3, 2, 1, 2887, 525, 558, 26, 24, 25, 23),
        (1, 1, 1, 1547, 455, 488, 33, 31, 32, 30),
        (1, 1, 2, 1708, 459, 496, 32, 30, 31, 29),
    ];
    for (n, t) in [(9, 7), (17, 12)] {
        let keys = committee(n);
        let mut rng = TestRng::new();
        for (k, l, suite, base9, pa, pa_tee, s9, s9_tee, s17, s17_tee) in rows {
            let (header, bodies, caps) = sized_fixture(suite, k, l);
            let b = header.labels().len();
            let h = header.half_count();
            let outer = t as usize * 33 + n as usize * 32 + 33 + 196;
            assert_eq!(outer, if n == 9 { 748 } else { 1169 });
            let base = base9 + if n == 9 { 0 } else { 421 };
            let capsules: usize = (1..=k)
                .map(|v| capsule_len(suite, header.g, l, v) + 16)
                .sum();
            let calculated = 96
                + outer
                + LAYOUT_SIZE
                + 214
                + 16
                + h * header.ticket_len()
                + b * (32 * l as usize + 48)
                + capsules;
            assert_eq!(calculated, base);
            let prepared = PreparedEnvelope::new(
                Public::new(7, keylist_hash(&keys).unwrap(), 100),
                &keys,
                t,
                &mut rng,
            )
            .unwrap();
            assert_eq!(
                prepared
                    .build(header, bodies, caps, vec![], &mut rng)
                    .unwrap()
                    .used_bytes(),
                base
            );
            for tee in [false, true] {
                let pa = if tee { pa_tee } else { pa };
                // Each other actor adds its padded actor capsule, so the
                // embedded form (sizes.py `emb`) replaces that capsule.
                assert!(pa > ACTOR_CAPSULE_SIZE);
                let tee_base = if tee { tee_header(k) } else { 0 };
                let max = (FRAME_SIZE - base - b * 33 - tee_base) / pa;
                assert_eq!(
                    max + 1,
                    match (n, tee) {
                        (9, false) => s9,
                        (9, true) => s9_tee,
                        (_, false) => s17,
                        (_, true) => s17_tee,
                    }
                );
                for count in [max, max + 1] {
                    let (mut header, bodies, mut caps) = sized_fixture(suite, k, l);
                    let actors = add_actors(&mut header, &mut caps, count, tee);
                    let prepared = PreparedEnvelope::new(
                        Public::new(7, keylist_hash(&keys).unwrap(), 100),
                        &keys,
                        t,
                        &mut rng,
                    )
                    .unwrap();
                    let result = prepared.build(header, bodies, caps, actors, &mut rng);
                    if count == max {
                        assert_eq!(
                            result.unwrap().used_bytes(),
                            base + b * 33 + tee_base + pa * count
                        )
                    } else {
                        assert!(result.is_err())
                    }
                }
                println!(
                    "n={n} K={k} L={l} suite={suite} tee={tee}: S={} base={base} extraTEE={tee_base} perActor={pa}",
                    max + 1
                );
            }
        }
    }
}
#[test]
fn contribution_and_embedded_bytes_match_reference() {
    use line_dealing::split::contribution::{ContributionContext, SealedContribution};
    for (n, t) in [(9, 7), (17, 12)] {
        let keys = committee(n);
        let mut rng = TestRng::new();
        for l in [1, 2] {
            let (mut target, _, _) = fixture(RequestType::Spend, 2, 8, l);
            let seal = target
                .labels()
                .iter()
                .map(|(v, g)| {
                    SealedContribution::seal(
                        G,
                        &ContributionContext {
                            dd: [1; 32],
                            position: 1,
                            variant: *v,
                            generation: *g,
                        },
                        &vec![Scalar::ONE; l as usize],
                        &mut rng,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let embedded = EmbeddedContribution {
                token: [1; 16],
                sealed: seal.clone(),
            };
            let emb_len = embedded.token.len()
                + embedded
                    .sealed
                    .iter()
                    .map(|s| s.encode().len())
                    .sum::<usize>();
            assert_eq!(emb_len, if l == 1 { 1231 } else { 1711 });
            let plain_before = target.encode().unwrap().len();
            target.actors.push(ActorSlot {
                position: 1,
                token_hash: token_hash(&[1; 16]),
                party_index: None,
                embedded: Some(embedded),
            });
            target.contribution_keys = vec![G; target.labels().len()];
            assert_eq!(
                target.encode().unwrap().len() - plain_before,
                33 + 15 * 33 + emb_len
            );
            let header = Header::contribution(
                &target,
                ContributionPayload {
                    target_hd: [2; 32],
                    position: 1,
                    token: [1; 16],
                    sealed: seal,
                },
            )
            .unwrap();
            let prepared = PreparedEnvelope::new(
                Public::new(7, keylist_hash(&keys).unwrap(), 100),
                &keys,
                t,
                &mut rng,
            )
            .unwrap();
            let pending = prepared
                .build(header, vec![], vec![], vec![], &mut rng)
                .unwrap();
            assert_eq!(
                pending.used_bytes(),
                LAYOUT_SIZE
                    + match (n, l) {
                        (9, 1) => 2274,
                        (9, 2) => 2754,
                        (17, 1) => 2695,
                        (17, 2) => 3175,
                        _ => unreachable!(),
                    }
            );
        }
    }
}

#[test]
fn twelve_of_seventeen_opens_and_under_threshold_does_not() {
    let keys = committee(17);
    let mut rng = TestRng::new();
    let (header, bodies, caps) = fixture(RequestType::Spend, 1, 3, 2);
    let frame = PreparedEnvelope::new(
        Public::new(8, keylist_hash(&keys).unwrap(), 100),
        &keys,
        12,
        &mut rng,
    )
    .unwrap()
    .build(header, bodies, caps, vec![], &mut rng)
    .unwrap()
    .authorize(None, &mut rng)
    .unwrap();
    frame.verify_public(&keys, 12, 8, 99).unwrap();
    assert!(frame.verify_public(&keys, 12, 8, 100).is_err());
    assert!(frame.verify_public(&keys, 11, 8, 99).is_err());
    let parts = partials(&frame, &keys, prf::Label::Hdr);
    assert!(frame.open_header(&parts[..11]).is_err());
    let header = frame.open_header(&parts).unwrap();
    frame
        .open_selected(
            &header,
            3,
            0,
            &partials(
                &frame,
                &keys,
                prf::Label::Body {
                    variant: 3,
                    generation: 0,
                },
            ),
        )
        .unwrap();
    let (other, _) = make_frame(RequestType::Spend, 2, 1, 1);
    assert!(other.open_selected(&header, 1, 0, &parts).is_err());
}

#[test]
fn selected_body_recovers_from_forged_partial_with_full_statement_proofs() {
    let (frame, keys) = make_frame(RequestType::Spend, 2, 2, 1);
    let mut rng = TestRng::new();
    let header = frame
        .open_header(&partials(&frame, &keys, prf::Label::Hdr))
        .unwrap();
    let label = prf::Label::Body {
        variant: 2,
        generation: 1,
    };
    let mut parts = (1..=9)
        .map(|i| {
            prf::partial(
                frame.decrypt_share(i, node_secret(i), &keys).unwrap(),
                i,
                &frame.dd(),
                label,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    parts[0].point += G;
    let outcome = frame
        .open_selected_with_fallback(&header, 2, 1, &parts, |p| {
            Some(
                prf::prove(
                    frame
                        .decrypt_share(p.index, node_secret(p.index), &keys)
                        .unwrap(),
                    p.index,
                    &frame.dd(),
                    label,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .unwrap();
    match outcome {
        prf::OpenOutcome::Opened {
            plaintext,
            rejected,
        } => {
            assert_eq!(plaintext.capsule.transaction, vec![2; 120]);
            assert_eq!(rejected, vec![1]);
        }
        _ => panic!("proved good body must open"),
    }
}
