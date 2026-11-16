use crate::common::*;
use k256::Scalar;
use line_dealing::{algebra::*, hash::*, message::*, reshare::*};

#[test]
fn encrypted_reshare_open_slot_still_signs_and_verifies() {
    let (message, accepted) = open_ecdsa();
    let old = shares(&accepted);
    let dealers = [1, 2, 4, 6, 9, 12];
    let new_keys: Vec<_> = (1..=10).map(|i| G * sc(&format!("new/{i}"))).collect();
    let mut rng = TestRng::new();
    let mut transferred = Vec::new();
    for (component, label) in message
        .deal
        .labels(&message.header)
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut dealings = Vec::new();
        for dealer in dealers {
            let domain = ReshareDomain {
                rid: message.rid().unwrap(),
                old_epoch: 7,
                new_epoch: 8,
                dealer,
            };
            dealings.push(
                Subdealing::create(
                    domain,
                    *label,
                    &accepted.polynomials()[component],
                    old[dealer as usize - 1].values()[component],
                    NewCommittee {
                        keys: new_keys.clone(),
                        f: 3,
                        threshold: 4,
                    },
                    sc(&format!("rs-eph/{component}/{dealer}")),
                    &mut rng,
                )
                .unwrap(),
            );
        }
        let transfer = Transfer::verify(&accepted.polynomials()[component], &dealings).unwrap();
        assert_eq!(
            transfer.commitment().constant,
            accepted.polynomials()[component].constant
        );
        let mut values = Vec::new();
        for node in 1..=10 {
            let share = transfer.decrypt(node, sc(&format!("new/{node}"))).unwrap();
            assert!(transfer.commitment().verify(node, share));
            values.push(share);
        }
        assert_eq!(
            interpolate(
                &values[..4]
                    .iter()
                    .enumerate()
                    .map(|(i, v)| (i as u16 + 1, *v))
                    .collect::<Vec<_>>(),
                4
            )
            .unwrap(),
            interpolate(
                &old[..6]
                    .iter()
                    .map(|s| (s.node(), s.values()[component]))
                    .collect::<Vec<_>>(),
                6
            )
            .unwrap()
        );
        transferred.push((transfer.commitment().clone(), values));
        let mut bad = dealings.clone();
        bad[0].ciphertexts[0] += Scalar::ONE;
        assert!(Transfer::verify(&accepted.polynomials()[component], &bad).is_err());
        let mut bad = dealings.clone();
        bad[0].domain.new_epoch += 1;
        assert!(Transfer::verify(&accepted.polynomials()[component], &bad).is_err());
        assert!(Transfer::verify(&accepted.polynomials()[component], &dealings[..5]).is_err());
        let mut bad = dealings.clone();
        bad[1] = bad[0].clone();
        assert!(Transfer::verify(&accepted.polynomials()[component], &bad).is_err());
    }
    let m = msg("reshared");
    let original = accepted.signing_package(1, 1, m, [9; 32]).unwrap();
    let commitments: Vec<_> = transferred.iter().map(|(c, _)| c.clone()).collect();
    let package = original.with_resharing(10, 4, &commitments).unwrap();
    let mut parts = Vec::new();
    for node in [2, 4, 7, 10] {
        let values: Vec<_> = transferred
            .iter()
            .map(|(_, vs)| vs[node as usize - 1])
            .collect();
        parts.push(package.partial_from_reshared(node, &values).unwrap());
    }
    assert!(parts.iter().all(|p| package.verify_partial(p)));
    package
        .combine(&parts)
        .unwrap()
        .verify(G * secret(), &m)
        .unwrap();
    let mut wrong = commitments;
    wrong[0].constant += G;
    assert!(original.with_resharing(10, 4, &wrong).is_err());
}

#[test]
fn reshare_domain_and_component_bind_each_pad() {
    let a = ReshareDomain {
        rid: [1; 32],
        old_epoch: 7,
        new_epoch: 8,
        dealer: 1,
    };
    let b = ReshareDomain { dealer: 2, ..a };
    let hd = a.digest(b"header", b"deal").unwrap();
    assert_ne!(hd, b.digest(b"header", b"deal").unwrap());
    assert_ne!(hd, dealing_digest(b"header", b"deal").unwrap());
    let label = SlotLabel::new(2, 2, 1, 1).unwrap();
    let pk = G * node_secret(1);
    let dh = pk * sc("eph");
    assert_ne!(
        share_pad(&hd, 1, pk, dh, label, Some(a)).unwrap(),
        share_pad(&hd, 1, pk, dh, label, Some(b)).unwrap()
    );
    assert_ne!(
        share_pad(&hd, 1, pk, dh, label, Some(a)).unwrap(),
        share_pad(&hd, 1, pk, dh, label, None).unwrap()
    );
}

#[test]
fn malformed_transfer_threshold_is_an_error() {
    let (message, accepted) = open_ecdsa();
    let old = shares(&accepted);
    let mut rng = TestRng::new();
    let label = SlotLabel::new(2, 2, 1, 1).unwrap();
    let mut dealings = Vec::new();
    for dealer in 1..=6 {
        dealings.push(
            Subdealing::create(
                ReshareDomain {
                    rid: message.rid().unwrap(),
                    old_epoch: 7,
                    new_epoch: 8,
                    dealer,
                },
                label,
                &accepted.polynomials()[0],
                old[dealer as usize - 1].values()[0],
                NewCommittee {
                    keys: keys(),
                    f: 5,
                    threshold: 6,
                },
                sc(&format!("e/{dealer}")),
                &mut rng,
            )
            .unwrap(),
        );
    }
    dealings[0].committee.threshold = 0;
    assert!(Transfer::verify(&accepted.polynomials()[0], &dealings).is_err());
}

#[test]
fn zero_old_share_can_be_reshared_with_identity_implied_constant() {
    let polynomial = Polynomial::from_coefficients(vec![Scalar::ONE, -Scalar::ONE]).unwrap();
    let old = polynomial.commit(G).unwrap();
    let mut rng = TestRng::new();
    let mut dealings = Vec::new();
    assert_eq!(polynomial.evaluate(1).unwrap(), Scalar::ZERO);
    for dealer in 1..=2 {
        dealings.push(
            Subdealing::create(
                ReshareDomain {
                    rid: [1; 32],
                    old_epoch: 7,
                    new_epoch: 8,
                    dealer,
                },
                SlotLabel::new(2, 2, 1, 1).unwrap(),
                &old,
                polynomial.evaluate(dealer).unwrap(),
                NewCommittee {
                    keys: keys(),
                    f: 5,
                    threshold: 6,
                },
                sc(&format!("zero-eph/{dealer}")),
                &mut rng,
            )
            .unwrap(),
        );
    }
    let transfer = Transfer::verify(&old, &dealings).unwrap();
    let shares: Vec<_> = (1..=6)
        .map(|node| (node, transfer.decrypt(node, node_secret(node)).unwrap()))
        .collect();
    assert_eq!(interpolate(&shares, 6).unwrap(), Scalar::ONE);
}

#[test]
fn bip340_resharing_preserves_original_binding_with_multiple_inputs() {
    let mut hdr = header(2, 2, 1);
    hdr.inputs = 2;
    let mut rng = TestRng::new();
    let nonces = [(sc("bd/1"), sc("be/1")), (sc("bd/2"), sc("be/2"))];
    let message = Owner::open_bip340(hdr, secret(), &nonces, &mut rng)
        .unwrap()
        .encrypt(sc("b-eph"), &keys(), &mut rng)
        .unwrap();
    let accepted = message.step_a(&Context::new(vec![])).unwrap();
    let old = shares(&accepted);
    let mut commitments = Vec::new();
    let mut new_values = vec![Vec::new(); 16];
    for (index, label) in message
        .deal
        .labels(&message.header)
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut dealings = Vec::new();
        for dealer in 1..=6 {
            dealings.push(
                Subdealing::create(
                    ReshareDomain {
                        rid: message.rid().unwrap(),
                        old_epoch: 7,
                        new_epoch: 8,
                        dealer,
                    },
                    *label,
                    &accepted.polynomials()[index],
                    old[dealer as usize - 1].values()[index],
                    NewCommittee {
                        keys: keys(),
                        f: 5,
                        threshold: 6,
                    },
                    sc(&format!("b-rs/{index}/{dealer}")),
                    &mut rng,
                )
                .unwrap(),
            );
        }
        let transfer = Transfer::verify(&accepted.polynomials()[index], &dealings).unwrap();
        commitments.push(transfer.commitment().clone());
        for node in 1..=16 {
            new_values[node as usize - 1].push(transfer.decrypt(node, node_secret(node)).unwrap());
        }
    }
    for input in 1..=2 {
        let m = msg(&format!("b-input/{input}"));
        let digest = msg("b-lock");
        let original = accepted.signing_package(1, input, m, digest).unwrap();
        let package = original.with_resharing(16, 6, &commitments).unwrap();
        assert_eq!(original.nonce(), package.nonce());
        let partials: Vec<_> = [3, 5, 8, 10, 14, 16]
            .into_iter()
            .map(|node| {
                package
                    .partial_from_reshared(node, &new_values[node as usize - 1])
                    .unwrap()
            })
            .collect();
        package
            .combine(&partials)
            .unwrap()
            .verify(G * normalized_secret(), &m)
            .unwrap();
    }
}
