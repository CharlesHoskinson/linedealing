mod common;

use common::*;
use k256::{elliptic_curve::rand_core::RngCore, ProjectivePoint, Scalar};
use line_dealing::{
    algebra::{
        encode_point, interpolate, inverse, is_odd, lagrange, reduce, Commitment, Polynomial,
    },
    message::{
        ecdsa_r, Accepted, AuthProof, Deal, DhProof, EcdsaSlot, Owner, OwnerMessage, SchnorrSlot,
        SealedPoint,
    },
    signing::{Combined, Partial, SigningPackage},
    Error,
};

fn old_reduce(bytes: &[u8]) -> Scalar {
    bytes.iter().fold(Scalar::ZERO, |a, b| {
        a * Scalar::from(256u64) + Scalar::from(*b as u64)
    })
}

#[test]
fn decoded_owner_wire_hashes_match_and_public_mutations_invalidate_the_cache() {
    for suite in [1, 2] {
        let (_, _, accepted) = package(suite);
        let original = accepted.message();
        let bytes = original.encode().unwrap();
        let decoded = OwnerMessage::decode(&bytes).unwrap();
        let rebuilt = OwnerMessage::new(
            decoded.header.clone(),
            decoded.deal.clone(),
            decoded.ciphertexts.clone(),
            decoded.proof.clone(),
        );
        assert_eq!(decoded, rebuilt);
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.hd().unwrap(), rebuilt.hd().unwrap());
        assert_eq!(decoded.rid().unwrap(), rebuilt.rid().unwrap());
        assert_eq!(decoded.mid().unwrap(), rebuilt.mid().unwrap());
        decoded.step_a(&Context::new(vec![])).unwrap();
        for field in 0..5 {
            let mut changed = decoded.clone();
            match field {
                0 => changed.header.owner_nonce[0] ^= 1,
                1 => changed.ciphertexts[0][0] += Scalar::ONE,
                2 => changed.proof.z_e += Scalar::ONE,
                3 => changed.proof.t_1 += G,
                _ => match &mut changed.deal {
                    Deal::OpenEcdsa(slots) => slots[0].w[0] += G,
                    Deal::OpenBip340 { x, .. } => x[0] += G,
                    _ => unreachable!(),
                },
            }
            let current = OwnerMessage::new(
                changed.header.clone(),
                changed.deal.clone(),
                changed.ciphertexts.clone(),
                changed.proof.clone(),
            );
            assert_eq!(changed.encode().unwrap(), current.encode().unwrap());
            assert_eq!(changed.hd().unwrap(), current.hd().unwrap());
            assert_eq!(changed.rid().unwrap(), current.rid().unwrap());
            assert_eq!(changed.mid().unwrap(), current.mid().unwrap());
            assert_ne!(changed.mid().unwrap(), decoded.mid().unwrap());
            assert!(changed.step_a(&Context::new(vec![])).is_err());
        }
        let mut invalid = decoded.clone();
        invalid.proof.t_2 = ProjectivePoint::IDENTITY;
        assert_eq!(invalid.encode(), Err(Error::Point));
        assert!(invalid.step_a(&Context::new(vec![])).is_err());
    }
}

#[test]
fn decoded_dh_wire_challenge_and_public_mutations_use_current_fields() {
    let mid = msg("dh-mid");
    let pk = G * secret();
    let ephemeral = G * sc("dh-ephemeral");
    let original = DhProof::create(&mid, pk, ephemeral, secret(), &mut TestRng::new()).unwrap();
    let bytes = original.encode().unwrap();
    let decoded = DhProof::decode(&bytes).unwrap();
    decoded.verify(&mid, pk, ephemeral).unwrap();
    assert_eq!(decoded.encode().unwrap(), bytes);
    let rebuilt = DhProof::new(decoded.key, decoded.t_1, decoded.t_2, decoded.z);
    assert_eq!(decoded.encode().unwrap(), rebuilt.encode().unwrap());
    rebuilt.verify(&mid, pk, ephemeral).unwrap();
    for field in 0..4 {
        let mut changed = decoded.clone();
        match field {
            0 => changed.key += G,
            1 => changed.t_1 += G,
            2 => changed.t_2 += G,
            _ => changed.z += Scalar::ONE,
        }
        let current = DhProof::new(changed.key, changed.t_1, changed.t_2, changed.z);
        assert_eq!(changed.encode().unwrap(), current.encode().unwrap());
        assert_ne!(changed.encode().unwrap(), bytes);
        assert!(changed.verify(&mid, pk, ephemeral).is_err());
    }
    let mut invalid = decoded;
    invalid.t_1 = ProjectivePoint::IDENTITY;
    assert_eq!(invalid.encode(), Err(Error::Point));
    assert_eq!(invalid.verify(&mid, pk, ephemeral), Err(Error::Point));
}

#[test]
fn decoded_sealed_owner_uses_wire_nonces_for_both_suites() {
    for suite in [1, 2] {
        let (signing, parts, _) = package(suite);
        let mut rng = TestRng::new();
        let owner = match signing.combine(&parts[..6]).unwrap() {
            Combined::Ecdsa { signature, .. } => {
                Owner::sealed_ecdsa(header(suite, 1, 1), &[(msg("tx"), signature)], &mut rng)
            }
            Combined::Bip340(signature) => {
                Owner::sealed_bip340(header(suite, 1, 1), &[(msg("tx"), signature)], &mut rng)
            }
        }
        .unwrap();
        let original = owner
            .encrypt(sc("sealed-ephemeral"), &keys(), &mut rng)
            .unwrap();
        let bytes = original.encode().unwrap();
        let decoded = OwnerMessage::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.hd().unwrap(), original.hd().unwrap());
        assert_eq!(decoded.rid().unwrap(), original.rid().unwrap());
        assert_eq!(decoded.mid().unwrap(), original.mid().unwrap());
        let context = Context::new(vec![msg("tx")]);
        let accepted = decoded.step_a(&context).unwrap();
        assert_eq!(
            accepted.polynomials(),
            original
                .deal
                .public_polynomials(&original.header, &[msg("tx")])
                .unwrap()
        );
        let package = accepted
            .signing_package(1, 1, msg("tx"), msg("sealed-digest"))
            .unwrap();
        let parts: Vec<_> = shares(&accepted)
            .iter()
            .map(|s| package.partial(s).unwrap())
            .collect();
        package
            .combine(&parts[..6])
            .unwrap()
            .verify(original.header.public_key, &msg("tx"))
            .unwrap();
        let mut changed = decoded.clone();
        changed.ciphertexts[0][0] += Scalar::ONE;
        assert_ne!(changed.mid().unwrap(), decoded.mid().unwrap());
        assert!(changed.step_a(&context).is_err());
    }
}

#[test]
fn decoded_owner_acceptance_preserves_all_ecdsa_address_profiles() {
    for kind in [1, 2, 3, 5] {
        let mut rng = TestRng::new();
        let mut hdr = header(1, 2, 1);
        hdr.addr_type = kind;
        hdr.address = line_dealing::wire::address_for(kind, hdr.public_key).unwrap();
        let original = Owner::open_ecdsa(hdr, secret(), &[sc("address-nonce")], &mut rng)
            .unwrap()
            .encrypt(sc("address-ephemeral"), &keys(), &mut rng)
            .unwrap();
        let decoded = OwnerMessage::decode(&original.encode().unwrap()).unwrap();
        assert_eq!(decoded.hd().unwrap(), original.hd().unwrap());
        decoded.step_a(&Context::new(vec![])).unwrap();
        let mut wrong = decoded;
        wrong.header.address[0] ^= 1;
        assert!(matches!(
            wrong.step_a(&Context::new(vec![])),
            Err(Error::Context)
        ));
    }
}

#[test]
fn reduction_matches_old_big_endian_formula_at_boundaries_and_random_lengths() {
    let mut rng = TestRng::new();
    for len in [
        0, 1, 2, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 257, 1024,
    ] {
        for fill in [0, 1, 255] {
            let bytes = vec![fill; len];
            assert_eq!(reduce(&bytes), old_reduce(&bytes), "length {len}");
        }
        let mut bytes = vec![0; len];
        rng.fill_bytes(&mut bytes);
        assert_eq!(reduce(&bytes), old_reduce(&bytes), "length {len}");
    }
    // q - 1, q, and q + 1, both alone and with leading zeros.
    let mut order = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ];
    for expected in [-Scalar::ONE, Scalar::ZERO, Scalar::ONE] {
        assert_eq!(reduce(&order), expected);
        assert_eq!(reduce(&[&[0; 65][..], &order].concat()), expected);
        order[31] += 1;
    }
    for _ in 0..128 {
        let len = (rng.next_u32() % 1025) as usize;
        let mut bytes = vec![0; len];
        rng.fill_bytes(&mut bytes);
        assert_eq!(reduce(&bytes), old_reduce(&bytes));
    }
}

#[test]
fn commitment_evaluation_matches_full_width_horner() {
    let mut rng = TestRng::new();
    for degree in [0, 1, 2, 5, 15] {
        let p = Polynomial::random(sc("constant"), degree + 1, &mut rng).unwrap();
        for base in [G, G * sc("arbitrary-base")] {
            let c = p.commit(base).unwrap();
            for node in [1, 2, 3, 16, 127, 128, 255, 256, 1023, 32768, u16::MAX] {
                let x = Scalar::from(node as u64);
                let expected = c
                    .coefficients
                    .iter()
                    .rev()
                    .fold(ProjectivePoint::IDENTITY, |acc, point| (acc + point) * x)
                    + c.constant;
                assert_eq!(c.evaluate(node).unwrap(), expected);
                assert_eq!(expected, base * p.evaluate(node).unwrap());
                assert!(c.verify(node, p.evaluate(node).unwrap()));
            }
            assert_eq!(c.evaluate(0), Err(Error::Parameters));
            for _ in 0..32 {
                let node = (rng.next_u32() % u16::MAX as u32 + 1) as u16;
                assert_eq!(c.evaluate(node).unwrap(), base * p.evaluate(node).unwrap());
            }
        }
    }
    // Public coefficients and the constant may be identity after resharing.
    let c = Commitment {
        base: G,
        constant: ProjectivePoint::IDENTITY,
        coefficients: vec![ProjectivePoint::IDENTITY, -G, G],
    };
    assert_eq!(c.evaluate(1).unwrap(), ProjectivePoint::IDENTITY);
}

fn package(suite: u8) -> (SigningPackage, Vec<Partial>, Accepted) {
    let mut rng = TestRng::new();
    let owner = if suite == 1 {
        Owner::open_ecdsa(header(1, 2, 1), secret(), &[sc("nonce")], &mut rng)
    } else {
        Owner::open_bip340(header(2, 2, 1), secret(), &[(sc("d"), sc("e"))], &mut rng)
    }
    .unwrap();
    let message = owner.encrypt(sc("ephemeral"), &keys(), &mut rng).unwrap();
    let accepted = message.step_a(&Context::new(vec![])).unwrap();
    let package = accepted
        .signing_package(1, 1, msg("tx"), msg("digest"))
        .unwrap();
    let parts = shares(&accepted)
        .iter()
        .map(|s| package.partial(s).unwrap())
        .collect();
    (package, parts, accepted)
}

#[test]
fn optimistic_combiner_recovers_and_names_bad_partials_in_both_suites() {
    for suite in [1, 2] {
        let (package, parts, accepted) = package(suite);
        let (combined, faults) = package.combine_with_faults(&parts[..6]).unwrap();
        assert!(faults.is_empty());
        combined
            .verify(accepted.message().header.public_key, &msg("tx"))
            .unwrap();
        let mut corrupted = parts[..9].to_vec();
        corrupted[1].value += Scalar::ONE;
        corrupted[7].value -= Scalar::ONE;
        let (combined, faults) = package.combine_with_faults(&corrupted).unwrap();
        assert_eq!(faults, vec![2, 8]);
        combined
            .verify(accepted.message().header.public_key, &msg("tx"))
            .unwrap();
        package.combine(&corrupted).unwrap();
        assert!(matches!(
            package.combine_with_faults(&corrupted[..6]),
            Err(Error::BadPartial(2))
        ));
        assert!(matches!(
            package.combine(&parts[..5]),
            Err(Error::Threshold)
        ));
        assert!(matches!(
            package.combine(&[parts[0]; 6]),
            Err(Error::Threshold)
        ));
        let mut invalid = parts[..6].to_vec();
        invalid[0].node = 0;
        assert!(matches!(package.combine(&invalid), Err(Error::Share)));
    }
}

#[test]
fn zero_interpolated_scalar_triggers_fault_detection_and_retry() {
    for suite in [1, 2] {
        let (package, parts, accepted) = package(suite);
        let mut corrupted = parts[..7].to_vec();
        let nodes: Vec<_> = corrupted.iter().map(|p| p.node).collect();
        let scalar = interpolate(
            &corrupted
                .iter()
                .map(|p| (p.node, p.value))
                .collect::<Vec<_>>(),
            6,
        )
        .unwrap();
        let lambda = lagrange(&nodes).unwrap()[0];
        corrupted[0].value -= scalar * inverse(lambda).unwrap();
        assert_eq!(
            interpolate(
                &corrupted
                    .iter()
                    .map(|p| (p.node, p.value))
                    .collect::<Vec<_>>(),
                6
            )
            .unwrap(),
            Scalar::ZERO
        );
        let (combined, faults) = package.combine_with_faults(&corrupted).unwrap();
        assert_eq!(faults, vec![1]);
        combined
            .verify(accepted.message().header.public_key, &msg("tx"))
            .unwrap();
        corrupted.pop();
        let nodes: Vec<_> = corrupted.iter().map(|p| p.node).collect();
        let scalar = interpolate(
            &corrupted
                .iter()
                .map(|p| (p.node, p.value))
                .collect::<Vec<_>>(),
            6,
        )
        .unwrap();
        corrupted[0].value -= scalar * inverse(lagrange(&nodes).unwrap()[0]).unwrap();
        assert_eq!(
            interpolate(
                &corrupted
                    .iter()
                    .map(|p| (p.node, p.value))
                    .collect::<Vec<_>>(),
                6
            )
            .unwrap(),
            Scalar::ZERO
        );
        assert!(matches!(
            package.combine_with_faults(&corrupted),
            Err(Error::BadPartial(1))
        ));
    }
}

#[test]
fn valid_optimistic_signature_does_not_scan_cancelling_bad_partials() {
    for suite in [1, 2] {
        let (package, parts, accepted) = package(suite);
        let mut corrupted = parts[..6].to_vec();
        let weights = lagrange(&corrupted.iter().map(|p| p.node).collect::<Vec<_>>()).unwrap();
        corrupted[0].value += weights[1];
        corrupted[1].value -= weights[0];
        assert!(!package.verify_partial(&corrupted[0]));
        assert!(!package.verify_partial(&corrupted[1]));
        let (combined, faults) = package.combine_with_faults(&corrupted).unwrap();
        assert!(faults.is_empty());
        combined
            .verify(accepted.message().header.public_key, &msg("tx"))
            .unwrap();
    }
}

#[test]
fn zero_final_with_all_valid_partials_does_not_accuse_a_node() {
    let (original, _, accepted) = package(1);
    let zero_message: [u8; 32] = (-ecdsa_r(original.nonce()).unwrap() * secret())
        .to_bytes()
        .into();
    let package = accepted
        .signing_package(1, 1, zero_message, msg("digest"))
        .unwrap();
    let parts: Vec<_> = shares(&accepted)
        .iter()
        .map(|s| package.partial(s).unwrap())
        .collect();
    assert_eq!(
        interpolate(
            &parts[..6]
                .iter()
                .map(|p| (p.node, p.value))
                .collect::<Vec<_>>(),
            6
        )
        .unwrap(),
        Scalar::ZERO
    );
    assert!(parts.iter().all(|p| package.verify_partial(p)));
    assert!(matches!(
        package.combine_with_faults(&parts[..6]),
        Err(Error::Signature)
    ));
}

#[test]
fn batch_encoding_matches_individual_wire_points_in_all_deal_layouts() {
    let mut rng = TestRng::new();
    let coefficients = Polynomial::random(sc("wire"), 6, &mut rng)
        .unwrap()
        .commit(G)
        .unwrap()
        .coefficients;
    let nonce = if is_odd(G * sc("wire-nonce")).unwrap() {
        -G * sc("wire-nonce")
    } else {
        G * sc("wire-nonce")
    };
    for (suite, mode, deal, wire_points, x_only) in [
        (
            1,
            2,
            Deal::OpenEcdsa(vec![EcdsaSlot {
                nonce,
                w: coefficients.clone(),
                mu: coefficients.clone(),
            }]),
            [vec![nonce], coefficients.clone(), coefficients.clone()].concat(),
            false,
        ),
        (
            2,
            2,
            Deal::OpenBip340 {
                x: coefficients.clone(),
                slots: vec![SchnorrSlot {
                    d: nonce,
                    e: G,
                    d_commitments: coefficients.clone(),
                    e_commitments: coefficients.clone(),
                }],
            },
            [
                coefficients.clone(),
                vec![nonce, G],
                coefficients.clone(),
                coefficients.clone(),
            ]
            .concat(),
            false,
        ),
        (
            1,
            1,
            Deal::Sealed(vec![SealedPoint {
                nonce,
                commitments: coefficients.clone(),
            }]),
            [vec![nonce], coefficients.clone()].concat(),
            false,
        ),
        (
            2,
            1,
            Deal::Sealed(vec![SealedPoint {
                nonce,
                commitments: coefficients.clone(),
            }]),
            [vec![nonce], coefficients.clone()].concat(),
            true,
        ),
    ] {
        let mut expected = Vec::new();
        for (index, point) in wire_points.iter().enumerate() {
            let bytes = encode_point(*point).unwrap();
            expected.extend_from_slice(if x_only && index == 0 {
                &bytes[1..]
            } else {
                &bytes
            });
        }
        assert_eq!(deal.encode(&header(suite, mode, 1)).unwrap(), expected);
    }
    let mut invalid = coefficients;
    invalid[2] = ProjectivePoint::IDENTITY;
    let bad = Deal::Sealed(vec![SealedPoint {
        nonce,
        commitments: invalid,
    }]);
    assert_eq!(bad.encode(&header(1, 1, 1)), Err(Error::Point));
    // A zero-degree commitment must not call k256's empty batch inversion.
    let constant = Polynomial::from_coefficients(vec![Scalar::ZERO])
        .unwrap()
        .commit(G)
        .unwrap();
    assert!(constant.coefficients.is_empty());
    assert_eq!(constant.constant, ProjectivePoint::IDENTITY);
    assert!(matches!(
        Polynomial::from_coefficients(vec![Scalar::ONE, Scalar::ZERO])
            .unwrap()
            .commit(G),
        Err(Error::Point)
    ));
}

#[test]
fn batch_encoding_preserves_auth_and_dh_proof_bytes() {
    let mut rng = TestRng::new();
    let proof = AuthProof::create(
        &msg("hd"),
        b"ct",
        sc("ephemeral"),
        secret(),
        G,
        None,
        &mut rng,
    )
    .unwrap();
    let expected = [
        encode_point(proof.e_prime).unwrap().as_slice(),
        &encode_point(proof.t_1).unwrap(),
        &encode_point(proof.t_2).unwrap(),
        &proof.z_e.to_bytes(),
        &encode_point(proof.t_a).unwrap(),
        &proof.z_a.to_bytes(),
    ]
    .concat();
    assert_eq!(proof.encode().unwrap(), expected);
    proof
        .verify(
            &msg("hd"),
            b"ct",
            G * sc("ephemeral"),
            G,
            G * secret(),
            None,
        )
        .unwrap();
    let dh = DhProof::create(
        &msg("mid"),
        G * secret(),
        G * sc("ephemeral"),
        secret(),
        &mut rng,
    )
    .unwrap();
    let expected = [
        encode_point(dh.key).unwrap().as_slice(),
        &encode_point(dh.t_1).unwrap(),
        &encode_point(dh.t_2).unwrap(),
        &dh.z.to_bytes(),
    ]
    .concat();
    assert_eq!(dh.encode().unwrap(), expected);
    dh.verify(&msg("mid"), G * secret(), G * sc("ephemeral"))
        .unwrap();
}
