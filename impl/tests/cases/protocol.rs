use crate::common::*;
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, VerifyingKey},
    elliptic_curve::scalar::IsHigh,
    Scalar,
};
use line_dealing::{algebra::*, hash::*, message::*, signing::*, wire::*, Error};

#[test]
fn open_ecdsa_all_8008_threshold_subsets_and_tampered_partial() {
    let (message, accepted) = open_ecdsa();
    assert_eq!(message.header.encode().unwrap().len(), 524);
    assert_eq!(message.encode().unwrap().len(), 2107);
    assert_eq!(
        OwnerMessage::decode(&message.encode().unwrap()).unwrap(),
        message
    );
    let m = msg("tx-A");
    let pkg = accepted.signing_package(1, 1, m, [9; 32]).unwrap();
    let parts: Vec<_> = shares(&accepted)
        .iter()
        .map(|s| pkg.partial(s).unwrap())
        .collect();
    assert!(parts.iter().all(|p| pkg.verify_partial(p)));
    let mut bad = parts[3];
    bad.value += Scalar::ONE;
    assert!(!pkg.verify_partial(&bad));
    let mut corrupted = parts[..6].to_vec();
    corrupted[3] = bad;
    assert!(pkg.combine(&corrupted).is_err());
    assert!(matches!(pkg.combine(&parts[..5]), Err(Error::Threshold)));
    assert_ne!(
        interpolate(
            &parts[..5]
                .iter()
                .map(|p| (p.node, p.value))
                .collect::<Vec<_>>(),
            5
        )
        .unwrap(),
        interpolate(
            &parts[..6]
                .iter()
                .map(|p| (p.node, p.value))
                .collect::<Vec<_>>(),
            6
        )
        .unwrap()
    );
    let key = VerifyingKey::from_sec1_bytes(&encode_point(G * secret()).unwrap()).unwrap();
    let mut count = 0;
    for a in 0..11 {
        for b in a + 1..12 {
            for c in b + 1..13 {
                for d in c + 1..14 {
                    for e in d + 1..15 {
                        for f in e + 1..16 {
                            let set = [parts[a], parts[b], parts[c], parts[d], parts[e], parts[f]];
                            let Combined::Ecdsa { signature, .. } = pkg.combine(&set).unwrap()
                            else {
                                panic!()
                            };
                            key.verify_prehash(&m, &signature).unwrap();
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(count, 8008);
    assert!(pkg.combine(&[parts[0]; 6]).is_err());
}

#[test]
fn sealed_ecdsa_wallet_import_and_recovery_of_nonce() {
    let k = sc("nonce-sealed");
    let nonce = G * k;
    let r = ecdsa_r(nonce).unwrap();
    let m = msg("variant-1");
    let raw_s = inverse(k).unwrap() * (reduce(&m) + r * secret());
    let Combined::Ecdsa { signature, .. } = finalize_ecdsa(nonce, raw_s).unwrap() else {
        panic!()
    };
    let mut rng = TestRng::new();
    let message = Owner::sealed_ecdsa(header(1, 1, 1), &[(m, signature)], &mut rng)
        .unwrap()
        .encrypt(sc("eph-sealed"), &keys(), &mut rng)
        .unwrap();
    let Deal::Sealed(slots) = &message.deal else {
        panic!()
    };
    let recovered = slots[0].nonce;
    assert!(recovered == nonce || recovered == -nonce);
    assert_eq!(ecdsa_r(recovered).unwrap(), r);
    assert_eq!(
        recovered * *signature.s(),
        G * reduce(&m) + G * secret() * r
    );
    assert_eq!(message.encode().unwrap().len(), 1430);
    let accepted = message.step_a(&Context::new(vec![m])).unwrap();
    let package = accepted.signing_package(1, 1, m, [0; 32]).unwrap();
    let parts: Vec<_> = shares(&accepted)
        .iter()
        .map(|s| package.partial(s).unwrap())
        .collect();
    assert!(parts.iter().all(|p| package.verify_partial(p)));
    package
        .combine(&parts[4..10])
        .unwrap()
        .verify(G * secret(), &m)
        .unwrap();
    assert!(accepted
        .signing_package(1, 1, msg("wrong"), [0; 32])
        .is_err());
}

#[test]
fn low_s_ethereum_recovery_covers_all_four_parity_flip_cases() {
    let key = VerifyingKey::from_sec1_bytes(&encode_point(G * secret()).unwrap()).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..32 {
        let k = sc(&format!("yp/case-{i}"));
        let nonce = G * k;
        let r = ecdsa_r(nonce).unwrap();
        let m = msg(&format!("case-{i}"));
        let s = inverse(k).unwrap() * (reduce(&m) + r * secret());
        seen.insert((is_odd(nonce).unwrap(), bool::from(s.is_high())));
        let Combined::Ecdsa {
            signature,
            recovery_id,
        } = finalize_ecdsa(nonce, s).unwrap()
        else {
            panic!()
        };
        assert!(!bool::from(signature.s().is_high()));
        assert_eq!(
            recovery_id.is_y_odd(),
            is_odd(nonce).unwrap() ^ bool::from(s.is_high())
        );
        assert_eq!(
            VerifyingKey::recover_from_prehash(&m, &signature, recovery_id).unwrap(),
            key
        );
        let wrong = RecoveryId::new(!recovery_id.is_y_odd(), false);
        assert_ne!(
            VerifyingKey::recover_from_prehash(&m, &signature, wrong).unwrap(),
            key
        );
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn open_bip340_two_nonces_both_parities() {
    let mut rng = TestRng::new();
    let nonces: Vec<_> = (1..=16)
        .map(|i| (sc(&format!("d/{i}")), sc(&format!("e/{i}"))))
        .collect();
    let message = Owner::open_bip340(header(2, 2, 16), secret(), &nonces, &mut rng)
        .unwrap()
        .encrypt(sc("eph-bip"), &keys(), &mut rng)
        .unwrap();
    assert_eq!(
        OwnerMessage::decode(&message.encode().unwrap()).unwrap(),
        message
    );
    let accepted = message.step_a(&Context::new(vec![])).unwrap();
    let shares = shares(&accepted);
    let key = k256::schnorr::VerifyingKey::from_bytes(&x_bytes(G * normalized_secret()).unwrap())
        .unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for slot in 1..=16 {
        let m = msg(&format!("bip/{slot}"));
        let dg = msg(&format!("digest/{slot}"));
        let package = accepted.signing_package(slot, 1, m, dg).unwrap();
        seen.insert(package.nonce_negated);
        let parts: Vec<_> = shares.iter().map(|s| package.partial(s).unwrap()).collect();
        assert!(parts.iter().all(|p| package.verify_partial(p)));
        let mut bad = parts[0];
        bad.value += Scalar::ONE;
        assert!(!package.verify_partial(&bad));
        let Combined::Bip340(signature) = package.combine(&parts[8..14]).unwrap() else {
            panic!()
        };
        key.verify_raw(&m, &signature).unwrap();
        let changed = accepted
            .signing_package(slot, 1, m, msg("other-lock"))
            .unwrap();
        assert!(!changed.verify_partial(&parts[0]));
    }
    assert_eq!(seen.len(), 2);
}

#[test]
fn sealed_bip340_wallet_import_both_raw_nonce_parities() {
    let mut rng = TestRng::new();
    let mut signatures = Vec::new();
    let mut messages = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..16 {
        let k = sc(&format!("sealed-bip/{i}"));
        let odd = is_odd(G * k).unwrap();
        seen.insert(odd);
        let k = if odd { -k } else { k };
        let nonce = G * k;
        let m = msg(&format!("variant/{i}"));
        let c = bip340_challenge(
            &x_bytes(nonce).unwrap(),
            &x_bytes(G * normalized_secret()).unwrap(),
            &m,
        );
        let s = k + c * normalized_secret();
        let bytes = [&x_bytes(nonce).unwrap()[..], &s.to_bytes()].concat();
        let signature = k256::schnorr::Signature::try_from(bytes.as_slice()).unwrap();
        signatures.push((m, signature));
        messages.push(m);
    }
    assert_eq!(seen.len(), 2);
    let message = Owner::sealed_bip340(header(2, 1, 16), &signatures, &mut rng)
        .unwrap()
        .encrypt(sc("sealed-bip-eph"), &keys(), &mut rng)
        .unwrap();
    assert_eq!(
        OwnerMessage::decode(&message.encode().unwrap()).unwrap(),
        message
    );
    let accepted = message.step_a(&Context::new(messages.clone())).unwrap();
    let shares = shares(&accepted);
    for (i, m) in messages.iter().enumerate() {
        let package = accepted
            .signing_package(i as u16 + 1, 1, *m, [0; 32])
            .unwrap();
        let parts: Vec<_> = shares.iter().map(|s| package.partial(s).unwrap()).collect();
        assert!(parts.iter().all(|p| package.verify_partial(p)));
        let Combined::Bip340(signature) = package.combine(&parts[..6]).unwrap() else {
            panic!()
        };
        k256::schnorr::VerifyingKey::from_bytes(&x_bytes(G * normalized_secret()).unwrap())
            .unwrap()
            .verify_raw(m, &signature)
            .unwrap();
    }
}

#[test]
fn shared_pad_attack_recovers_key_but_component_labels_stop_it() {
    let (message, accepted) = open_ecdsa();
    let node_shares = shares(&accepted);
    let m = msg("tx-A");
    let k = sc("nonce-1");
    let r = ecdsa_r(G * k).unwrap();
    let h = reduce(&m);
    let s = inverse(k).unwrap() * (h + r * secret());
    // Test-only vulnerable encoder deliberately gives w and mu the same pad.
    let one_pad = line_dealing::hash::SlotLabel::new(2, 2, 1, 1).unwrap();
    let vulnerable: Vec<_> = node_shares
        .iter()
        .map(|sh| {
            let i = sh.node();
            let pk = G * node_secret(i);
            let pad =
                share_pad(&message.hd().unwrap(), i, pk, pk * sc("eph"), one_pad, None).unwrap();
            (i, [sh.values()[0] + pad, sh.values()[1] + pad])
        })
        .collect();
    let recover = |delta: Scalar| {
        let w = (s - r * delta) * inverse(h + r).unwrap();
        Scalar::ONE + delta * inverse(w).unwrap()
    };
    let delta = interpolate(
        &vulnerable[..6]
            .iter()
            .map(|(i, ct)| (*i, ct[1] - ct[0]))
            .collect::<Vec<_>>(),
        6,
    )
    .unwrap();
    assert_eq!(recover(delta), secret());
    let fixed_delta = interpolate(
        &message.ciphertexts[..6]
            .iter()
            .enumerate()
            .map(|(i, ct)| (i as u16 + 1, ct[1] - ct[0]))
            .collect::<Vec<_>>(),
        6,
    )
    .unwrap();
    assert_ne!(recover(fixed_delta), secret());
    assert_ne!(G * recover(fixed_delta), G * secret());
}

#[test]
fn two_signatures_on_one_open_ecdsa_slot_recover_key() {
    let (_, accepted) = open_ecdsa();
    let shares = shares(&accepted);
    let mut signatures = Vec::new();
    for name in ["tx-A", "tx-B"] {
        let m = msg(name);
        let package = accepted.signing_package(1, 1, m, msg(name)).unwrap();
        let parts: Vec<_> = shares[..6]
            .iter()
            .map(|sh| package.partial(sh).unwrap())
            .collect();
        let combined = package.combine(&parts).unwrap();
        combined.verify(G * secret(), &m).unwrap();
        let Combined::Ecdsa { signature, .. } = combined else {
            panic!()
        };
        signatures.push((reduce(&m), *signature.s()));
    }
    let [(h1, s1), (h2, s2)] = signatures.as_slice() else {
        panic!()
    };
    let r = ecdsa_r(G * sc("nonce-1")).unwrap();
    // Only the two low-s signatures, their hashes, and public X are needed.
    // Enumerate the signs hidden by low-s normalization.
    let mut recovered = false;
    for a in [*s1, -*s1] {
        for b in [*s2, -*s2] {
            if let Ok(inv) = inverse(a - b) {
                let k = (h1 - h2) * inv;
                let x = (a * k - h1) * inverse(r).unwrap();
                if G * x == G * secret() {
                    assert_eq!(x, secret());
                    recovered = true;
                }
            }
        }
    }
    assert!(recovered);
}

#[test]
fn step_a_rejects_zero_constant_odd_bip340_and_repeated_nonces() {
    let m = msg("zero");
    let r = ecdsa_r(G).unwrap();
    let x = -reduce(&m) * inverse(r).unwrap();
    let mut h = header(1, 1, 1);
    h.public_key = G * x;
    let deal = Deal::Sealed(vec![SealedPoint {
        nonce: G,
        commitments: vec![G; 5],
    }]);
    assert!(deal.public_polynomials(&h, &[m]).is_err());
    let odd = (1..100)
        .map(|i| G * Scalar::from(i as u64))
        .find(|p| is_odd(*p).unwrap())
        .unwrap();
    let bad = Deal::Sealed(vec![SealedPoint {
        nonce: odd,
        commitments: vec![G; 5],
    }]);
    assert!(bad.public_polynomials(&header(2, 1, 1), &[m]).is_err());
    // An x-only wire nonce lifts to even y: odd-y shares fail the private check.
    let k = (1..100)
        .map(|i| Scalar::from(i as u64))
        .find(|k| G * k == odd)
        .unwrap();
    let c = bip340_challenge(
        &x_bytes(odd).unwrap(),
        &x_bytes(G * normalized_secret()).unwrap(),
        &m,
    );
    let wrong_s = k + c * normalized_secret();
    let good_nonce = lift_x(&x_bytes(odd).unwrap()).unwrap();
    let mut rng = TestRng::new();
    let p = Polynomial::random(wrong_s, 6, &mut rng).unwrap();
    let encoded = Deal::Sealed(vec![SealedPoint {
        nonce: good_nonce,
        commitments: p.commit(G).unwrap().coefficients,
    }]);
    let cmt = encoded.public_polynomials(&header(2, 1, 1), &[m]).unwrap();
    assert!(!cmt[0].verify(1, p.evaluate(1).unwrap()));
    assert!(Owner::open_ecdsa(header(1, 2, 2), secret(), &[sc("same"); 2], &mut rng).is_err());
    assert!(Owner::open_bip340(
        header(2, 2, 1),
        secret(),
        &[(sc("same"), -sc("same"))],
        &mut rng
    )
    .is_err());
}

#[test]
fn changed_header_breaks_proof_and_decryption() {
    let (message, accepted) = open_ecdsa();
    let mut changed = message.clone();
    changed.header.owner_nonce[0] ^= 1;
    assert!(matches!(
        changed.step_a(&Context::new(vec![])),
        Err(Error::Proof)
    ));
    let label = SlotLabel::new(2, 2, 1, 1).unwrap();
    let pk = G * node_secret(1);
    let wrong = changed.ciphertexts[0][0]
        - share_pad(
            &changed.hd().unwrap(),
            1,
            pk,
            message.header.ephemeral * node_secret(1),
            label,
            None,
        )
        .unwrap();
    assert!(!accepted.polynomials()[0].verify(1, wrong));
    let mut changed = message.clone();
    changed.ciphertexts[0][0] += Scalar::ONE;
    assert!(matches!(
        changed.step_a(&Context::new(vec![])),
        Err(Error::Proof)
    ));
    let mut changed = message.clone();
    changed.proof.z_a += Scalar::ONE;
    assert!(changed.step_a(&Context::new(vec![])).is_err());
    assert!(accepted.decrypt(1, node_secret(2)).is_err());
}

#[test]
fn canonical_wire_header_context_and_address_checks() {
    let (message, _) = open_ecdsa();
    let mut bytes = message.encode().unwrap();
    bytes.push(0);
    assert!(OwnerMessage::decode(&bytes).is_err());
    bytes.pop();
    for len in [0, 1, 100, 523, bytes.len() - 1] {
        assert!(OwnerMessage::decode(&bytes[..len]).is_err());
    }
    let mut malformed = bytes.clone();
    malformed[0] = 2;
    assert!(OwnerMessage::decode(&malformed).is_err());
    let mut malformed = bytes.clone();
    malformed[166] = 4;
    assert!(OwnerMessage::decode(&malformed).is_err());
    let mut malformed = bytes.clone();
    malformed[267] = 1;
    assert!(OwnerMessage::decode(&malformed).is_err());
    let mut changed = message.clone();
    changed.header.address[0] ^= 1;
    assert!(changed.step_a(&Context::new(vec![])).is_err());
    let mut changed = message.clone();
    changed.header.epoch += 1;
    assert!(changed.step_a(&Context::new(vec![])).is_err());
    let mut changed = message.clone();
    changed.header.threshold = 11;
    assert!(changed.header.validate().is_err());
    let mut context = Context::new(vec![]);
    context.bound = true;
    assert!(message.step_a(&context).is_err());
    for kind in [1, 2, 3, 5] {
        let address = address_for(kind, G * secret()).unwrap();
        assert_eq!(address.len(), 20);
    }
    assert_ne!(address_for(1, G).unwrap(), address_for(2, G).unwrap());
    assert_eq!(address_for(1, G).unwrap(), address_for(3, G).unwrap());
    assert_eq!(
        address_for(5, G).unwrap(),
        [
            0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2,
            0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf
        ]
    );
}

#[test]
fn identity_rules_and_lock_digest_binding() {
    let (message, _) = open_ecdsa();
    let mut changed = message.clone();
    changed.ciphertexts[0][0] += Scalar::ONE;
    assert_eq!(message.rid().unwrap(), changed.rid().unwrap());
    assert_ne!(message.mid().unwrap(), changed.mid().unwrap());
    changed.header.epoch += 1;
    assert_eq!(message.rid().unwrap(), changed.rid().unwrap());
    changed.header.owner_nonce[0] ^= 1;
    assert_ne!(message.rid().unwrap(), changed.rid().unwrap());
    let hashes = [msg("m")];
    let mut lock = LockDigest {
        rid: message.rid().unwrap(),
        epoch: 7,
        generation: 1,
        attempt: 1,
        anchor_height: 42,
        anchor_hash: [6; 32],
        transaction: b"tx",
        sighashes: &hashes,
    };
    let original = lock.hash().unwrap();
    lock.transaction = b"changed";
    assert_ne!(original, lock.hash().unwrap());
    let mut rng = TestRng::new();
    let m = msg("sealed");
    let k = sc("sealed");
    let s = inverse(k).unwrap() * (reduce(&m) + ecdsa_r(G * k).unwrap() * secret());
    let Combined::Ecdsa { signature, .. } = finalize_ecdsa(G * k, s).unwrap() else {
        panic!()
    };
    let sealed = Owner::sealed_ecdsa(header(1, 1, 1), &[(m, signature)], &mut rng)
        .unwrap()
        .encrypt(sc("eph"), &keys(), &mut rng)
        .unwrap();
    let mut changed = sealed.clone();
    changed.header.epoch += 1;
    assert_ne!(sealed.rid().unwrap(), changed.rid().unwrap());
}

#[test]
fn all_payment_can_retain_change_destination_in_header() {
    let mut h = header(1, 2, 1);
    h.intent.outputs[0].amount = u128::MAX;
    assert!(h.validate().is_ok());
}

#[test]
fn header_state_checks_and_ecdsa_overflow_nonce() {
    let h = header(1, 2, 1);
    let context = Context::new(vec![]);
    let state = context.committee();
    state.check_header(&h).unwrap();
    for mutate in 0..8 {
        let mut changed = state;
        match mutate {
            0 => changed.chain_id[0] ^= 1,
            1 => changed.board_id[0] ^= 1,
            2 => changed.epoch += 1,
            3 => changed.keylist_hash[0] ^= 1,
            4 => changed.n += 1,
            5 => changed.f += 1,
            6 => changed.board_height = h.expires + 1,
            _ => changed.grace_end = h.expires - 1,
        }
        let mut candidate = h.clone();
        if mutate == 7 {
            candidate.on_rotation = 1;
        }
        assert!(changed.check_header(&candidate).is_err());
    }
    let mut q = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let mut checked = false;
    for low in 0x41..0x80 {
        q[31] = low;
        if let Ok(nonce) = lift_x(&q) {
            assert!(ecdsa_r(nonce).is_err());
            checked = true;
            break;
        }
    }
    assert!(checked);
    assert!(finalize_ecdsa(G, Scalar::ZERO).is_err());
}

#[test]
fn malformed_deal_threshold_is_an_error() {
    let mut hdr = header(1, 2, 1);
    hdr.threshold = 0;
    let deal = Deal::OpenEcdsa(vec![]);
    assert!(deal.encode(&hdr).is_err());
}

#[test]
fn sealed_ecdsa_accepts_high_s_wallet_signature() {
    let k = sc("wallet-high");
    let m = msg("wallet-high");
    let r = ecdsa_r(G * k).unwrap();
    let raw = inverse(k).unwrap() * (reduce(&m) + r * secret());
    let high_s = if bool::from(raw.is_high()) { raw } else { -raw };
    let signature = k256::ecdsa::Signature::from_scalars(r.to_bytes(), high_s.to_bytes()).unwrap();
    let mut rng = TestRng::new();
    let message = Owner::sealed_ecdsa(header(1, 1, 1), &[(m, signature)], &mut rng)
        .unwrap()
        .encrypt(sc("eph-high"), &keys(), &mut rng)
        .unwrap();
    let accepted = message.step_a(&Context::new(vec![m])).unwrap();
    let package = accepted.signing_package(1, 1, m, [0; 32]).unwrap();
    let parts: Vec<_> = shares(&accepted)[..6]
        .iter()
        .map(|s| package.partial(s).unwrap())
        .collect();
    let Combined::Ecdsa { signature, .. } = package.combine(&parts).unwrap() else {
        panic!()
    };
    assert!(!bool::from(signature.s().is_high()));
}

#[test]
fn multiple_generations_inputs_and_t2_profile() {
    let mut hdr = header(1, 2, 2);
    hdr.inputs = 2;
    hdr.threshold = 11;
    hdr.on_rotation = 1;
    let mut rng = TestRng::new();
    let nonces: Vec<_> = (1..=4).map(|i| sc(&format!("t2/{i}"))).collect();
    let message = Owner::open_ecdsa(hdr, secret(), &nonces, &mut rng)
        .unwrap()
        .encrypt(sc("t2-eph"), &keys(), &mut rng)
        .unwrap();
    let labels = message.deal.labels(&message.header).unwrap();
    assert_eq!(labels[6].bytes(), [2, 2, 0, 2, 0, 2, 0, 0]);
    let accepted = message.step_a(&Context::new(vec![])).unwrap();
    let shares = shares(&accepted);
    for generation in 1..=2 {
        for input in 1..=2 {
            let m = msg(&format!("t2/{generation}/{input}"));
            let package = accepted
                .signing_package(generation, input, m, [8; 32])
                .unwrap();
            let parts: Vec<_> = shares.iter().map(|s| package.partial(s).unwrap()).collect();
            assert!(package.combine(&parts[..10]).is_err());
            package
                .combine(&parts[5..16])
                .unwrap()
                .verify(G * secret(), &m)
                .unwrap();
            assert!(package
                .with_resharing(16, 6, accepted.polynomials())
                .is_err());
        }
    }
}

#[test]
fn wire_rejects_noncanonical_ciphertext_and_identity_commitment() {
    let (message, _) = open_ecdsa();
    let bytes = message.encode().unwrap();
    let mut bad = bytes.clone();
    let ct = message.header.encode().unwrap().len()
        + message.deal.encode(&message.header).unwrap().len();
    bad[ct..ct + 32].fill(255);
    assert!(OwnerMessage::decode(&bad).is_err());
    let mut bad = bytes;
    let first_commitment = message.header.encode().unwrap().len() + 33;
    bad[first_commitment..first_commitment + 33].fill(0);
    assert!(OwnerMessage::decode(&bad).is_err());
}
