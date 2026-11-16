mod common;
use common::{sc, TestRng, G};
use k256::Scalar;
use line_dealing::{
    algebra::encode_point,
    experiment::{EdSetup, SecpSetup, SeededRng},
    hash::{ciphertext_digest, h, hg, hq, ReshareDomain},
    message::AuthProof,
};

#[test]
fn proof_transcripts_match_section_3_1_and_reject_every_changed_field() {
    let hd = [1; 32];
    let ct = [2; 64];
    let e = sc("e");
    let x = sc("x");
    let domain = ReshareDomain {
        rid: [3; 32],
        old_epoch: 1,
        new_epoch: 2,
        dealer: 4,
    };
    for domain in [None, Some(domain)] {
        let proof = AuthProof::create(&hd, &ct, e, x, G, domain, &mut TestRng::new()).unwrap();
        assert_eq!(proof.encode().unwrap().len(), 196);
        let prefix = domain.map_or_else(Vec::new, |d| d.prefix());
        let label = if domain.is_some() { "LD1/rs-" } else { "LD1/" };
        let ct_hash = h(&format!("{label}ct"), &[prefix.as_slice(), &ct].concat());
        assert_eq!(ciphertext_digest(&ct, domain), ct_hash);
        let eph = [
            prefix.as_slice(),
            &hd,
            &ct_hash,
            &encode_point(G * e).unwrap(),
        ]
        .concat();
        let gp = hg(&format!("{label}eph"), &eph).unwrap();
        assert_eq!(proof.e_prime, gp * e);
        let ce = hq(
            &format!("{label}ephpok"),
            &[
                eph.as_slice(),
                &encode_point(proof.e_prime).unwrap(),
                &encode_point(proof.t_1).unwrap(),
                &encode_point(proof.t_2).unwrap(),
            ]
            .concat(),
        );
        let ca = hq(
            &format!("{label}auth"),
            &[
                prefix.as_slice(),
                &hd,
                &ct_hash,
                &encode_point(proof.e_prime).unwrap(),
                &encode_point(proof.t_1).unwrap(),
                &encode_point(proof.t_2).unwrap(),
                &proof.z_e.to_bytes(),
                &encode_point(proof.t_a).unwrap(),
            ]
            .concat(),
        );
        assert_eq!(G * proof.z_e, proof.t_1 + G * e * ce);
        assert_eq!(gp * proof.z_e, proof.t_2 + proof.e_prime * ce);
        assert_eq!(G * proof.z_a, proof.t_a + G * x * ca);
        for field in 0..6 {
            let mut bad = proof.clone();
            match field {
                0 => bad.e_prime += G,
                1 => bad.t_1 += G,
                2 => bad.t_2 += G,
                3 => bad.z_e += Scalar::ONE,
                4 => bad.t_a += G,
                _ => bad.z_a += Scalar::ONE,
            }
            assert!(bad.verify(&hd, &ct, G * e, G, G * x, domain).is_err());
        }
        assert!(proof
            .verify(&[9; 32], &ct, G * e, G, G * x, domain)
            .is_err());
        assert!(proof
            .verify(&hd, &[3; 64], G * e, G, G * x, domain)
            .is_err());
        assert!(proof
            .verify(&hd, &ct, G * (e + Scalar::ONE), G, G * x, domain)
            .is_err());
        assert!(proof
            .verify(
                &hd,
                &ct,
                G * e,
                G,
                G * x,
                if domain.is_some() {
                    None
                } else {
                    Some(ReshareDomain {
                        rid: [3; 32],
                        old_epoch: 1,
                        new_epoch: 2,
                        dealer: 4,
                    })
                }
            )
            .is_err());
        if let Some(mut changed) = domain {
            changed.dealer += 1;
            assert!(proof
                .verify(&hd, &ct, G * e, G, G * x, Some(changed))
                .is_err());
        }
    }
}

#[test]
fn secp_hash_to_curve_matches_rfc_9380_empty_message_vector() {
    let point = hg("QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_", b"").unwrap();
    let encoded = encode_point(point).unwrap();
    let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "03c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346"
    );
    assert_ne!(
        hg("LD1/eph", b"message").unwrap(),
        hg("LD1/rs-eph", b"message").unwrap()
    );
}

#[test]
fn section_7_sizes_for_all_suites_and_profiles() {
    for n in [16, 64, 256] {
        let f = (n - 1) / 3;
        for t in [f + 1, n - f] {
            let p = usize::from(33 * (t - 1) + 32 * n);
            for suite in 1..=3 {
                for sealed in [false, true] {
                    let mut rng = SeededRng::new(17);
                    let (len, header, proof) = if suite == 3 {
                        let setup = EdSetup::new(n, t, sealed, 17).unwrap();
                        let msg = setup.owner_message(&mut rng).unwrap();
                        (
                            msg.encode().unwrap().len(),
                            msg.header.encode().unwrap().len(),
                            msg.proof.encode().unwrap().len(),
                        )
                    } else {
                        let setup = SecpSetup::new(n, t, suite, sealed, 17).unwrap();
                        let msg = setup.owner_message(&mut rng).unwrap();
                        (
                            msg.encode().unwrap().len(),
                            msg.header.encode().unwrap().len(),
                            msg.proof.encode().unwrap().len(),
                        )
                    };
                    // Sealed Schnorr transmits 32-byte nonces (§3.2); the §7 table
                    // uses the conservative 33-byte point convention for all suites.
                    let deal = if sealed {
                        8 * (p + if suite == 1 { 33 } else { 32 })
                    } else if suite == 1 {
                        33 + 2 * p
                    } else {
                        66 + 3 * p
                    };
                    assert_eq!(header, 524);
                    assert_eq!(proof, 196);
                    assert_eq!(len, 720 + deal);
                    assert_eq!(len - (654 + deal), 66);
                }
            }
        }
    }
}

#[test]
fn complaint_requires_authenticated_bad_delivery() {
    let setup = SecpSetup::new(9, 3, 1, false, 17).unwrap();
    let mut rng = SeededRng::new(17);
    let mut msg = setup.owner_message(&mut rng).unwrap();
    assert!(msg
        .step_a(&setup)
        .unwrap()
        .complain(1, setup.secrets[0], &mut rng)
        .is_err());
    msg.ciphertexts[0][0] += Scalar::ONE;
    assert!(msg.step_a(&setup).is_err());
    // Owner keys in this fixture are private; the public test fixture exposes them.
    let (mut msg, _) = common::open_ecdsa();
    msg.ciphertexts[0][0] += Scalar::ONE;
    let ct: Vec<_> = msg
        .ciphertexts
        .iter()
        .flatten()
        .flat_map(|s| s.to_bytes())
        .collect();
    msg.proof = AuthProof::create(
        &msg.hd().unwrap(),
        &ct,
        common::sc("eph"),
        common::secret(),
        G,
        None,
        &mut rng,
    )
    .unwrap();
    assert_eq!(msg.header.ephemeral, G * common::sc("eph"));
    {
        let accepted = msg.step_a(&common::Context::new(vec![])).unwrap();
        let complaint = accepted
            .complain(1, common::node_secret(1), &mut rng)
            .unwrap();
        accepted.verify_complaint(&complaint).unwrap();
    }
}
