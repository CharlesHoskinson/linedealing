mod common;
use common::TestRng;
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT as G, EIGHT_TORSION},
    edwards::EdwardsPoint,
    scalar::Scalar,
    traits::Identity,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::RngCore;
use line_dealing::{
    ed25519::*,
    message::CommitteeState,
    wire::{Intent, Output},
    Error, Result,
};
use sha2::{Digest, Sha256, Sha512};

const SEED: [u8; 32] = [42; 32];
fn sc(label: &str) -> Scalar {
    hq("test/ed25519", label.as_bytes())
}
fn node_secret(node: u16) -> Scalar {
    sc(&format!("node/{node}"))
}
fn header(mode: u8, slots: u16) -> Header {
    let public_key = G * secret_from_seed(&SEED);
    let mut pin = [0; 72];
    pin[0] = 3;
    Header {
        version: 1,
        suite: 3,
        mode,
        addr_type: 6,
        on_rotation: 1,
        late_inputs: 0,
        chain_id: [1; 32],
        board_id: [2; 32],
        owner_nonce: [3; 32],
        keylist_hash: [4; 32],
        builder_hash: [5; 32],
        public_key,
        ephemeral: G,
        address: public_key.compress().to_bytes().to_vec(),
        epoch: 7,
        not_before: 10,
        expires: 100,
        n: 4,
        threshold: 2,
        f: 1,
        variants: if mode == 1 { slots } else { 0 },
        inputs: 1,
        generations: if mode == 2 { slots } else { 0 },
        trigger_id: 0,
        trigger_params: [0; 32],
        intent: Intent {
            outputs: vec![Output {
                script: vec![6; 32],
                amount: 100,
            }],
            change_to: vec![7; 32],
            pin,
            allowed: vec![],
            fee_ceiling: 1000,
            fee_rule: 0,
            bump_delay: 6,
            grid_ratio: [2, 1],
            min_conf: 6,
        },
    }
}
struct Context {
    keys: Vec<EdwardsPoint>,
    messages: Vec<Vec<u8>>,
    bound: bool,
}
impl Context {
    fn new(messages: Vec<Vec<u8>>) -> Self {
        Self {
            keys: (1..=4).map(|i| G * node_secret(i)).collect(),
            messages,
            bound: false,
        }
    }
}
impl AcceptanceContext for Context {
    fn committee(&self) -> CommitteeState {
        CommitteeState {
            chain_id: [1; 32],
            board_id: [2; 32],
            epoch: 7,
            keylist_hash: [4; 32],
            n: 4,
            f: 1,
            board_height: 20,
            grace_end: 200,
        }
    }
    fn check_header(&self, header: &Header) -> Result<()> {
        if header.builder_hash == [5; 32] {
            Ok(())
        } else {
            Err(Error::Context)
        }
    }
    fn is_bound_or_tombstoned(&self, _: &[u8; 32]) -> bool {
        self.bound
    }
    fn sealed_messages(&self, _: &Header) -> Result<Vec<Vec<u8>>> {
        Ok(self.messages.clone())
    }
    fn node_keys(&self) -> &[EdwardsPoint] {
        &self.keys
    }
}
fn open(slots: u16) -> (OwnerMessage, Context) {
    let mut rng = TestRng::new();
    let context = Context::new(vec![]);
    let nonces = (1..=slots)
        .map(|i| (sc(&format!("d/{i}")), sc(&format!("e/{i}"))))
        .collect::<Vec<_>>();
    let message = Owner::open(header(2, slots), SEED, &nonces, &mut rng)
        .unwrap()
        .encrypt(sc("ephemeral"), &context.keys, &mut rng)
        .unwrap();
    (message, context)
}
fn sealed(slots: u16) -> (OwnerMessage, Context, Vec<ed25519_dalek::Signature>) {
    let mut rng = TestRng::new();
    let wallet = SigningKey::from_bytes(&SEED);
    let messages = (1..=slots)
        .map(|i| format!("sealed variant {i}, arbitrary message length").into_bytes())
        .collect::<Vec<_>>();
    let signatures = messages.iter().map(|m| wallet.sign(m)).collect::<Vec<_>>();
    let imported = messages
        .iter()
        .cloned()
        .zip(signatures.iter().copied())
        .collect::<Vec<_>>();
    let context = Context::new(messages);
    let message = Owner::sealed(header(1, slots), &imported, &mut rng)
        .unwrap()
        .encrypt(sc("ephemeral"), &context.keys, &mut rng)
        .unwrap();
    (message, context, signatures)
}

#[test]
fn seed_expansion_and_protocol_scalar_encoding() {
    assert_eq!(
        (G * secret_from_seed(&SEED)).compress().to_bytes(),
        SigningKey::from_bytes(&SEED).verifying_key().to_bytes()
    );
    let encoded = encode_scalar(Scalar::from(257u64));
    assert_eq!(encoded[30..], [1, 1]);
    assert_eq!(decode_scalar(&encoded).unwrap(), Scalar::from(257u64));
    assert_eq!(decode_scalar(&[255; 32]), Err(Error::Scalar));
    let tag = Sha256::digest(b"test/hq");
    let mut hash = Sha512::new();
    hash.update(tag);
    hash.update(tag);
    hash.update(b"message");
    let scalar = hash.finalize().iter().fold(Scalar::ZERO, |acc, b| {
        acc * Scalar::from(256u64) + Scalar::from(*b as u64)
    });
    assert_eq!(hq("test/hq", b"message"), scalar);
}

#[test]
fn auth_proof_supports_generator_and_arbitrary_public_bases() {
    let hd = [17; 32];
    let ct = b"public ciphertext";
    let ephemeral = sc("proof ephemeral");
    let witness = sc("proof witness");
    for base in [G, G * sc("arbitrary proof base")] {
        let mut rng = TestRng::new();
        let proof = AuthProof::create(&hd, ct, ephemeral, witness, base, None, &mut rng).unwrap();
        // Replay the two nonce draws to compare the generic multiplication formula.
        let mut nonce_rng = TestRng::new();
        let _a = random_nonzero(&mut nonce_rng);
        let b = random_nonzero(&mut nonce_rng);
        assert_eq!(proof.t_a, base * b);
        proof
            .verify(&hd, ct, G * ephemeral, base, base * witness, None)
            .unwrap();
        assert_eq!(
            proof.verify(
                &hd,
                ct,
                G * ephemeral,
                base,
                base * (witness + Scalar::ONE),
                None
            ),
            Err(Error::Proof)
        );
    }
}

#[test]
fn decoded_dh_proof_uses_original_wire_and_invalidates_on_mutation() {
    let mid = [23; 32];
    let secret = sc("DH proof secret");
    let pk = G * secret;
    let ephemeral = G * sc("DH proof ephemeral");
    let proof = DhProof::create(&mid, pk, ephemeral, secret, &mut TestRng::new()).unwrap();
    let bytes = proof.encode().unwrap();
    let decoded = DhProof::decode(&bytes).unwrap();
    assert_eq!(decoded.encode().unwrap(), bytes);
    decoded.verify(&mid, pk, ephemeral).unwrap();
    let challenge = hq(
        "LD1/dleq",
        &[
            encode_point(G).unwrap().as_slice(),
            &encode_point(pk).unwrap(),
            &encode_point(ephemeral).unwrap(),
            &bytes[..99],
            &mid,
        ]
        .concat(),
    );
    assert_eq!(G * decoded.z, decoded.t_1 + pk * challenge);
    assert_eq!(ephemeral * decoded.z, decoded.t_2 + decoded.key * challenge);
    for point in [
        EdwardsPoint::identity(),
        EIGHT_TORSION[1],
        G + EIGHT_TORSION[1],
    ] {
        for field in 0..3 {
            let mut changed = decoded.clone();
            match field {
                0 => changed.key = point,
                1 => changed.t_1 = point,
                _ => changed.t_2 = point,
            }
            assert_eq!(changed.encode().err(), Some(Error::Point));
            assert_eq!(changed.verify(&mid, pk, ephemeral), Err(Error::Point));
        }
    }
    for field in 0..4 {
        let mut changed = decoded.clone();
        match field {
            0 => changed.key += G,
            1 => changed.t_1 += G,
            2 => changed.t_2 += G,
            _ => changed.z += Scalar::ONE,
        }
        assert_ne!(changed.encode().unwrap(), bytes);
        assert_eq!(changed.verify(&mid, pk, ephemeral), Err(Error::Proof));
    }
    assert_eq!(
        decoded.verify(&mid, G + EIGHT_TORSION[1], ephemeral),
        Err(Error::Point)
    );
    assert_eq!(
        decoded.verify(&mid, pk, EIGHT_TORSION[1]),
        Err(Error::Point)
    );
}

#[test]
fn wide_big_endian_reduction_matches_bytewise_at_boundaries_and_random_lengths() {
    let mut rng = TestRng::new();
    let mut lengths = vec![
        0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 255, 256, 257, 1024,
    ];
    lengths.extend((0..64).map(|_| (rng.next_u32() % 1100) as usize));
    for length in lengths {
        let mut bytes = vec![0; length];
        rng.fill_bytes(&mut bytes);
        for candidate in [bytes.clone(), vec![0; length], vec![255; length]] {
            let old = candidate.iter().fold(Scalar::ZERO, |value, byte| {
                value * Scalar::from(256u64) + Scalar::from(u64::from(*byte))
            });
            assert_eq!(reduce(&candidate), old, "length {length}");
        }
    }
    let mut order = [0; 32];
    order[..8].copy_from_slice(&[0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58]);
    order[8..16].copy_from_slice(&[0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14]);
    order[31] = 0x10;
    order.reverse();
    assert_eq!(reduce(&order), Scalar::ZERO);
    order[31] -= 1;
    assert_eq!(reduce(&order), -Scalar::ONE);
    order[31] += 2;
    assert_eq!(reduce(&order), Scalar::ONE);
}

#[test]
fn small_node_horner_matches_full_width_scalar_evaluation() {
    let mut rng = TestRng::new();
    for degree in [0, 1, 2, 4, 8, 16] {
        let commitment = Commitment {
            constant: EdwardsPoint::mul_base(&random_nonzero(&mut rng)),
            coefficients: (0..degree)
                .map(|_| EdwardsPoint::mul_base(&random_nonzero(&mut rng)))
                .collect(),
        };
        let mut nodes = vec![1, 2, 3, 127, 128, 255, 256, 32767, 32768, u16::MAX];
        nodes.extend((0..20).map(|_| (rng.next_u32() as u16).max(1)));
        for node in nodes {
            let x = Scalar::from(u64::from(node));
            let old = commitment
                .coefficients
                .iter()
                .rev()
                .fold(EdwardsPoint::identity(), |sum, point| (sum + point) * x)
                + commitment.constant;
            assert_eq!(commitment.evaluate(node).unwrap(), old);
        }
        assert_eq!(commitment.evaluate(0), Err(Error::Parameters));
    }
}

#[test]
fn decoded_wire_cache_preserves_hashes_and_invalidates_after_public_mutation() {
    let (original, context) = open(2);
    let bytes = original.encode().unwrap();
    let decoded = OwnerMessage::decode(&bytes).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(decoded.hd().unwrap(), original.hd().unwrap());
    assert_eq!(decoded.rid().unwrap(), original.rid().unwrap());
    assert_eq!(decoded.mid().unwrap(), original.mid().unwrap());
    decoded.step_a(&context).unwrap();
    let mut changed = decoded.clone();
    changed.header.owner_nonce[0] ^= 1;
    assert_ne!(changed.hd().unwrap(), decoded.hd().unwrap());
    assert_ne!(changed.rid().unwrap(), decoded.rid().unwrap());
    assert_ne!(changed.mid().unwrap(), decoded.mid().unwrap());
    let mut changed = decoded.clone();
    changed.ciphertexts[0][0] += Scalar::ONE;
    assert_ne!(changed.mid().unwrap(), decoded.mid().unwrap());
    assert!(changed.step_a(&context).is_err());
    let mut changed = decoded.clone();
    changed.proof.z_a += Scalar::ONE;
    assert_ne!(changed.mid().unwrap(), decoded.mid().unwrap());
    assert!(changed.step_a(&context).is_err());
    for invalid in [
        EdwardsPoint::identity(),
        EIGHT_TORSION[1],
        G + EIGHT_TORSION[1],
    ] {
        let mut changed = decoded.clone();
        changed.header.public_key = invalid;
        assert!(changed.encode().is_err());
        assert!(changed.hd().is_err());
        assert!(changed.step_a(&context).is_err());
        let mut changed = decoded.clone();
        changed.proof.t_1 = invalid;
        assert!(changed.encode().is_err());
        assert!(changed.step_a(&context).is_err());
        let mut changed = decoded.clone();
        if let Deal::Open { slots, .. } = &mut changed.deal {
            slots[0].d = invalid;
        }
        assert!(changed.encode().is_err());
        assert!(changed.hd().is_err());
        assert!(changed.step_a(&context).is_err());
    }
}

#[test]
fn open_multigeneration_all_partials_and_strict_ed25519() {
    let (message, context) = open(3);
    let accepted = message.step_a(&context).unwrap();
    let shares = (1..=4)
        .map(|i| accepted.decrypt(i, node_secret(i)).unwrap())
        .collect::<Vec<_>>();
    for generation in 1..=3 {
        let m = format!("open transaction generation {generation}");
        let package = accepted
            .signing_package(generation, 1, m.as_bytes(), [generation as u8; 32])
            .unwrap();
        let partials = shares
            .iter()
            .map(|share| package.partial(share).unwrap())
            .collect::<Vec<_>>();
        assert!(partials.iter().all(|p| package.verify_partial(p)));
        let signature = package.combine(&[partials[1], partials[3]]).unwrap();
        VerifyingKey::from_bytes(&message.header.public_key.compress().to_bytes())
            .unwrap()
            .verify_strict(m.as_bytes(), &signature.0)
            .unwrap();
        signature
            .verify(message.header.public_key, m.as_bytes())
            .unwrap();
        assert!(signature
            .verify(message.header.public_key, b"changed")
            .is_err());
        assert_eq!(
            package.combine(&partials[..1]).err(),
            Some(Error::Threshold)
        );
        assert_eq!(
            package.combine(&[partials[0], partials[0]]).err(),
            Some(Error::Threshold)
        );
        let mut bad = partials[0];
        bad.value += Scalar::ONE;
        assert!(!package.verify_partial(&bad));
        assert_eq!(
            package.combine(&[bad, partials[1]]).err(),
            Some(Error::BadPartial(bad.node))
        );
        let changed = accepted
            .signing_package(generation, 1, m.as_bytes(), [99; 32])
            .unwrap();
        assert_ne!(package.nonce(), changed.nonce());
        assert!(!changed.verify_partial(&partials[0]));
    }
}

#[test]
fn optimistic_combine_recovers_bad_partials_and_zero_interpolation() {
    let (message, context) = open(1);
    let accepted = message.step_a(&context).unwrap();
    let package = accepted.signing_package(1, 1, b"retry", [7; 32]).unwrap();
    let partials = (1..=4)
        .map(|node| {
            package
                .partial(&accepted.decrypt(node, node_secret(node)).unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    let expected = package.combine(&partials).unwrap().to_bytes();
    let mut bad = partials.clone();
    bad[0].value += Scalar::ONE;
    bad[3].value += Scalar::ONE;
    let (combined, faults) = package.combine_with_faults(&bad).unwrap();
    assert_eq!(combined.to_bytes(), expected);
    assert_eq!(faults, vec![1, 4]);
    assert_eq!(package.combine(&bad).unwrap().to_bytes(), expected);

    // For nodes 1,2,3 the interpolation weights at zero are 3,-3,1.
    let mut zero = partials[..3].to_vec();
    zero[0].value =
        (Scalar::from(3u64) * zero[1].value - zero[2].value) * Scalar::from(3u64).invert();
    assert!(!package.verify_partial(&zero[0]));
    let (combined, faults) = package.combine_with_faults(&zero).unwrap();
    assert_eq!(combined.to_bytes(), expected);
    assert_eq!(faults, vec![1]);
    assert_eq!(
        package.combine_with_faults(&zero[..2]).err(),
        Some(Error::BadPartial(1))
    );
}

#[test]
fn sealed_wallet_import_roundtrip_and_release() {
    let (message, context, signatures) = sealed(3);
    let bytes = message.encode().unwrap();
    let decoded = OwnerMessage::decode(&bytes).unwrap();
    assert_eq!(decoded, message);
    assert_eq!(decoded.encode().unwrap(), bytes);
    let accepted = decoded.step_a(&context).unwrap();
    for (index, expected) in signatures.iter().enumerate() {
        let package = accepted
            .signing_package(index as u16 + 1, 1, &context.messages[index], [0; 32])
            .unwrap();
        let partials = [1, 4].map(|i| {
            package
                .partial(&accepted.decrypt(i, node_secret(i)).unwrap())
                .unwrap()
        });
        assert!(partials.iter().all(|p| package.verify_partial(p)));
        let actual = package.combine(&partials).unwrap();
        assert_eq!(actual.to_bytes(), expected.to_bytes());
        actual
            .verify(message.header.public_key, &context.messages[index])
            .unwrap();
        assert_eq!(
            accepted
                .signing_package(index as u16 + 1, 1, b"other transaction", [0; 32])
                .err(),
            Some(Error::Context)
        );
    }
}

#[test]
fn canonical_wire_rejects_trailing_truncated_scalars_and_points() {
    let (message, _) = open(1);
    let bytes = message.encode().unwrap();
    assert_eq!(OwnerMessage::decode(&bytes).unwrap(), message);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(OwnerMessage::decode(&trailing).is_err());
    assert!(OwnerMessage::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut scalar = bytes.clone();
    let scalar_offset = scalar.len() - 32;
    scalar[scalar_offset..].fill(255);
    assert_eq!(OwnerMessage::decode(&scalar).err(), Some(Error::Scalar));
    let mut prefix = bytes.clone();
    prefix[166] = 1;
    assert_eq!(OwnerMessage::decode(&prefix).err(), Some(Error::Encoding));
    // p+1 encodes the same field element as y=1 in permissive decoders.
    let mut noncanonical = [255; 32];
    noncanonical[0] = 238;
    noncanonical[31] = 127;
    assert!(decode_compressed(&noncanonical).is_err());
    let mut alias = bytes;
    alias[167..199].copy_from_slice(&noncanonical);
    assert_eq!(OwnerMessage::decode(&alias).err(), Some(Error::Point));
}

#[test]
fn step_a_rejects_torsion_and_identity_at_every_point_position() {
    let (message, context) = open(1);
    for invalid in [
        EdwardsPoint::identity(),
        EIGHT_TORSION[1],
        G + EIGHT_TORSION[1],
    ] {
        assert!(encode_point(invalid).is_err());
        assert!(decode_compressed(&invalid.compress().to_bytes()).is_err());
        let mut bad = message.clone();
        bad.header.public_key = invalid;
        assert!(bad.step_a(&context).is_err());
        let mut bad = message.clone();
        bad.header.ephemeral = invalid;
        assert!(bad.step_a(&context).is_err());
        let mut bad = message.clone();
        bad.proof.t_1 = invalid;
        assert!(bad.step_a(&context).is_err());
        let mut bad = message.clone();
        bad.proof.t_a = invalid;
        assert!(bad.step_a(&context).is_err());
        for position in 0..5 {
            let mut bad = message.clone();
            if let Deal::Open { x, slots } = &mut bad.deal {
                match position {
                    0 => x[0] = invalid,
                    1 => slots[0].d = invalid,
                    2 => slots[0].e = invalid,
                    3 => slots[0].d_commitments[0] = invalid,
                    _ => slots[0].e_commitments[0] = invalid,
                }
            }
            assert!(bad.step_a(&context).is_err());
        }
        let mut bad_context = Context::new(vec![]);
        bad_context.keys[0] = invalid;
        assert!(message.step_a(&bad_context).is_err());
        let (mut bad, sealed_context, _) = sealed(1);
        if let Deal::Sealed(slots) = &mut bad.deal {
            slots[0].nonce = invalid;
        }
        assert!(bad.step_a(&sealed_context).is_err());
        let (mut bad, sealed_context, _) = sealed(1);
        if let Deal::Sealed(slots) = &mut bad.deal {
            slots[0].commitments[0] = invalid;
        }
        assert!(bad.step_a(&sealed_context).is_err());
    }
}

#[test]
fn auth_address_registry_and_replay_are_checked() {
    let (message, mut context) = open(1);
    let mut bad = message.clone();
    bad.header.address[0] ^= 1;
    assert_eq!(bad.step_a(&context).err(), Some(Error::Context));
    let mut bad = message.clone();
    bad.proof.z_a += Scalar::ONE;
    assert_eq!(bad.step_a(&context).err(), Some(Error::Proof));
    let mut bad = message.clone();
    bad.proof.z_e += Scalar::ONE;
    assert_eq!(bad.step_a(&context).err(), Some(Error::Proof));
    let mut bad = message.clone();
    bad.ciphertexts[0][0] += Scalar::ONE;
    assert_eq!(bad.step_a(&context).err(), Some(Error::Proof));
    let mut bad = message.clone();
    bad.header.epoch += 1;
    assert_eq!(bad.step_a(&context).err(), Some(Error::Context));
    let mut bad = message.clone();
    bad.header.expires = 201;
    assert_eq!(bad.step_a(&context).err(), Some(Error::Context));
    let accepted = message.step_a(&context).unwrap();
    assert_eq!(
        accepted.decrypt(1, node_secret(2)).err(),
        Some(Error::Share)
    );
    assert_eq!(
        accepted.decrypt(0, node_secret(1)).err(),
        Some(Error::Parameters)
    );
    context.bound = true;
    assert_eq!(message.step_a(&context).err(), Some(Error::Context));
}

#[test]
fn duplicate_nonces_and_component_pad_reuse_are_rejected() {
    let (mut message, context) = open(1);
    if let Deal::Open { slots, .. } = &mut message.deal {
        slots[0].e = slots[0].d;
    }
    assert_eq!(message.step_a(&context).err(), Some(Error::Nonce));
    let (mut message, context, _) = sealed(2);
    if let Deal::Sealed(slots) = &mut message.deal {
        slots[1].nonce = slots[0].nonce;
    }
    assert_eq!(message.step_a(&context).err(), Some(Error::Nonce));
    let (message, context) = open(1);
    let hd = message.hd().unwrap();
    let labels = message.deal.labels(&message.header).unwrap();
    let pads = labels
        .iter()
        .map(|label| {
            share_pad(
                &hd,
                1,
                context.keys[0],
                context.keys[0] * sc("ephemeral"),
                *label,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert_ne!(pads[0], pads[1]);
    assert_ne!(pads[1], pads[2]);
    assert_ne!(pads[0], pads[2]);
}

#[test]
fn identities_bind_dealing_only_in_sealed_mode() {
    let (message, _) = open(1);
    let mut modified = message.clone();
    modified.ciphertexts[0][0] += Scalar::ONE;
    modified.proof.z_a += Scalar::ONE;
    assert_eq!(message.rid().unwrap(), modified.rid().unwrap());
    assert_ne!(message.mid().unwrap(), modified.mid().unwrap());
    modified.header.owner_nonce[0] ^= 1;
    assert_ne!(message.rid().unwrap(), modified.rid().unwrap());
    let (sealed, _, _) = sealed(1);
    let mut modified = sealed.clone();
    if let Deal::Sealed(slots) = &mut modified.deal {
        slots[0].commitments[0] += G;
    }
    assert_ne!(sealed.rid().unwrap(), modified.rid().unwrap());
}

#[test]
fn t2_multiple_inputs_use_distinct_labels_and_slots() {
    let context = Context::new(vec![]);
    let mut header = header(2, 2);
    header.threshold = 3;
    header.inputs = 2;
    let mut rng = TestRng::new();
    let nonces = (0..4)
        .map(|i| (sc(&format!("multi/d/{i}")), sc(&format!("multi/e/{i}"))))
        .collect::<Vec<_>>();
    let message = Owner::open(header, SEED, &nonces, &mut rng)
        .unwrap()
        .encrypt(sc("ephemeral"), &context.keys, &mut rng)
        .unwrap();
    let accepted = message.step_a(&context).unwrap();
    let labels = message.deal.labels(&message.header).unwrap();
    assert_eq!(labels.len(), 9);
    let unique = labels
        .iter()
        .map(|l| l.bytes())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), labels.len());
    for generation in 1..=2 {
        for input in 1..=2 {
            let m = format!("generation {generation} input {input}");
            let package = accepted
                .signing_package(generation, input, m.as_bytes(), [generation as u8; 32])
                .unwrap();
            let partials = [1, 2, 4].map(|node| {
                package
                    .partial(&accepted.decrypt(node, node_secret(node)).unwrap())
                    .unwrap()
            });
            package
                .combine(&partials)
                .unwrap()
                .verify(message.header.public_key, m.as_bytes())
                .unwrap();
            assert_eq!(
                package.combine(&partials[..2]).err(),
                Some(Error::Threshold)
            );
        }
    }
    let mut reshare = message.header.clone();
    reshare.on_rotation = 2;
    assert_eq!(reshare.validate(), Err(Error::Parameters));
}

#[test]
fn authenticated_bad_delivery_fails_private_share_check() {
    let (mut message, context) = open(1);
    // A malicious owner knows both witnesses, so it can authenticate malformed
    // ciphertexts. Public acceptance alone must never stand in for delivery.
    message.ciphertexts[0][1] += Scalar::ONE;
    let ct = message
        .ciphertexts
        .iter()
        .flatten()
        .flat_map(|s| encode_scalar(*s))
        .collect::<Vec<_>>();
    message.proof = AuthProof::create(
        &message.hd().unwrap(),
        &ct,
        sc("ephemeral"),
        secret_from_seed(&SEED),
        G,
        None,
        &mut TestRng::new(),
    )
    .unwrap();
    let accepted = message.step_a(&context).unwrap();
    assert_eq!(
        accepted.decrypt(1, node_secret(1)).err(),
        Some(Error::Share)
    );
    assert!(accepted.decrypt(2, node_secret(2)).is_ok());
}

#[test]
fn strict_verifier_rejects_scalar_malleability_and_small_order_nonce() {
    let (message, context) = open(1);
    let accepted = message.step_a(&context).unwrap();
    let package = accepted.signing_package(1, 1, b"message", [9; 32]).unwrap();
    let partials = [1, 2].map(|node| {
        package
            .partial(&accepted.decrypt(node, node_secret(node)).unwrap())
            .unwrap()
    });
    let signature = package.combine(&partials).unwrap();
    let mut bytes = signature.to_bytes();
    bytes[32..].fill(255);
    assert!(Combined(ed25519_dalek::Signature::from_bytes(&bytes))
        .verify(message.header.public_key, b"message")
        .is_err());
    let mut bytes = signature.to_bytes();
    bytes[..32].copy_from_slice(EIGHT_TORSION[1].compress().as_bytes());
    assert!(Combined(ed25519_dalek::Signature::from_bytes(&bytes))
        .verify(message.header.public_key, b"message")
        .is_err());
}

#[test]
fn revised_edwards_proof_and_complaint_membership() {
    let (mut message, context) = open(1);
    for field in 0..6 {
        let mut bad = message.clone();
        match field {
            0 => bad.proof.e_prime += G,
            1 => bad.proof.t_1 += G,
            2 => bad.proof.t_2 += G,
            3 => bad.proof.z_e += Scalar::ONE,
            4 => bad.proof.t_a += G,
            _ => bad.proof.z_a += Scalar::ONE,
        }
        assert!(bad.step_a(&context).is_err());
    }
    for invalid in [
        EdwardsPoint::identity(),
        EIGHT_TORSION[1],
        G + EIGHT_TORSION[1],
    ] {
        for field in 0..3 {
            let mut bad = message.clone();
            match field {
                0 => bad.proof.e_prime = invalid,
                1 => bad.proof.t_1 = invalid,
                _ => bad.proof.t_2 = invalid,
            }
            assert!(bad.step_a(&context).is_err());
        }
    }
    // Strict decoding applies at the actual E' and registered-key wire boundaries.
    let bytes = message.encode().unwrap();
    let mut noncanonical = [255; 32];
    noncanonical[0] = 237;
    noncanonical[31] = 127;
    let mut bad_bytes = bytes.clone();
    let offset = bytes.len() - 196;
    bad_bytes[offset + 1..offset + 33].copy_from_slice(&noncanonical);
    assert!(OwnerMessage::decode(&bad_bytes).is_err());
    assert!(decode_point(&[&[0][..], &noncanonical].concat()).is_err());
    message.ciphertexts[0][0] += Scalar::ONE;
    let ct: Vec<_> = message
        .ciphertexts
        .iter()
        .flatten()
        .flat_map(|s| encode_scalar(*s))
        .collect();
    message.proof = AuthProof::create(
        &message.hd().unwrap(),
        &ct,
        sc("ephemeral"),
        secret_from_seed(&SEED),
        G,
        None,
        &mut TestRng::new(),
    )
    .unwrap();
    let accepted = message.step_a(&context).unwrap();
    let complaint = accepted
        .complain(1, node_secret(1), &mut TestRng::new())
        .unwrap();
    accepted.verify_complaint(&complaint).unwrap();
    let mut encoded_complaint = complaint.proof.encode().unwrap();
    encoded_complaint[1..33].copy_from_slice(&noncanonical);
    assert!(DhProof::decode(&encoded_complaint).is_err());

    assert!(accepted
        .complain(2, node_secret(2), &mut TestRng::new())
        .is_err());
    for invalid in [
        EdwardsPoint::identity(),
        EIGHT_TORSION[1],
        G + EIGHT_TORSION[1],
    ] {
        let mut bad = complaint.clone();
        bad.proof.key = invalid;
        assert!(accepted.verify_complaint(&bad).is_err());
        assert!(DhProof::create(
            &message.mid().unwrap(),
            invalid,
            message.header.ephemeral,
            node_secret(1),
            &mut TestRng::new()
        )
        .is_err());
    }
    let gp = hg("LD1/eph", b"test").unwrap();
    assert!(gp.is_torsion_free());
    assert_ne!(gp, EdwardsPoint::identity());
    assert_ne!(gp, hg("LD1/rs-eph", b"test").unwrap());
}

#[test]
fn edwards_transfer_reconstructs_and_rejects_non_subgroup_points() {
    use line_dealing::{
        ed25519::reshare::{NewCommittee, Subdealing, Transfer},
        hash::ReshareDomain,
    };
    let (message, context) = open(1);
    let accepted = message.step_a(&context).unwrap();
    let old = &accepted.polynomials()[0];
    let committee = NewCommittee {
        keys: context.keys.clone(),
        f: 1,
        threshold: 2,
    };
    let mut rng = TestRng::new();
    let dealers: Vec<_> = (1..=2)
        .map(|dealer| {
            Subdealing::create(
                ReshareDomain {
                    rid: message.rid().unwrap(),
                    old_epoch: 7,
                    new_epoch: 8,
                    dealer,
                },
                message.deal.labels(&message.header).unwrap()[0],
                old,
                accepted
                    .decrypt(dealer, node_secret(dealer))
                    .unwrap()
                    .values()[0],
                committee.clone(),
                sc(&format!("rs-e/{dealer}")),
                &mut rng,
            )
            .unwrap()
        })
        .collect();
    let transfer = Transfer::verify(old, &dealers).unwrap();
    for node in 1..=4 {
        let share = transfer.decrypt(node, node_secret(node)).unwrap();
        assert!(transfer.commitment().verify(node, share));
    }
    let one = transfer.decrypt(1, node_secret(1)).unwrap();
    let two = transfer.decrypt(2, node_secret(2)).unwrap();
    assert_eq!(G * (one * Scalar::from(2u64) - two), old.constant);
    for invalid in [
        EdwardsPoint::identity(),
        EIGHT_TORSION[1],
        G + EIGHT_TORSION[1],
    ] {
        for field in 0..7 {
            let mut bad = dealers.clone();
            match field {
                0 => bad[0].committee.keys[0] = invalid,
                1 => bad[0].ephemeral = invalid,
                2 => bad[0].coefficients[0] = invalid,
                3 => bad[0].proof.e_prime = invalid,
                4 => bad[0].proof.t_1 = invalid,
                5 => bad[0].proof.t_2 = invalid,
                _ => bad[0].proof.t_a = invalid,
            }
            assert!(Transfer::verify(old, &bad).is_err());
            assert!(bad[0].decrypt(old, 1, node_secret(1)).is_err());
        }
        let mut proof = DhProof::create(
            &[1; 32],
            context.keys[0],
            dealers[0].ephemeral,
            node_secret(1),
            &mut rng,
        )
        .unwrap();
        proof.key = invalid;
        assert!(dealers[0].verify_complaint(old, 1, &proof).is_err());
    }
    let mut changed = dealers.clone();
    changed[0].ciphertexts[0] += Scalar::ONE;
    assert!(Transfer::verify(old, &changed).is_err());
    assert!(changed[0]
        .complain(old, 1, node_secret(1), &mut rng)
        .is_err());
    let ct: Vec<_> = changed[0]
        .ciphertexts
        .iter()
        .flat_map(|s| encode_scalar(*s))
        .collect();
    changed[0].proof = AuthProof::create(
        &changed[0].hd().unwrap(),
        &ct,
        sc("rs-e/1"),
        accepted.decrypt(1, node_secret(1)).unwrap().values()[0],
        G,
        Some(changed[0].domain),
        &mut rng,
    )
    .unwrap();
    let proof = changed[0]
        .complain(old, 1, node_secret(1), &mut rng)
        .unwrap();
    changed[0].verify_complaint(old, 1, &proof).unwrap();
    for invalid in [
        EdwardsPoint::identity(),
        EIGHT_TORSION[1],
        G + EIGHT_TORSION[1],
    ] {
        let mut bad = proof.clone();
        bad.key = invalid;
        assert!(changed[0].verify_complaint(old, 1, &bad).is_err());
    }
}
