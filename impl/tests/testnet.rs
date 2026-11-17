//! LOOP item 34: testnet end to end with the split-line committee.
//!
//! Offline tests (always run) build each network's transaction from fixed
//! inputs, sign it with the committee and check it against published vectors,
//! chain-derived fixtures and the chain's verification rule.
//! Live tests are `#[ignore]` and need `TESTNET_E2E=1`; see impl/testnet/PLAN.md.

mod testnet {
    pub mod chains;
    pub mod codec;
    pub mod committee;
    pub mod live;
    pub mod tools;
    pub mod vectors;
}
use testnet::{chains::*, codec::*, committee::*, vectors::*};

use k256::{
    ecdsa::{RecoveryId, VerifyingKey},
    elliptic_curve::sec1::FromEncodedPoint,
    schnorr::signature::Verifier,
    AffinePoint, EncodedPoint, ProjectivePoint,
};
use line_dealing::builder::{Eip1559Transaction, SpendKind};
use line_dealing::split::{
    group::{Edwards, Secp},
    request::SpendVariant,
    schnorr::SchnorrSuite,
};

fn seed(label: &str) -> [u8; 32] {
    sha256(format!("testnet/offline/{label}").as_bytes())
}
fn lift_x(x: &[u8]) -> ProjectivePoint {
    let mut sec = vec![2];
    sec.extend_from_slice(x);
    let p = EncodedPoint::from_bytes(&sec).unwrap();
    ProjectivePoint::from(Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&p)).unwrap())
}

// ---------------- encoders against published vectors ----------------

#[test]
fn bip350_segwit_address_vectors() {
    for (hrp, addr, script) in SEGWIT_VALID {
        let (v, p) = segwit_decode(hrp, addr).unwrap_or_else(|| panic!("{addr}"));
        assert_eq!(hex(&segwit_script(v, &p)), *script);
        assert_eq!(segwit_encode(hrp, v, &p), addr.to_lowercase());
    }
    for (hrp, addr) in SEGWIT_INVALID {
        assert!(segwit_decode(hrp, addr).is_none(), "{addr}");
    }
}

#[test]
fn bip86_output_key_matches_the_split_taptweak() {
    let (q, ..) = Secp::output_key(lift_x(&unhex(BIP86_INTERNAL)), &[]).unwrap();
    assert_eq!(hex(&x_only(q)), BIP86_OUTPUT);
    assert_eq!(btc_address("bc", &p2tr_script(q)), BIP86_ADDRESS);
}

#[test]
fn hash160_of_generator_is_the_bip173_program() {
    let g = ProjectivePoint::GENERATOR;
    assert_eq!(
        hex(&p2wpkh_script(g)),
        "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    );
}

#[test]
fn base58_base64_blake2_der_vectors() {
    // base58: Bitcoin Core src/test/data/base58_encode_decode.json entries.
    for (h, b) in [
        ("", ""),
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
        ("00000000000000000000", "1111111111"),
        ("516b6fcd0f", "ABnLTmg"),
        ("572e4794", "3EFU7m"),
        ("10c8511e", "Rt5zm"),
    ] {
        assert_eq!(base58(&unhex(h)), b);
        assert_eq!(unbase58(b).unwrap(), unhex(h));
    }
    assert_eq!(base58(&SYSTEM_PROGRAM), "11111111111111111111111111111111");
    // RFC 4648 section 10.
    for (p, e) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64(p.as_bytes()), e);
        assert_eq!(unbase64(e).unwrap(), p.as_bytes());
    }
    // RFC 7693 appendix A (BLAKE2b-512 of "abc") and BLAKE2b-256 of "".
    {
        use blake2::{Blake2b512, Digest};
        assert_eq!(
            hex(&Blake2b512::digest(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }
    assert_eq!(
        hex(&blake2b256(b"")),
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
    );
    // DER: the hand encoder equals k256's for random low-s signatures.
    for i in 0..64u8 {
        let key = k256::ecdsa::SigningKey::from_bytes(&sha256(&[i]).into()).unwrap();
        let (sig, _) = key.sign_prehash_recoverable(&sha256(&[i, i])).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig);
        let (r, s) = (sig.r().to_bytes(), sig.s().to_bytes());
        assert_eq!(der(&r.into(), &s.into()), sig.to_der().as_bytes().to_vec());
    }
}

#[test]
fn eip55_vectors() {
    for a in EIP55 {
        let raw: [u8; 20] = unhex(&a[2..].to_lowercase()).try_into().unwrap();
        assert_eq!(eip55(&raw), *a);
    }
}

#[test]
fn cip19_enterprise_testnet_address() {
    let (hrp, vk, _) = bech32_bytes_decode(CIP19_ADDR_VK).unwrap();
    assert_eq!(hrp, "addr_vk");
    let vk: [u8; 32] = vk.try_into().unwrap();
    assert_eq!(ada_bech32(&ada_enterprise(&vk)), CIP19_TYPE6_TESTNET);
}

// ---------------- chain-derived fixtures ----------------

#[test]
fn sepolia_fixture_reencodes_and_recovers_its_sender() {
    use sepolia::*;
    let tx = Eip1559Transaction {
        chain_id: 11_155_111,
        nonce: NONCE,
        to: unhex(TO).try_into().unwrap(),
        value: VALUE,
        gas_limit: GAS,
        max_fee_per_gas: MAX_FEE,
        max_priority_fee_per_gas: MAX_PRIORITY,
        anchor_height: 0,
    };
    let (r, s): ([u8; 32], [u8; 32]) = (unhex(R).try_into().unwrap(), unhex(S).try_into().unwrap());
    let raw = eth_signed(&tx, Y_PARITY, &r, &s);
    assert_eq!(hex(&raw), RAW);
    assert_eq!(hex(&keccak(&raw)), HASH);
    let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();
    let key =
        VerifyingKey::recover_from_prehash(&tx.sighash(), &sig, RecoveryId::new(Y_PARITY, false))
            .unwrap();
    assert_eq!(
        hex(&eth_address(ProjectivePoint::from(*key.as_affine()))),
        FROM
    );
}

#[test]
fn preprod_fixture_signs_blake2b_of_the_body() {
    let raw = unhex(preprod::CBOR);
    assert_eq!(raw[0], 0x84);
    let body_end = cbor_skip(&raw, 1);
    let body = &raw[1..body_end];
    assert_eq!(hex(&blake2b256(body)), preprod::TX_HASH);
    // witness set {0: [[vkey, sig]]}
    let w = &raw[body_end..];
    assert_eq!(&w[..6], &[0xa1, 0x00, 0x81, 0x82, 0x58, 0x20]);
    let vk: [u8; 32] = w[6..38].try_into().unwrap();
    assert_eq!(&w[38..40], &[0x58, 0x40]);
    let sig: [u8; 64] = w[40..104].try_into().unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&vk)
        .unwrap()
        .verify_strict(
            &blake2b256(body),
            &ed25519_dalek::Signature::from_bytes(&sig),
        )
        .unwrap();
    assert_eq!(cbor_skip(&raw, 0), raw.len());
}

// ---------------- committee-signed transactions ----------------

#[test]
fn committee_key_is_stable_and_nonces_are_fresh() {
    let mut rng = fresh();
    let a = Bip340Committee::new(seed("stable"), &mut rng);
    let mut b = Bip340Committee::new(seed("stable"), &mut rng);
    assert_eq!(a.output_key(), b.output_key());
    let other = Bip340Committee::new(seed("other"), &mut rng);
    assert_ne!(a.output_key(), other.output_key());
    let m = [9u8; 32];
    let s1 = b.sign_message(&m, &mut rng);
    let mut c = Bip340Committee::new(seed("stable"), &mut rng);
    let s2 = c.sign_message(&m, &mut rng);
    assert_ne!(s1[..32], s2[..32], "a rerun must draw a new nonce");
    let e1 = EcdsaCommittee::new(seed("stable"));
    let e2 = EcdsaCommittee::new(seed("stable"));
    assert_eq!(e1.public_key(), e2.public_key());
    let h = [5u8; 32];
    assert_ne!(
        e1.sign_hash(h, &mut rng).signature.r().to_bytes(),
        e2.sign_hash(h, &mut rng).signature.r().to_bytes()
    );
}

fn fake_prev(script: Vec<u8>) -> line_dealing::builder::Utxo {
    utxo(
        "4f2a5c3a1b0e9d8c7b6a59483726150403f2e1d0c9b8a79685746352413021f0",
        1,
        100_000,
        script,
    )
}

#[test]
fn bitcoin_p2tr_committee_spend_verifies() {
    let mut rng = fresh();
    let mut committee = Bip340Committee::new(seed("btc-p2tr"), &mut rng);
    let q = committee.output_key();
    let script = p2tr_script(q);
    let address = btc_address("tb", &script);
    assert!(address.starts_with("tb1p"));
    assert_eq!(script_for_address("tb", &address), script);
    let back = script_for_address(
        "tb",
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
    );
    let tx = btc_spend(fake_prev(script.clone()), back, 300, SpendKind::P2tr);
    let (sig, message) = committee.sign_variant(SpendVariant::bitcoin(&tx).unwrap(), &mut rng);
    // Independent recomputation of the BIP341 sighash and BIP340 verification
    // against the key parsed from the address.
    assert_eq!(message, tx.sighashes().unwrap()[0].to_vec());
    let key = k256::schnorr::VerifyingKey::from_bytes(&script[2..]).unwrap();
    key.verify_raw(
        &message,
        &k256::schnorr::Signature::try_from(&sig[..]).unwrap(),
    )
    .unwrap();
    let signed = btc_signed(&tx, &[vec![sig.to_vec()]]);
    assert_eq!(&signed[4..6], &[0, 1]);
    let unsigned = tx.unsigned_bytes().unwrap();
    assert_eq!(signed.len(), unsigned.len() + 2 + 1 + 1 + 64);
    assert_eq!(btc_vsize(&signed, unsigned.len()), 111);
    assert_ne!(sha256d(&signed), sha256d(&unsigned));
}

#[test]
fn bitcoin_p2wpkh_committee_spend_verifies() {
    let mut rng = fresh();
    let committee = EcdsaCommittee::new(seed("btc-p2wpkh"));
    let pk = committee.public_key();
    let script = p2wpkh_script(pk);
    let address = btc_address("tb", &script);
    assert!(address.starts_with("tb1q"));
    let tx = btc_spend(
        fake_prev(script.clone()),
        script.clone(),
        300,
        SpendKind::P2wpkh,
    );
    let sigs = committee.sign_p2wpkh(&tx, &mut rng);
    let sighash = tx.sighashes().unwrap()[0];
    let sig = &sigs[0].signature;
    assert!(sig.normalize_s().is_none(), "BIP146 low-s");
    let vk = VerifyingKey::from_sec1_bytes(&compressed(pk)).unwrap();
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    vk.verify_prehash(&sighash, sig).unwrap();
    // BIP143 scriptCode uses hash160(pubkey) from the witness.
    assert_eq!(&script[2..], &hash160(&compressed(pk)));
    let mut item = der(&sig.r().to_bytes().into(), &sig.s().to_bytes().into());
    item.push(1); // SIGHASH_ALL
    let signed = btc_signed(&tx, &[vec![item, compressed(pk).to_vec()]]);
    assert_eq!(&signed[4..6], &[0, 1]);
}

#[test]
fn ethereum_committee_transfer_recovers_to_committee_address() {
    let mut rng = fresh();
    let committee = EcdsaCommittee::new(seed("sepolia"));
    let from = eth_address(committee.public_key());
    let tx = Eip1559Transaction {
        chain_id: 11_155_111,
        nonce: 0,
        to: unhex(sepolia::FROM).try_into().unwrap(),
        value: 1_000_000_000_000,
        gas_limit: 21_000,
        max_fee_per_gas: 3_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        anchor_height: 0,
    };
    let sig = committee.sign_hash(tx.sighash(), &mut rng);
    let (r, s) = (sig.signature.r().to_bytes(), sig.signature.s().to_bytes());
    assert!(sig.signature.normalize_s().is_none(), "EIP-2 low-s");
    let raw = eth_signed(&tx, sig.recovery_id.is_y_odd(), &r.into(), &s.into());
    assert_eq!(raw[0], 2);
    let key = VerifyingKey::recover_from_prehash(
        &tx.sighash(),
        &sig.signature,
        RecoveryId::new(sig.recovery_id.is_y_odd(), false),
    )
    .unwrap();
    assert_eq!(eth_address(ProjectivePoint::from(*key.as_affine())), from);
}

#[test]
fn cardano_committee_transaction_verifies() {
    let mut rng = fresh();
    let mut committee = Ed25519Committee::new(seed("preprod"), &mut rng);
    let vk: [u8; 32] = Edwards::signature_point(committee.output_key()).unwrap();
    let addr = ada_enterprise(&vk);
    assert!(ada_bech32(&addr).starts_with("addr_test1v"));
    let tx = AdaTx {
        inputs: vec![(sha256(b"input"), 0)],
        outputs: vec![(addr.clone(), 9_800_000)],
        fee: 200_000,
        ttl: 100_000_000,
    };
    let id = tx.id();
    let (sig, message) = committee.sign_variant(
        SpendVariant {
            transaction: id.to_vec(),
            prevouts: vec![],
            destination: addr,
        },
        &mut rng,
    );
    assert_eq!(message, id.to_vec());
    let signed = tx.signed(&vk, &sig);
    // Same independent check as the preprod fixture: cut the body out of the
    // signed CBOR, hash it, verify the witness.
    let body_end = cbor_skip(&signed, 1);
    assert_eq!(blake2b256(&signed[1..body_end]), id);
    assert_eq!(cbor_skip(&signed, 0), signed.len());
    ed25519_dalek::VerifyingKey::from_bytes(&vk)
        .unwrap()
        .verify_strict(&id, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
}

#[test]
fn solana_committee_transfer_verifies() {
    let mut rng = fresh();
    let mut committee = Ed25519Committee::new(seed("devnet"), &mut rng);
    let from: [u8; 32] = Edwards::signature_point(committee.output_key()).unwrap();
    let to = sha256(b"recipient");
    let message = sol_transfer_message(&from, &to, &sha256(b"blockhash"), 5_000_000);
    // header, key count, keys, blockhash, ix count, program, account count, accounts, data len, data
    assert_eq!(message.len(), 3 + 1 + 96 + 32 + 1 + 1 + 1 + 2 + 1 + 12);
    let (sig, signed_message) = committee.sign_variant(
        SpendVariant {
            transaction: message.clone(),
            prevouts: vec![],
            destination: to.to_vec(),
        },
        &mut rng,
    );
    assert_eq!(signed_message, message);
    ed25519_dalek::VerifyingKey::from_bytes(&from)
        .unwrap()
        .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
    let wire = sol_signed(&sig, &message);
    assert_eq!(wire.len(), 1 + 64 + message.len());
    assert_eq!(unbase58(&base58(&from)).unwrap(), from.to_vec());
}

#[test]
fn midnight_committee_signature_is_bip340_over_sha256() {
    let mut rng = fresh();
    let mut committee = Bip340Committee::new(seed("midnight"), &mut rng);
    let vk = x_only(committee.output_key());
    let data = b"midnight intent signature data, any length".to_vec();
    let sig = committee.sign_message(&sha256(&data), &mut rng);
    // k256's Verifier hashes the message with SHA-256 before BIP340, the rule
    // midnight-base-crypto uses (checked against ledger-v9 by the Node probe).
    k256::schnorr::VerifyingKey::from_bytes(&vk)
        .unwrap()
        .verify(
            &data,
            &k256::schnorr::Signature::try_from(&sig[..]).unwrap(),
        )
        .unwrap();
}

/// Optional: the installed ledger-v9 verifies the committee signature.
#[test]
fn midnight_ledger_v9_accepts_the_committee_signature() {
    if std::env::var("TESTNET_TOOLS").as_deref() != Ok("1") {
        return;
    }
    let mut rng = fresh();
    let mut committee = Bip340Committee::new(seed("midnight"), &mut rng);
    let vk = x_only(committee.output_key());
    let data = b"midnight ledger-v9 check".to_vec();
    let sig = committee.sign_message(&sha256(&data), &mut rng);
    let out = testnet::live::midnight_node(&["verify", &hex(&vk), &hex(&data), &hex(&sig)]);
    assert_eq!(out.trim(), "true");
}

// ---------------- live tests (TESTNET_E2E=1, --ignored) ----------------

#[test]
#[ignore]
fn live_bitcoin_p2wpkh() {
    testnet::live::bitcoin(SpendKind::P2wpkh);
}
#[test]
#[ignore]
fn live_bitcoin_p2tr() {
    testnet::live::bitcoin(SpendKind::P2tr);
}
#[test]
#[ignore]
fn live_sepolia() {
    testnet::live::sepolia();
}
#[test]
#[ignore]
fn live_cardano_preprod() {
    testnet::live::cardano();
}
#[test]
#[ignore]
fn live_solana_devnet() {
    testnet::live::solana();
}
#[test]
#[ignore]
fn live_midnight_preview() {
    testnet::live::midnight();
}

/// Optional: mn.mjs derives the pinned public address of the Moriarty Preview
/// wallet from its pinned public verifying key (public data only).
#[test]
fn midnight_sdk_address_of_a_pinned_public_key() {
    if std::env::var("TESTNET_TOOLS").as_deref() != Ok("1") {
        return;
    }
    let out = testnet::live::midnight_node(&[
        "address",
        "830e20e1b4d1253d58fbd195bdf5b9ecf06287320bad54c7c5b06f32fbed566e",
    ]);
    assert!(
        out.contains("mn_addr_preview1qdqmf7mv8n673fm0r868vyxzkfcnjepmsnyayhxc54vqvyg4l87s5dwena")
    );
}

#[test]
#[ignore]
fn live_addresses() {
    testnet::live::addresses();
}
