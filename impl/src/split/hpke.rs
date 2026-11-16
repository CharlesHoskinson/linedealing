//! Single-shot RFC 9180 base-mode HPKE for actor capsules.

use crate::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Fixed actor-capsule application context.
pub const INFO: &[u8] = b"SL1/act";
/// The encapsulated X25519 public key and Poly1305 tag.
pub const OVERHEAD: usize = 48;

const KEM_SUITE: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

/// Encrypt one capsule with fresh ephemeral randomness and empty associated data.
/// The wire encoding is `enc[32] || ciphertext || tag[16]`.
pub fn seal(
    recipient_public_key: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let public_bytes: [u8; 32] = recipient_public_key
        .try_into()
        .map_err(|_| Error::Encoding)?;
    let recipient = PublicKey::from(public_bytes);
    let ephemeral = StaticSecret::random_from_rng(rng);
    let enc = PublicKey::from(&ephemeral).to_bytes();
    let shared = shared_secret(&ephemeral, &recipient, &enc, &public_bytes)?;
    let ciphertext = key_schedule(&shared, INFO)?.encrypt(plaintext, &[])?;
    let mut out = Vec::with_capacity(32 + ciphertext.len());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Authenticate and decrypt one actor capsule with its 32-byte recipient key.
pub fn open(recipient_secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let secret_bytes: [u8; 32] = recipient_secret_key
        .try_into()
        .map_err(|_| Error::Encoding)?;
    let secret_bytes = Zeroizing::new(secret_bytes);
    if ciphertext.len() < OVERHEAD {
        return Err(Error::Encoding);
    }
    let secret = StaticSecret::from(*secret_bytes);
    let public = PublicKey::from(&secret);
    let enc: [u8; 32] = ciphertext[..32].try_into().map_err(|_| Error::Encoding)?;
    let shared = shared_secret(&secret, &PublicKey::from(enc), &enc, public.as_bytes())?;
    key_schedule(&shared, INFO)?.decrypt(&ciphertext[32..], &[])
}

// RFC 9180 sections 4 and 7.1.1. Bind both public keys in enc || pkR.
fn shared_secret(
    secret: &StaticSecret,
    peer: &PublicKey,
    enc: &[u8; 32],
    recipient: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let dh = secret.diffie_hellman(peer);
    if !dh.was_contributory() {
        return Err(Error::Point);
    }
    let mut context = [0; 64];
    context[..32].copy_from_slice(enc);
    context[32..].copy_from_slice(recipient);
    let eae_prk = labeled_extract(&[], KEM_SUITE, b"eae_prk", dh.as_bytes());
    labeled_expand(&eae_prk, KEM_SUITE, b"shared_secret", &context)
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyMaterial {
    key: [u8; 32],
    nonce: [u8; 12],
}

fn labeled_extract(salt: &[u8], suite: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        7 + suite.len() + label.len() + ikm.len(),
    ));
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let (mut prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    let mut out = Zeroizing::new([0; 32]);
    out.copy_from_slice(&prk);
    prk[..].zeroize();
    out
}

fn labeled_expand<const N: usize>(
    prk: &[u8; 32],
    suite: &[u8],
    label: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; N]>> {
    let length = u16::try_from(N)
        .map_err(|_| Error::Parameters)?
        .to_be_bytes();
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| Error::Parameters)?;
    let mut out = Zeroizing::new([0; N]);
    hkdf.expand_multi_info(&[&length, b"HPKE-v1", suite, label, info], out.as_mut())
        .map_err(|_| Error::Parameters)?;
    Ok(out)
}

// RFC 9180 section 5.1, mode=0 with empty PSK and PSK ID.
fn key_schedule(shared: &[u8; 32], info: &[u8]) -> Result<KeyMaterial> {
    let psk_id_hash = labeled_extract(&[], HPKE_SUITE, b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&[], HPKE_SUITE, b"info_hash", info);
    let mut context = [0; 65];
    context[1..33].copy_from_slice(psk_id_hash.as_slice());
    context[33..].copy_from_slice(info_hash.as_slice());
    let secret = labeled_extract(shared, HPKE_SUITE, b"secret", &[]);
    Ok(KeyMaterial {
        key: *labeled_expand(&secret, HPKE_SUITE, b"key", &context)?,
        nonce: *labeled_expand(&secret, HPKE_SUITE, b"base_nonce", &context)?,
    })
}

impl KeyMaterial {
    // Consuming the key material limits each context to sequence number zero.
    // RFC 9180 uses base_nonce XOR seq, so the first nonce equals base_nonce.
    fn encrypt(self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        ChaCha20Poly1305::new((&self.key).into())
            .encrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Context)
    }

    fn decrypt(self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        ChaCha20Poly1305::new((&self.key).into())
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::SeededRng;

    fn decode(value: &serde_json::Value) -> Vec<u8> {
        let text = value.as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc9180_base_x25519_sha256_chacha_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/hpke_x25519_chacha.json"))
                .unwrap();
        assert_eq!(
            (
                v["mode"].as_u64(),
                v["kem_id"].as_u64(),
                v["kdf_id"].as_u64(),
                v["aead_id"].as_u64()
            ),
            (Some(0), Some(32), Some(1), Some(3))
        );
        let ephemeral = StaticSecret::from(<[u8; 32]>::try_from(decode(&v["skEm"])).unwrap());
        let recipient = StaticSecret::from(<[u8; 32]>::try_from(decode(&v["skRm"])).unwrap());
        let public = PublicKey::from(&recipient);
        assert_eq!(public.as_bytes().as_slice(), decode(&v["pkRm"]));
        let enc = PublicKey::from(&ephemeral).to_bytes();
        assert_eq!(enc.as_slice(), decode(&v["enc"]));
        let shared = shared_secret(&ephemeral, &public, &enc, public.as_bytes()).unwrap();
        assert_eq!(shared.as_slice(), decode(&v["shared_secret"]));
        let received =
            shared_secret(&recipient, &PublicKey::from(enc), &enc, public.as_bytes()).unwrap();
        assert_eq!(*shared, *received);
        let info = decode(&v["info"]);
        let material = key_schedule(&shared, &info).unwrap();
        assert_eq!(material.key.as_slice(), decode(&v["key"]));
        assert_eq!(material.nonce.as_slice(), decode(&v["base_nonce"]));
        let first = &v["encryption"];
        assert_eq!(
            material
                .encrypt(&decode(&first["pt"]), &decode(&first["aad"]))
                .unwrap(),
            decode(&first["ct"])
        );
        assert_eq!(
            key_schedule(&received, &info)
                .unwrap()
                .decrypt(&decode(&first["ct"]), &decode(&first["aad"]))
                .unwrap(),
            decode(&first["pt"])
        );
    }

    #[test]
    fn authenticates_info_and_aad() {
        let shared = [7; 32];
        let ciphertext = key_schedule(&shared, INFO)
            .unwrap()
            .encrypt(b"capsule", b"metadata")
            .unwrap();
        assert_eq!(
            key_schedule(&shared, b"SL1/other")
                .unwrap()
                .decrypt(&ciphertext, b"metadata"),
            Err(Error::Context)
        );
        assert_eq!(
            key_schedule(&shared, INFO)
                .unwrap()
                .decrypt(&ciphertext, b"altered"),
            Err(Error::Context)
        );
    }

    fn recipient() -> ([u8; 32], [u8; 32]) {
        let secret = [42; 32];
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        (secret, public.to_bytes())
    }

    #[test]
    fn roundtrip_and_fresh_encapsulation() {
        let (secret, public) = recipient();
        let mut rng = SeededRng::new(91);
        for plaintext in [
            b"".as_slice(),
            b"actor header key, position, token and capsule keys",
        ] {
            let first = seal(&public, plaintext, &mut rng).unwrap();
            let second = seal(&public, plaintext, &mut rng).unwrap();
            assert_eq!(first.len(), plaintext.len() + OVERHEAD);
            assert_ne!(first, second);
            assert_eq!(open(&secret, &first).unwrap(), plaintext);
            assert_eq!(open(&secret, &second).unwrap(), plaintext);
        }
    }

    #[test]
    fn rejects_malformed_lengths() {
        let (secret, public) = recipient();
        let mut rng = SeededRng::new(92);
        for key in [vec![], vec![1; 31], vec![1; 33]] {
            assert_eq!(seal(&key, b"capsule", &mut rng), Err(Error::Encoding));
            assert_eq!(open(&key, &[1; 64]), Err(Error::Encoding));
        }
        for length in 0..OVERHEAD {
            assert_eq!(open(&secret, &vec![1; length]), Err(Error::Encoding));
        }
        assert!(seal(&public, b"capsule", &mut rng).is_ok());
    }

    #[test]
    fn rejects_noncontributory_dh() {
        let (secret, _) = recipient();
        let mut rng = SeededRng::new(93);
        for low_order in [[0; 32], {
            let mut one = [0; 32];
            one[0] = 1;
            one
        }] {
            assert_eq!(seal(&low_order, b"capsule", &mut rng), Err(Error::Point));
            let mut encoded = vec![0; OVERHEAD];
            encoded[..32].copy_from_slice(&low_order);
            assert_eq!(open(&secret, &encoded), Err(Error::Point));
        }
    }

    #[test]
    fn rejects_tampered_encapsulation_ciphertext_and_tag() {
        let (secret, public) = recipient();
        let ciphertext = seal(&public, b"actor capsule", &mut SeededRng::new(94)).unwrap();
        for index in [0, 31, 32, ciphertext.len() - 1] {
            let mut tampered = ciphertext.clone();
            tampered[index] ^= 1;
            assert!(open(&secret, &tampered).is_err());
        }
        assert_eq!(open(&[43; 32], &ciphertext), Err(Error::Context));
        let mut appended = ciphertext.clone();
        appended.push(0);
        assert_eq!(open(&secret, &appended), Err(Error::Context));
    }
}
