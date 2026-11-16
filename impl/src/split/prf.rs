//! Threshold PRF and single-use encryption keys for a split envelope.

use crate::{
    algebra::{
        decode_point, decode_scalar, encode_point, mul_generator, random_nonzero, Commitment,
    },
    hash::{hg, hq},
    Error, Result,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use k256::{
    elliptic_curve::{rand_core::CryptoRngCore, Group},
    ProjectivePoint, Scalar,
};
use sha2::Sha256;
use std::collections::BTreeSet;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Label {
    Hdr,
    Body { variant: u16, generation: u16 },
}

impl Label {
    /// Canonical PRF label: `hdr`, or `body` followed by two big-endian u16s.
    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Hdr => b"hdr".to_vec(),
            Self::Body {
                variant,
                generation,
            } => [
                b"body".as_slice(),
                &variant.to_be_bytes(),
                &generation.to_be_bytes(),
            ]
            .concat(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partial {
    pub index: u16,
    pub point: ProjectivePoint,
}

impl Partial {
    /// Include the index when the authenticated channel does not supply it.
    pub fn encode(&self) -> Result<[u8; 35]> {
        if self.index == 0 {
            return Err(Error::Parameters);
        }
        let mut bytes = [0; 35];
        bytes[..2].copy_from_slice(&self.index.to_be_bytes());
        bytes[2..].copy_from_slice(&encode_statement_point(self.point)?);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; 35] = bytes.try_into().map_err(|_| Error::Encoding)?;
        let index = u16::from_be_bytes([bytes[0], bytes[1]]);
        if index == 0 {
            return Err(Error::Parameters);
        }
        Ok(Self {
            index,
            point: if bytes[2..] == [0; 33] {
                ProjectivePoint::IDENTITY
            } else {
                decode_point(&bytes[2..])?
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub a1: ProjectivePoint,
    pub a2: ProjectivePoint,
    pub z: Scalar,
}

impl Proof {
    pub fn encode(&self) -> Result<[u8; 98]> {
        let mut bytes = [0; 98];
        bytes[..33].copy_from_slice(&encode_point(self.a1)?);
        bytes[33..66].copy_from_slice(&encode_point(self.a2)?);
        bytes[66..].copy_from_slice(&self.z.to_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; 98] = bytes.try_into().map_err(|_| Error::Encoding)?;
        Ok(Self {
            a1: decode_point(&bytes[..33])?,
            a2: decode_point(&bytes[33..66])?,
            z: decode_scalar(bytes[66..].try_into().map_err(|_| Error::Encoding)?)?,
        })
    }
}

/// An AEAD key that permits one encryption with the fixed all-zero nonce.
///
/// Imported or exported bytes must not be reused for another encryption.
///
/// ```compile_fail
/// use line_dealing::split::prf::OneShotKey;
/// let key = OneShotKey::from_bytes([7; 32]);
/// let first = key.encrypt(b"first", b"").unwrap();
/// let second = key.encrypt(b"second", b"").unwrap(); // key was consumed
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OneShotKey([u8; 32]);

impl OneShotKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn export_bytes(&self) -> [u8; 32] {
        self.0
    }
    pub fn encrypt(self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        ChaCha20Poly1305::new((&self.0).into())
            .encrypt(
                &Nonce::from([0; 12]),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Encoding)
    }
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        ChaCha20Poly1305::new((&self.0).into())
            .decrypt(
                &Nonce::from([0; 12]),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Proof)
    }
}

fn label_base(dd: &[u8; 32], label: Label) -> Result<ProjectivePoint> {
    hg("SL1/hc", &[dd.as_slice(), &label.encode()].concat())
}

pub fn evaluate(secret: Scalar, dd: &[u8; 32], label: Label) -> Result<ProjectivePoint> {
    let secret = Zeroizing::new(secret);
    if *secret == Scalar::ZERO {
        return Err(Error::Scalar);
    }
    Ok(label_base(dd, label)? * *secret)
}

pub fn partial(share: Scalar, index: u16, dd: &[u8; 32], label: Label) -> Result<Partial> {
    let share = Zeroizing::new(share);
    if index == 0 {
        return Err(Error::Parameters);
    }
    Ok(Partial {
        index,
        point: label_base(dd, label)? * *share,
    })
}

// Only PRF partials and their evaluated share commitments permit identity.
// Reserve the otherwise-invalid 33-byte all-zero encoding for that point.
fn encode_statement_point(point: ProjectivePoint) -> Result<[u8; 33]> {
    if point == ProjectivePoint::IDENTITY {
        Ok([0; 33])
    } else {
        encode_point(point)
    }
}

fn challenge(
    dd: &[u8; 32],
    label: Label,
    index: u16,
    ci: ProjectivePoint,
    hp: ProjectivePoint,
    yi: ProjectivePoint,
    proof: &Proof,
) -> Result<Scalar> {
    let mut transcript = Zeroizing::new(dd.to_vec());
    transcript.extend_from_slice(&label.encode());
    transcript.extend_from_slice(&index.to_be_bytes());
    transcript.extend_from_slice(&encode_point(ProjectivePoint::GENERATOR)?);
    transcript.extend_from_slice(&encode_statement_point(ci)?);
    transcript.extend_from_slice(&encode_point(hp)?);
    transcript.extend_from_slice(&encode_statement_point(yi)?);
    transcript.extend_from_slice(&encode_point(proof.a1)?);
    transcript.extend_from_slice(&encode_point(proof.a2)?);
    Ok(hq("SL1/dleq", &transcript))
}

pub fn prove(
    share: Scalar,
    index: u16,
    dd: &[u8; 32],
    label: Label,
    rng: &mut impl CryptoRngCore,
) -> Result<Proof> {
    let share = Zeroizing::new(share);
    if index == 0 {
        return Err(Error::Parameters);
    }
    let hp = label_base(dd, label)?;
    let nonce = Zeroizing::new(random_nonzero(rng));
    let mut proof = Proof {
        a1: mul_generator(*nonce),
        a2: hp * *nonce,
        z: Scalar::ZERO,
    };
    let c = challenge(
        dd,
        label,
        index,
        mul_generator(*share),
        hp,
        hp * *share,
        &proof,
    )?;
    proof.z = *nonce + c * *share;
    Ok(proof)
}

fn validate_commitment(commitment: &Commitment) -> Result<()> {
    if commitment.base != ProjectivePoint::GENERATOR
        || commitment.coefficients.len() >= usize::from(u16::MAX)
    {
        return Err(Error::Parameters);
    }
    for point in std::iter::once(&commitment.constant).chain(&commitment.coefficients) {
        if bool::from(point.is_identity()) {
            return Err(Error::Point);
        }
    }
    Ok(())
}

// Only the public node index controls these additions and doublings.
fn multiply_small(mut point: ProjectivePoint, mut index: u16) -> ProjectivePoint {
    let mut result = ProjectivePoint::IDENTITY;
    while index != 0 {
        if index & 1 != 0 {
            result += point;
        }
        point = point.double();
        index >>= 1;
    }
    result
}

fn evaluate_commitment(commitment: &Commitment, index: u16) -> Result<ProjectivePoint> {
    if index == 0 {
        return Err(Error::Parameters);
    }
    validate_commitment(commitment)?;
    let mut acc = ProjectivePoint::IDENTITY;
    for coefficient in commitment.coefficients.iter().rev() {
        acc = multiply_small(acc + coefficient, index);
    }
    Ok(acc + commitment.constant)
}

pub fn verify(
    commitment: &Commitment,
    dd: &[u8; 32],
    label: Label,
    partial: &Partial,
    proof: &Proof,
) -> Result<()> {
    let ci = evaluate_commitment(commitment, partial.index)?;
    let hp = label_base(dd, label)?;
    let c = challenge(dd, label, partial.index, ci, hp, partial.point, proof)?;
    if mul_generator(proof.z) != proof.a1 + ci * c || hp * proof.z != proof.a2 + partial.point * c {
        return Err(Error::Proof);
    }
    Ok(())
}

fn validate_indices(partials: &[Partial], threshold: usize) -> Result<()> {
    if threshold == 0 || threshold > partials.len() {
        return Err(Error::Threshold);
    }
    let mut seen = BTreeSet::new();
    for partial in partials {
        if partial.index == 0 || !seen.insert(partial.index) {
            return Err(Error::Threshold);
        }
    }
    Ok(())
}

/// Combine the first `threshold` partials; all supplied indices must be unique and nonzero.
/// The point multiplications use k256's constant-time scalar multiplication.
pub fn combine(partials: &[Partial], threshold: usize) -> Result<ProjectivePoint> {
    validate_indices(partials, threshold)?;
    let selected = &partials[..threshold];
    let indices: Vec<_> = selected.iter().map(|partial| partial.index).collect();
    let weights = super::group::lagrange::<super::group::Secp>(&indices)?;
    Ok(selected
        .iter()
        .zip(weights)
        .fold(ProjectivePoint::IDENTITY, |sum, (partial, weight)| {
            sum + partial.point * weight
        }))
}

/// HKDF-SHA256 with salt `SL1/kdf` and info `SL1/` followed by `label`.
pub fn derive_key(ikm: &[u8], label: &[u8]) -> Result<OneShotKey> {
    let mut key = OneShotKey::from_bytes([0; 32]);
    Hkdf::<Sha256>::new(Some(b"SL1/kdf"), ikm)
        .expand(&[b"SL1/".as_slice(), label].concat(), &mut key.0)
        .map_err(|_| Error::Parameters)?;
    Ok(key)
}

pub fn header_key(point: ProjectivePoint) -> Result<OneShotKey> {
    let point = Zeroizing::new(point);
    let encoded = Zeroizing::new(encode_point(*point)?);
    derive_key(encoded.as_ref(), b"hdr")
}

/// Independent one-message keys from the same combined header PRF point.
pub fn header_keys(point: ProjectivePoint) -> Result<(OneShotKey, OneShotKey)> {
    let point = Zeroizing::new(point);
    let encoded = Zeroizing::new(encode_point(*point)?);
    Ok((
        derive_key(encoded.as_ref(), b"hdr")?,
        derive_key(encoded.as_ref(), b"layout")?,
    ))
}

pub fn body_key(point: ProjectivePoint) -> Result<OneShotKey> {
    let point = Zeroizing::new(point);
    let encoded = Zeroizing::new(encode_point(*point)?);
    derive_key(encoded.as_ref(), b"body")
}

pub fn final_key(point: ProjectivePoint) -> Result<OneShotKey> {
    let point = Zeroizing::new(point);
    let encoded = Zeroizing::new(encode_point(*point)?);
    derive_key(encoded.as_ref(), b"final")
}

pub fn contribution_key(point: ProjectivePoint) -> Result<(Scalar, ProjectivePoint)> {
    let point = Zeroizing::new(point);
    let encoded = Zeroizing::new(encode_point(*point)?);
    let mut input = Zeroizing::new(Vec::with_capacity(36));
    input.extend_from_slice(encoded.as_ref());
    input.extend_from_slice(b"ctb");
    let y = Zeroizing::new(hq("SL1/ctb", &input));
    if *y == Scalar::ZERO {
        return Err(Error::Scalar);
    }
    Ok((*y, mul_generator(*y)))
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenOutcome<T = Vec<u8>> {
    Opened { plaintext: T, rejected: Vec<u16> },
    InsufficientValid { valid: usize, rejected: Vec<u16> },
    DealerFault { rejected: Vec<u16> },
}

pub fn open_with_fallback(
    commitment: &Commitment,
    dd: &[u8; 32],
    label: Label,
    partials: &[Partial],
    ciphertext: &[u8],
    aad: &[u8],
    request_proof: impl FnMut(&Partial) -> Option<Proof>,
) -> Result<OpenOutcome> {
    combine_with_fallback(
        commitment,
        dd,
        label,
        partials,
        |point| {
            let key = match label {
                Label::Hdr => header_key(point)?,
                Label::Body { .. } => body_key(point)?,
            };
            key.decrypt(ciphertext, aad)
        },
        request_proof,
    )
}

/// Try the combined point with an authenticated opener before requesting proofs.
/// The opener authenticates the fixed layout before reading variable regions.
/// An opener error after threshold valid proofs reports dealer fault.
pub fn combine_with_fallback<T>(
    commitment: &Commitment,
    dd: &[u8; 32],
    label: Label,
    partials: &[Partial],
    mut open: impl FnMut(ProjectivePoint) -> Result<T>,
    mut request_proof: impl FnMut(&Partial) -> Option<Proof>,
) -> Result<OpenOutcome<T>> {
    validate_commitment(commitment)?;
    let threshold = commitment.coefficients.len() + 1;
    validate_indices(partials, threshold)?;
    let mut try_open = |parts: &[Partial]| open(combine(parts, threshold)?);
    if let Ok(plaintext) = try_open(partials) {
        return Ok(OpenOutcome::Opened {
            plaintext,
            rejected: vec![],
        });
    }
    let mut valid = Vec::new();
    let mut rejected = Vec::new();
    for partial in partials {
        match request_proof(partial) {
            Some(proof) if verify(commitment, dd, label, partial, &proof).is_ok() => {
                valid.push(*partial)
            }
            _ => rejected.push(partial.index),
        }
    }
    if valid.len() < threshold {
        return Ok(OpenOutcome::InsufficientValid {
            valid: valid.len(),
            rejected,
        });
    }
    Ok(match try_open(&valid) {
        Ok(plaintext) => OpenOutcome::Opened {
            plaintext,
            rejected,
        },
        Err(_) => OpenOutcome::DealerFault { rejected },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algebra::{inverse, Polynomial},
        experiment::SeededRng,
        hash::hq,
        Error,
    };

    const DD: [u8; 32] = [42; 32];
    const BODY: Label = Label::Body {
        variant: 2,
        generation: 1,
    };

    fn fixture(label: Label) -> (Polynomial, Commitment, Vec<Partial>, Vec<Proof>) {
        let poly = Polynomial::from_coefficients(vec![
            Scalar::from(17u64),
            Scalar::from(31u64),
            Scalar::from(7u64),
        ])
        .unwrap();
        let commitment = poly.commit(ProjectivePoint::GENERATOR).unwrap();
        let mut rng = SeededRng::new(77);
        let partials = (1..=5)
            .map(|i| partial(poly.evaluate(i).unwrap(), i, &DD, label).unwrap())
            .collect();
        let proofs = (1..=5)
            .map(|i| prove(poly.evaluate(i).unwrap(), i, &DD, label, &mut rng).unwrap())
            .collect();
        (poly, commitment, partials, proofs)
    }

    #[test]
    fn threshold_subsets_match_dealer_and_separate_contexts() {
        let (poly, _, parts, _) = fixture(BODY);
        let expected = evaluate(poly.constant(), &DD, BODY).unwrap();
        assert_eq!(combine(&parts[..3], 3).unwrap(), expected);
        assert_eq!(
            combine(&[parts[4], parts[1], parts[3]], 3).unwrap(),
            expected
        );
        assert_ne!(
            evaluate(poly.constant(), &DD, Label::Hdr).unwrap(),
            expected
        );
        assert_ne!(
            evaluate(poly.constant(), &[43; 32], BODY).unwrap(),
            expected
        );
        for label in [
            Label::Body {
                variant: 3,
                generation: 1,
            },
            Label::Body {
                variant: 2,
                generation: 2,
            },
            Label::Body {
                variant: 2,
                generation: 0,
            },
        ] {
            assert_ne!(evaluate(poly.constant(), &DD, label).unwrap(), expected);
        }
        assert_ne!(combine(&parts[..2], 2).unwrap(), expected);
    }

    #[test]
    fn combine_rejects_bad_threshold_and_all_duplicate_or_zero_indices() {
        let (_, _, parts, _) = fixture(BODY);
        for threshold in [0, 4] {
            assert_eq!(combine(&parts[..3], threshold), Err(Error::Threshold));
        }
        assert_eq!(
            combine(&[parts[0], parts[0], parts[1]], 3),
            Err(Error::Threshold)
        );
        assert_eq!(
            combine(&[parts[0], parts[1], parts[2], parts[0]], 3),
            Err(Error::Threshold)
        );
        let mut bad = parts.clone();
        bad[4].index = 0;
        assert_eq!(combine(&bad, 3), Err(Error::Threshold));
        assert!(partial(Scalar::ONE, 0, &DD, BODY).is_err());
    }

    #[test]
    fn full_statement_proofs_bind_every_context_component() {
        let (_, commitment, parts, proofs) = fixture(BODY);
        for (part, proof) in parts.iter().zip(&proofs) {
            verify(&commitment, &DD, BODY, part, proof).unwrap();
        }
        assert!(verify(&commitment, &[43; 32], BODY, &parts[0], &proofs[0]).is_err());
        assert!(verify(&commitment, &DD, Label::Hdr, &parts[0], &proofs[0]).is_err());
        assert!(verify(&commitment, &DD, BODY, &parts[1], &proofs[0]).is_err());
        let mut changed = parts[0];
        changed.point += ProjectivePoint::GENERATOR;
        assert!(verify(&commitment, &DD, BODY, &changed, &proofs[0]).is_err());
        let mut changed = commitment.clone();
        changed.constant += ProjectivePoint::GENERATOR;
        assert!(verify(&changed, &DD, BODY, &parts[0], &proofs[0]).is_err());
        let mut changed = proofs[0];
        changed.a2 += ProjectivePoint::GENERATOR;
        assert!(verify(&commitment, &DD, BODY, &parts[0], &changed).is_err());
        let mut changed = proofs[0];
        changed.a1 += ProjectivePoint::GENERATOR;
        assert!(verify(&commitment, &DD, BODY, &parts[0], &changed).is_err());
        let mut changed = proofs[0];
        changed.z += Scalar::ONE;
        assert!(verify(&commitment, &DD, BODY, &parts[0], &changed).is_err());
        let mut changed = commitment.clone();
        changed.base = ProjectivePoint::GENERATOR.double();
        assert!(verify(&changed, &DD, BODY, &parts[0], &proofs[0]).is_err());
    }

    #[test]
    fn small_index_horner_matches_scalar_evaluation_at_boundary_indices() {
        let (_, commitment, _, _) = fixture(BODY);
        for index in [1, 5, 9, 255, 256, 32768, u16::MAX] {
            assert_eq!(
                evaluate_commitment(&commitment, index).unwrap(),
                commitment.evaluate(index).unwrap()
            );
        }
        assert!(evaluate_commitment(&commitment, 0).is_err());
    }

    #[test]
    fn seven_of_nine_partial_subsets_match_the_dealer() {
        let mut rng = SeededRng::new(9);
        let poly = Polynomial::random(Scalar::from(73u64), 7, &mut rng).unwrap();
        let commitment = poly.commit(ProjectivePoint::GENERATOR).unwrap();
        let parts: Vec<_> = (1..=9)
            .map(|i| {
                let share = poly.evaluate(i).unwrap();
                let part = partial(share, i, &DD, BODY).unwrap();
                let proof = prove(share, i, &DD, BODY, &mut rng).unwrap();
                verify(&commitment, &DD, BODY, &part, &proof).unwrap();
                part
            })
            .collect();
        let expected = evaluate(poly.constant(), &DD, BODY).unwrap();
        assert_eq!(combine(&parts[..7], 7).unwrap(), expected);
        assert_eq!(combine(&parts[2..], 7).unwrap(), expected);
        assert_eq!(
            combine(
                &[parts[8], parts[0], parts[7], parts[2], parts[6], parts[3], parts[5]],
                7
            )
            .unwrap(),
            expected
        );
    }

    #[test]
    fn forged_partial_passes_legacy_challenge_but_fails_full_statement() {
        let (poly, commitment, mut parts, mut proofs) = fixture(Label::Hdr);
        let hp = evaluate(Scalar::ONE, &DD, Label::Hdr).unwrap();
        let share = poly.evaluate(1).unwrap();
        let r = Scalar::from(19u64);
        let u = Scalar::from(23u64);
        let a1 = ProjectivePoint::GENERATOR * r;
        let a2 = hp * u;
        // Legacy transcript deliberately omits the statement, particularly Y_i.
        let mut transcript = DD.to_vec();
        transcript.extend_from_slice(b"hdr");
        transcript.extend_from_slice(&1u16.to_be_bytes());
        transcript.extend_from_slice(&crate::algebra::encode_point(a1).unwrap());
        transcript.extend_from_slice(&crate::algebra::encode_point(a2).unwrap());
        let challenge = hq("SL1/dleq", &transcript);
        let proof = Proof {
            a1,
            a2,
            z: r + challenge * share,
        };
        let forged = Partial {
            index: 1,
            point: hp * (share + (r - u) * inverse(challenge).unwrap()),
        };
        assert_ne!(forged.point, parts[0].point);
        assert_eq!(
            ProjectivePoint::GENERATOR * proof.z,
            a1 + commitment.evaluate(1).unwrap() * challenge
        );
        assert_eq!(hp * proof.z, a2 + forged.point * challenge);
        assert!(verify(&commitment, &DD, Label::Hdr, &forged, &proof).is_err());
        parts[0] = forged;
        proofs[0] = proof;
        let ciphertext = header_key(evaluate(poly.constant(), &DD, Label::Hdr).unwrap())
            .unwrap()
            .encrypt(b"honest dealer", b"")
            .unwrap();
        let result = open_with_fallback(
            &commitment,
            &DD,
            Label::Hdr,
            &parts,
            &ciphertext,
            b"",
            |p| Some(proofs[usize::from(p.index - 1)]),
        )
        .unwrap();
        assert_eq!(
            result,
            OpenOutcome::Opened {
                plaintext: b"honest dealer".to_vec(),
                rejected: vec![1]
            }
        );
    }

    #[test]
    fn derived_keys_separate_roles_and_authenticate_ciphertext_and_aad() {
        let z = evaluate(Scalar::from(17u64), &DD, BODY).unwrap();
        let h = header_key(z).unwrap().export_bytes();
        let b = body_key(z).unwrap().export_bytes();
        let f = final_key(z).unwrap().export_bytes();
        assert_ne!(h, b);
        assert_ne!(h, f);
        assert_ne!(b, f);
        let (y, p) = contribution_key(z).unwrap();
        assert_eq!(p, ProjectivePoint::GENERATOR * y);
        let ciphertext = OneShotKey::from_bytes(b)
            .encrypt(b"payload", b"context")
            .unwrap();
        let decryptor = OneShotKey::from_bytes(b);
        assert_eq!(ciphertext.len(), 7 + 16);
        assert_eq!(
            decryptor.decrypt(&ciphertext, b"context").unwrap(),
            b"payload"
        );
        assert!(decryptor.decrypt(&ciphertext, b"other").is_err());
        assert!(OneShotKey::from_bytes(h)
            .decrypt(&ciphertext, b"context")
            .is_err());
        let mut changed = ciphertext;
        changed[0] ^= 1;
        assert!(decryptor.decrypt(&changed, b"context").is_err());
        assert!(decryptor.decrypt(&[0; 15], b"context").is_err());
    }

    #[test]
    fn optimistic_open_does_not_request_proofs() {
        let (poly, commitment, parts, _) = fixture(Label::Hdr);
        let ciphertext = header_key(evaluate(poly.constant(), &DD, Label::Hdr).unwrap())
            .unwrap()
            .encrypt(b"header", b"")
            .unwrap();
        let result = open_with_fallback(
            &commitment,
            &DD,
            Label::Hdr,
            &parts,
            &ciphertext,
            b"",
            |_| panic!("proofs must remain lazy"),
        )
        .unwrap();
        assert_eq!(
            result,
            OpenOutcome::Opened {
                plaintext: b"header".to_vec(),
                rejected: vec![]
            }
        );
    }

    #[test]
    fn fallback_drops_bad_partials_and_recombines() {
        let (poly, commitment, mut parts, proofs) = fixture(BODY);
        let ciphertext = body_key(evaluate(poly.constant(), &DD, BODY).unwrap())
            .unwrap()
            .encrypt(b"body", b"dd")
            .unwrap();
        parts[0].point += ProjectivePoint::GENERATOR;
        let mut requested = 0;
        let result = open_with_fallback(&commitment, &DD, BODY, &parts, &ciphertext, b"dd", |p| {
            requested += 1;
            Some(proofs[usize::from(p.index - 1)])
        })
        .unwrap();
        assert_eq!(requested, 5);
        assert_eq!(
            result,
            OpenOutcome::Opened {
                plaintext: b"body".to_vec(),
                rejected: vec![1]
            }
        );
    }

    #[test]
    fn fallback_distinguishes_missing_proofs_from_dealer_fault() {
        let (_, commitment, parts, proofs) = fixture(BODY);
        let result = open_with_fallback(&commitment, &DD, BODY, &parts, &[0; 16], b"", |p| {
            if p.index < 3 {
                Some(proofs[usize::from(p.index - 1)])
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(
            result,
            OpenOutcome::InsufficientValid {
                valid: 2,
                rejected: vec![3, 4, 5]
            }
        );
        let result = open_with_fallback(&commitment, &DD, BODY, &parts, &[0; 16], b"", |p| {
            Some(proofs[usize::from(p.index - 1)])
        })
        .unwrap();
        assert_eq!(result, OpenOutcome::DealerFault { rejected: vec![] });
    }

    #[test]
    fn wire_codecs_roundtrip_and_reject_noncanonical_encodings() {
        let (_, _, parts, proofs) = fixture(BODY);
        let part = parts[0].encode().unwrap();
        let proof = proofs[0].encode().unwrap();
        assert_eq!(part.len(), 35);
        assert_eq!(proof.len(), 98);
        assert_eq!(Partial::decode(&part).unwrap(), parts[0]);
        assert_eq!(Proof::decode(&proof).unwrap(), proofs[0]);
        assert!(Partial::decode(&part[..34]).is_err());
        assert!(Partial::decode(&[part.as_slice(), &[0]].concat()).is_err());
        assert!(Proof::decode(&proof[..97]).is_err());
        assert!(Proof::decode(&[proof.as_slice(), &[0]].concat()).is_err());
        let mut bad = part;
        bad[..2].fill(0);
        assert!(Partial::decode(&bad).is_err());
        let mut bad = part;
        bad[2] = 4;
        assert!(Partial::decode(&bad).is_err());
        let mut bad = part;
        bad[3..].fill(255);
        assert!(Partial::decode(&bad).is_err());
        for offset in [0, 33] {
            let mut bad = proof;
            bad[offset] = 0;
            assert!(Proof::decode(&bad).is_err());
            let mut bad = proof;
            bad[offset + 1..offset + 33].fill(255);
            assert!(Proof::decode(&bad).is_err());
        }
        let mut bad = proof;
        bad[66..].fill(255);
        assert!(Proof::decode(&bad).is_err());
        let mut invalid = parts[0];
        invalid.index = 0;
        assert!(invalid.encode().is_err());
        invalid.index = 1;
        invalid.point = ProjectivePoint::IDENTITY;
        assert_eq!(
            Partial::decode(&invalid.encode().unwrap()).unwrap(),
            invalid
        );
        let mut invalid = proofs[0];
        invalid.a1 = ProjectivePoint::IDENTITY;
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn generic_fallback_opens_an_authenticated_layout_without_public_length() {
        let (poly, commitment, mut parts, proofs) = fixture(Label::Hdr);
        let (header, layout) =
            header_keys(evaluate(poly.constant(), &DD, Label::Hdr).unwrap()).unwrap();
        let ciphertext = header.encrypt(b"header", b"context").unwrap();
        let expected_end = ciphertext.len();
        let mut frame_tail = layout
            .encrypt(&(expected_end as u16).to_be_bytes(), b"context")
            .unwrap();
        frame_tail.extend_from_slice(&ciphertext);
        frame_tail.extend_from_slice(&[91; 20]);
        parts[0].point += ProjectivePoint::GENERATOR;
        let mut attempts = 0;
        let result = combine_with_fallback(
            &commitment,
            &DD,
            Label::Hdr,
            &parts,
            |point| {
                attempts += 1;
                let (key, layout_key) = header_keys(point)?;
                let lengths = layout_key.decrypt(&frame_tail[..18], b"context")?;
                let end =
                    u16::from_be_bytes(lengths.try_into().map_err(|_| Error::Encoding)?) as usize;
                let region = frame_tail.get(18..18 + end).ok_or(Error::Encoding)?;
                Ok((key.decrypt(region, b"context")?, end))
            },
            |part| Some(proofs[usize::from(part.index - 1)]),
        )
        .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(
            result,
            OpenOutcome::Opened {
                plaintext: (b"header".to_vec(), expected_end),
                rejected: vec![1]
            }
        );
    }

    #[test]
    fn honest_zero_share_proves_roundtrips_and_combines() {
        let a = Scalar::from(17u64);
        let poly = Polynomial::from_coefficients(vec![a, -a]).unwrap();
        let commitment = poly.commit(ProjectivePoint::GENERATOR).unwrap();
        assert_eq!(poly.evaluate(1).unwrap(), Scalar::ZERO);
        assert!(commitment.verify(1, Scalar::ZERO));
        let zero = partial(Scalar::ZERO, 1, &DD, BODY).unwrap();
        assert_eq!(zero.point, ProjectivePoint::IDENTITY);
        let mut rng = SeededRng::new(211);
        let proof = prove(Scalar::ZERO, 1, &DD, BODY, &mut rng).unwrap();
        verify(&commitment, &DD, BODY, &zero, &proof).unwrap();
        let encoded = zero.encode().unwrap();
        assert_eq!(&encoded[..2], &1u16.to_be_bytes());
        assert_eq!(&encoded[2..], &[0; 33]);
        assert_eq!(Partial::decode(&encoded).unwrap(), zero);
        assert_eq!(Proof::decode(&proof.encode().unwrap()).unwrap(), proof);
        let second = partial(poly.evaluate(2).unwrap(), 2, &DD, BODY).unwrap();
        assert_eq!(
            combine(&[zero, second], 2).unwrap(),
            evaluate(a, &DD, BODY).unwrap()
        );
        let mut noncanonical = encoded;
        noncanonical[34] = 1;
        assert!(Partial::decode(&noncanonical).is_err());
        let mut noncanonical_proof = proof.encode().unwrap();
        noncanonical_proof[..33].fill(0);
        assert!(Proof::decode(&noncanonical_proof).is_err());
        let mut bad = proof;
        bad.a1 = ProjectivePoint::IDENTITY;
        assert!(verify(&commitment, &DD, BODY, &zero, &bad).is_err());
        let mut bad_commitment = commitment.clone();
        bad_commitment.coefficients[0] = ProjectivePoint::IDENTITY;
        assert!(verify(&bad_commitment, &DD, BODY, &zero, &proof).is_err());
        let mut bad_partial = zero;
        bad_partial.point = ProjectivePoint::GENERATOR;
        assert!(verify(&commitment, &DD, BODY, &bad_partial, &proof).is_err());
        let third_share = poly.evaluate(3).unwrap();
        let third = partial(third_share, 3, &DD, BODY).unwrap();
        let proofs = [
            proof,
            prove(poly.evaluate(2).unwrap(), 2, &DD, BODY, &mut rng).unwrap(),
            prove(third_share, 3, &DD, BODY, &mut rng).unwrap(),
        ];
        let mut bad_second = second;
        bad_second.point += ProjectivePoint::GENERATOR;
        let ciphertext = body_key(evaluate(a, &DD, BODY).unwrap())
            .unwrap()
            .encrypt(b"zero share", b"")
            .unwrap();
        let opened = open_with_fallback(
            &commitment,
            &DD,
            BODY,
            &[zero, bad_second, third],
            &ciphertext,
            b"",
            |part| Some(proofs[usize::from(part.index - 1)]),
        )
        .unwrap();
        assert_eq!(
            opened,
            OpenOutcome::Opened {
                plaintext: b"zero share".to_vec(),
                rejected: vec![2]
            }
        );
    }
}
