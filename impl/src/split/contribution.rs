//! Actor contributions sealed to one variant body of an outer dealing.

use super::prf::{derive_key, OneShotKey};
use crate::{
    algebra::{decode_point, decode_scalar, encode_point, mul_generator, random_nonzero},
    Error, Result,
};
use k256::{
    elliptic_curve::{rand_core::CryptoRngCore, Group},
    ProjectivePoint, Scalar,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContributionContext {
    pub dd: [u8; 32],
    pub position: u8,
    pub variant: u8,
    pub generation: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedContribution {
    ephemeral: [u8; 33],
    ephemeral_point: ProjectivePoint,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContributionOpenError {
    /// The published contribution key does not match the released PRF secret.
    InitiatorKeyMismatch,
    Invalid(Error),
}

impl From<Error> for ContributionOpenError {
    fn from(error: Error) -> Self {
        Self::Invalid(error)
    }
}

impl core::fmt::Display for ContributionOpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InitiatorKeyMismatch => f.write_str("initiator contribution key mismatch"),
            Self::Invalid(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ContributionOpenError {}

impl SealedContribution {
    /// Seal canonical signing scalars for suite 1 (ECDSA), 2 (BIP340), or 3 (Ed25519).
    /// The carrier stores integers. All suites use the crate's big-endian wire form.
    pub fn seal_for_suite(
        suite: u8,
        public_key: ProjectivePoint,
        context: &ContributionContext,
        scalars: &[Scalar],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        validate_suite_scalars(suite, scalars)?;
        Self::seal(public_key, context, scalars, rng)
    }

    /// Authenticate the contribution and enforce the signing suite's scalar order.
    /// Use this method for Ed25519 before converting the integer carrier to dalek.
    pub fn open_for_suite(
        &self,
        suite: u8,
        secret_y: Scalar,
        advertised_public_key: ProjectivePoint,
        context: &ContributionContext,
        inputs: usize,
    ) -> core::result::Result<Vec<Scalar>, ContributionOpenError> {
        validate_suite_scalars(suite, &[])?;
        let mut scalars =
            Zeroizing::new(self.open(secret_y, advertised_public_key, context, inputs)?);
        validate_suite_scalars(suite, &scalars)?;
        Ok(core::mem::take(&mut *scalars))
    }

    /// Seal one body's scalars with a fresh nonzero ephemeral scalar.
    pub fn seal(
        public_key: ProjectivePoint,
        context: &ContributionContext,
        scalars: &[Scalar],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if bool::from(public_key.is_identity()) {
            return Err(Error::Point);
        }
        let len = Self::encoded_len(scalars.len())?;
        let e = Zeroizing::new(random_nonzero(rng));
        let ephemeral_point = mul_generator(*e);
        let ephemeral = encode_point(ephemeral_point)?;
        let key = sealing_key(public_key * *e, &ephemeral, context)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(len - 49));
        for scalar in scalars {
            plaintext.extend_from_slice(&scalar.to_bytes());
        }
        let ciphertext = key.encrypt(&plaintext, b"")?;
        Ok(Self {
            ephemeral,
            ephemeral_point,
            ciphertext,
        })
    }

    /// Check the initiator's advertised key before attempting decryption.
    pub fn open(
        &self,
        secret_y: Scalar,
        advertised_public_key: ProjectivePoint,
        context: &ContributionContext,
        inputs: usize,
    ) -> core::result::Result<Vec<Scalar>, ContributionOpenError> {
        if mul_generator(secret_y) != advertised_public_key {
            return Err(ContributionOpenError::InitiatorKeyMismatch);
        }
        if bool::from(advertised_public_key.is_identity()) {
            return Err(Error::Point.into());
        }
        self.validate_inputs(inputs)?;
        let shared = self.ephemeral_point * secret_y;
        let key = sealing_key(shared, &self.ephemeral, context)?;
        let plaintext = Zeroizing::new(key.decrypt(&self.ciphertext, b"")?);
        let mut scalars = Zeroizing::new(Vec::with_capacity(inputs));
        for bytes in plaintext.as_chunks::<32>().0 {
            scalars.push(decode_scalar(bytes)?);
        }
        Ok(core::mem::take(&mut *scalars))
    }

    pub fn encoded_len(inputs: usize) -> Result<usize> {
        if inputs == 0 {
            return Err(Error::Parameters);
        }
        inputs
            .checked_mul(32)
            .and_then(|len| len.checked_add(49))
            .ok_or(Error::Encoding)
    }

    // The private point was validated at decode (or generated during sealing).
    // Header validation needs only the expected number of scalar carriers.
    pub(crate) fn validate_inputs(&self, inputs: usize) -> Result<()> {
        if self.ciphertext.len() != Self::encoded_len(inputs)? - 33 {
            return Err(Error::Encoding);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33 + self.ciphertext.len());
        bytes.extend_from_slice(&self.ephemeral);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn decode(bytes: &[u8], inputs: usize) -> Result<Self> {
        if bytes.len() != Self::encoded_len(inputs)? {
            return Err(Error::Encoding);
        }
        let ephemeral: [u8; 33] = bytes[..33].try_into().map_err(|_| Error::Encoding)?;
        let ephemeral_point = decode_point(&ephemeral)?;
        Ok(Self {
            ephemeral,
            ephemeral_point,
            ciphertext: bytes[33..].to_vec(),
        })
    }
}

fn validate_suite_scalars(suite: u8, scalars: &[Scalar]) -> Result<()> {
    match suite {
        1 | 2 => Ok(()),
        3 => {
            for scalar in scalars {
                let bytes = Zeroizing::new(<[u8; 32]>::from(scalar.to_bytes()));
                let _canonical = Zeroizing::new(crate::ed25519::decode_scalar(&bytes)?);
            }
            Ok(())
        }
        _ => Err(Error::Parameters),
    }
}

fn sealing_key(
    shared: ProjectivePoint,
    ephemeral: &[u8; 33],
    context: &ContributionContext,
) -> Result<OneShotKey> {
    let mut ikm = Zeroizing::new([0u8; 101]);
    ikm[..33].copy_from_slice(&encode_point(shared)?);
    ikm[33..66].copy_from_slice(ephemeral);
    ikm[66..98].copy_from_slice(&context.dd);
    ikm[98..].copy_from_slice(&[context.position, context.variant, context.generation]);
    derive_key(ikm.as_ref(), b"contribution")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::SeededRng;

    fn edwards_max_scalar() -> Scalar {
        decode_scalar(&crate::ed25519::encode_scalar(
            -curve25519_dalek::Scalar::ONE,
        ))
        .unwrap()
    }

    #[test]
    fn suite_wrappers_roundtrip_canonical_scalar_integers() {
        let y = Scalar::from(17u64);
        let public = ProjectivePoint::GENERATOR * y;
        let scalars = [Scalar::ZERO, Scalar::ONE, edwards_max_scalar()];
        for suite in 1..=3 {
            let sealed = SealedContribution::seal_for_suite(
                suite,
                public,
                &context(),
                &scalars,
                &mut SeededRng::new(51),
            )
            .unwrap();
            assert_eq!(
                sealed
                    .open_for_suite(suite, y, public, &context(), scalars.len())
                    .unwrap(),
                scalars
            );
            assert_eq!(sealed.encode().len(), 49 + 32 * scalars.len());
            assert_eq!(
                crate::ed25519::decode_scalar(&scalars[2].to_bytes().into()).unwrap(),
                -curve25519_dalek::Scalar::ONE
            );
        }
    }

    #[test]
    fn suite_wrappers_reject_edwards_order_and_larger_integers() {
        let y = Scalar::from(17u64);
        let public = ProjectivePoint::GENERATOR * y;
        for scalar in [
            edwards_max_scalar() + Scalar::ONE,
            edwards_max_scalar() + Scalar::from(2u64),
            -Scalar::ONE,
        ] {
            assert_eq!(
                SealedContribution::seal_for_suite(
                    3,
                    public,
                    &context(),
                    &[scalar],
                    &mut SeededRng::new(52)
                ),
                Err(Error::Scalar)
            );
            // A malicious sender can authenticate a noncanonical integer.
            let sealed =
                SealedContribution::seal(public, &context(), &[scalar], &mut SeededRng::new(53))
                    .unwrap();
            assert_eq!(
                sealed.open_for_suite(3, y, public, &context(), 1),
                Err(ContributionOpenError::Invalid(Error::Scalar))
            );
            for suite in [1, 2] {
                assert_eq!(
                    sealed
                        .open_for_suite(suite, y, public, &context(), 1)
                        .unwrap(),
                    vec![scalar]
                );
            }
        }
    }

    #[test]
    fn suite_wrappers_reject_unknown_suites() {
        let (y, public, scalars, sealed) = fixture(1);
        for suite in [0, 4, 255] {
            assert_eq!(
                SealedContribution::seal_for_suite(
                    suite,
                    public,
                    &context(),
                    &scalars,
                    &mut SeededRng::new(54)
                ),
                Err(Error::Parameters)
            );
            assert_eq!(
                sealed.open_for_suite(suite, y, public, &context(), 1),
                Err(ContributionOpenError::Invalid(Error::Parameters))
            );
        }
    }

    fn context() -> ContributionContext {
        ContributionContext {
            dd: [0x42; 32],
            position: 2,
            variant: 3,
            generation: 1,
        }
    }

    fn fixture(inputs: usize) -> (Scalar, ProjectivePoint, Vec<Scalar>, SealedContribution) {
        let y = Scalar::from(17u64);
        let public = ProjectivePoint::GENERATOR * y;
        let scalars = (0..inputs)
            .map(|i| Scalar::from(i as u64))
            .collect::<Vec<_>>();
        let sealed =
            SealedContribution::seal(public, &context(), &scalars, &mut SeededRng::new(9)).unwrap();
        (y, public, scalars, sealed)
    }

    #[test]
    fn seal_open_and_exact_wire_round_trip() {
        for inputs in [1, 2, 8] {
            let (y, public, scalars, sealed) = fixture(inputs);
            let wire = sealed.encode();
            assert_eq!(wire.len(), 49 + 32 * inputs);
            assert_eq!(SealedContribution::encoded_len(inputs).unwrap(), wire.len());
            let decoded = SealedContribution::decode(&wire, inputs).unwrap();
            assert_eq!(decoded, sealed);
            assert_eq!(
                decoded.open(y, public, &context(), inputs).unwrap(),
                scalars
            );
        }
    }

    #[test]
    fn changed_context_cannot_open_contribution() {
        let (y, public, _, sealed) = fixture(2);
        let mut changed = [context(); 4];
        changed[0].dd[0] ^= 1;
        changed[1].position += 1;
        changed[2].variant += 1;
        changed[3].generation += 1;
        for context in changed {
            assert!(matches!(
                sealed.open(y, public, &context, 2),
                Err(ContributionOpenError::Invalid(_))
            ));
        }
    }

    #[test]
    fn initiator_key_mismatch_precedes_ciphertext_validation() {
        let (y, public, _, mut sealed) = fixture(1);
        sealed.ciphertext.clear();
        assert_eq!(
            sealed.open(y + Scalar::ONE, public, &context(), 1),
            Err(ContributionOpenError::InitiatorKeyMismatch)
        );
        assert_eq!(
            sealed.open(y, public + ProjectivePoint::GENERATOR, &context(), 1),
            Err(ContributionOpenError::InitiatorKeyMismatch)
        );
    }

    #[test]
    fn rejects_truncation_trailing_bytes_wrong_counts_and_bad_points() {
        let (y, public, _, sealed) = fixture(2);
        let wire = sealed.encode();
        for length in [0, 32, 33, 49, wire.len() - 1] {
            assert!(SealedContribution::decode(&wire[..length], 2).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(SealedContribution::decode(&trailing, 2).is_err());
        assert!(SealedContribution::decode(&wire, 1).is_err());
        assert!(sealed.open(y, public, &context(), 1).is_err());
        let mut bad_point = wire;
        bad_point[..33].fill(0);
        assert_eq!(SealedContribution::decode(&bad_point, 2), Err(Error::Point));
        assert!(SealedContribution::encoded_len(usize::MAX).is_err());
        assert!(SealedContribution::encoded_len(0).is_err());
    }

    #[test]
    fn tampered_ephemeral_ciphertext_and_tag_fail() {
        let (y, public, _, sealed) = fixture(2);
        for index in [33, sealed.encode().len() - 1] {
            let mut wire = sealed.encode();
            wire[index] ^= 1;
            let tampered = SealedContribution::decode(&wire, 2).unwrap();
            assert!(tampered.open(y, public, &context(), 2).is_err());
        }
        let mut wire = sealed.encode();
        wire[0] ^= 1;
        let tampered = SealedContribution::decode(&wire, 2).unwrap();
        assert!(tampered.open(y, public, &context(), 2).is_err());
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral() {
        let mut rng = SeededRng::new(19);
        let public = ProjectivePoint::GENERATOR * Scalar::from(17u64);
        let first = SealedContribution::seal(public, &context(), &[Scalar::ONE], &mut rng).unwrap();
        let second =
            SealedContribution::seal(public, &context(), &[Scalar::ONE], &mut rng).unwrap();
        assert_ne!(first.ephemeral, second.ephemeral);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn identity_public_key_and_empty_contribution_are_rejected() {
        let mut rng = SeededRng::new(29);
        assert_eq!(
            SealedContribution::seal(
                ProjectivePoint::IDENTITY,
                &context(),
                &[Scalar::ONE],
                &mut rng
            ),
            Err(Error::Point)
        );
        assert!(
            SealedContribution::seal(ProjectivePoint::GENERATOR, &context(), &[], &mut rng)
                .is_err()
        );
    }

    #[test]
    fn independently_sealed_plaintext_uses_exact_kdf_and_strict_scalar_decode() {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };
        use hkdf::Hkdf;
        use sha2::Sha256;

        let y = Scalar::from(17u64);
        let e = Scalar::from(5u64);
        let public = ProjectivePoint::GENERATOR * y;
        let ephemeral = encode_point(ProjectivePoint::GENERATOR * e).unwrap();
        let mut ikm = encode_point(public * e).unwrap().to_vec();
        ikm.extend_from_slice(&ephemeral);
        ikm.extend_from_slice(&[0x42; 32]);
        ikm.extend_from_slice(&[2, 3, 1]);
        let mut key = [0; 32];
        Hkdf::<Sha256>::new(Some(b"SL1/kdf"), &ikm)
            .expand(b"SL1/contribution", &mut key)
            .unwrap();
        let cipher = ChaCha20Poly1305::new((&key).into());
        let order: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        for (scalar_bytes, expected) in [
            ([0; 32], Ok(vec![Scalar::ZERO])),
            ((-Scalar::ONE).to_bytes().into(), Ok(vec![-Scalar::ONE])),
            (order, Err(ContributionOpenError::Invalid(Error::Scalar))),
            (
                [0xff; 32],
                Err(ContributionOpenError::Invalid(Error::Scalar)),
            ),
        ] {
            let mut wire = ephemeral.to_vec();
            wire.extend_from_slice(
                &cipher
                    .encrypt(&Nonce::from([0; 12]), scalar_bytes.as_slice())
                    .unwrap(),
            );
            let sealed = SealedContribution::decode(&wire, 1).unwrap();
            assert_eq!(sealed.open(y, public, &context(), 1), expected);
        }
    }

    #[test]
    fn ecdsa_generation_zero_round_trips() {
        let mut context = context();
        context.generation = 0;
        let y = Scalar::from(17u64);
        let public = ProjectivePoint::GENERATOR * y;
        let sealed =
            SealedContribution::seal(public, &context, &[Scalar::ONE], &mut SeededRng::new(39))
                .unwrap();
        assert_eq!(
            sealed.open(y, public, &context, 1).unwrap(),
            vec![Scalar::ONE]
        );
    }
}
