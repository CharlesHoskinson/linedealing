use crate::{
    algebra::*,
    hash::*,
    message::{ecdsa_r, Accepted, Deal, NodeShares},
    Error, Result,
};
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId},
    elliptic_curve::scalar::IsHigh,
    ProjectivePoint, Scalar,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partial {
    pub node: u16,
    pub value: Scalar,
}

pub enum Combined {
    Ecdsa {
        signature: k256::ecdsa::Signature,
        recovery_id: RecoveryId,
    },
    Bip340(k256::schnorr::Signature),
}

#[derive(Clone)]
pub struct SigningPackage {
    hd: [u8; 32],
    threshold: usize,
    n: u16,
    public_key: ProjectivePoint,
    message: [u8; 32],
    nonce: ProjectivePoint,
    suite: u8,
    base: ProjectivePoint,
    terms: Vec<(usize, Scalar, Commitment)>,
    /// True when the bound two-nonce sum required negation for BIP340.
    pub nonce_negated: bool,
}

impl Accepted {
    /// Algebra for a digest already locked by the caller's board protocol.
    /// This method does not persist a slot ledger or establish a lock quorum.
    pub fn signing_package(
        &self,
        generation: u16,
        input: u16,
        message: [u8; 32],
        digest: [u8; 32],
    ) -> Result<SigningPackage> {
        let hdr = &self.message.header;
        let count = if hdr.mode == 1 {
            hdr.variants
        } else {
            hdr.generations
        };
        if generation == 0 || generation > count || input == 0 || input > hdr.inputs {
            return Err(Error::Parameters);
        }
        let index = (generation as usize - 1) * hdr.inputs as usize + input as usize - 1;
        let hd = self.message.hd()?;
        let mut terms = Vec::new();
        let mut add = |index: usize, scalar| {
            terms.push((index, scalar, self.polynomials[index].clone()));
        };
        let (nonce, base, nonce_negated) = match &self.message.deal {
            Deal::OpenEcdsa(slots) => {
                let nonce = slots[index].nonce;
                add(2 * index, reduce(&message));
                add(2 * index + 1, ecdsa_r(nonce)?);
                (nonce, nonce, false)
            }
            Deal::OpenBip340 { slots, .. } => {
                let slot = &slots[index];
                let rho = binding_factor(&hd, generation, input, &digest);
                let raw = slot.d + slot.e * rho;
                let negated = is_odd(raw)?;
                let sigma = if negated { -Scalar::ONE } else { Scalar::ONE };
                let nonce = raw * sigma;
                let c = bip340_challenge(&x_bytes(nonce)?, &self.message.public_key_x()?, &message);
                add(0, c);
                add(1 + 2 * index, sigma);
                add(2 + 2 * index, sigma * rho);
                (nonce, ProjectivePoint::GENERATOR, negated)
            }
            Deal::Sealed(slots) => {
                if message != self.sealed_messages[index] {
                    return Err(Error::Context);
                }
                add(index, Scalar::ONE);
                (slots[index].nonce, self.polynomials[index].base, false)
            }
        };
        Ok(SigningPackage {
            hd,
            threshold: hdr.threshold as usize,
            n: hdr.n,
            public_key: hdr.public_key,
            message,
            nonce,
            suite: hdr.suite,
            base,
            terms,
            nonce_negated,
        })
    }
}

impl SigningPackage {
    /// Replace public polynomials after an authenticated T1 HANDOVER. Keep the
    /// original hd so a BIP340 slot retains its original binding factor.
    pub fn with_resharing(
        &self,
        n: u16,
        threshold: u16,
        commitments: &[Commitment],
    ) -> Result<Self> {
        if (self.n as usize) < 3 * (self.threshold - 1) + 1
            || threshold == 0
            || (n as usize) < 3 * (threshold as usize - 1) + 1
        {
            return Err(Error::Parameters);
        }
        let mut result = self.clone();
        result.n = n;
        result.threshold = threshold as usize;
        for (index, _, old) in &mut result.terms {
            let new = commitments.get(*index).ok_or(Error::Share)?;
            if new.base != old.base
                || new.constant != old.constant
                || new.coefficients.len() + 1 != threshold as usize
            {
                return Err(Error::Share);
            }
            *old = new.clone();
        }
        Ok(result)
    }

    /// Check transferred shares against the new public commitments before use.
    pub fn partial_from_reshared(&self, node: u16, values: &[Scalar]) -> Result<Partial> {
        if node == 0 || node > self.n {
            return Err(Error::Share);
        }
        let mut value = Scalar::ZERO;
        for (index, factor, commitment) in &self.terms {
            let share = *values.get(*index).ok_or(Error::Share)?;
            if !commitment.verify(node, share) {
                return Err(Error::Share);
            }
            value += share * factor;
        }
        Ok(Partial { node, value })
    }

    pub fn nonce(&self) -> ProjectivePoint {
        self.nonce
    }
    pub fn partial(&self, shares: &NodeShares) -> Result<Partial> {
        if shares.hd != self.hd || shares.node == 0 || shares.node > self.n {
            return Err(Error::Share);
        }
        let mut value = Scalar::ZERO;
        for (index, factor, _) in &self.terms {
            value += *factor * shares.values.get(*index).ok_or(Error::Share)?;
        }
        let partial = Partial {
            node: shares.node,
            value,
        };
        if !self.verify_partial(&partial) {
            return Err(Error::Share);
        }
        Ok(partial)
    }
    pub fn verify_partial(&self, partial: &Partial) -> bool {
        if partial.node == 0 || partial.node > self.n {
            return false;
        }
        let expected = self
            .terms
            .iter()
            .try_fold(ProjectivePoint::IDENTITY, |sum, (_, factor, c)| {
                Ok::<_, Error>(sum + c.evaluate(partial.node)? * factor)
            });
        expected.is_ok_and(|expected| mul_base(self.base, partial.value) == expected)
    }
    /// Optimistic interpolation, followed by mandatory independent final verification.
    /// Discard bad partials and retry when enough valid nodes remain.
    pub fn combine(&self, partials: &[Partial]) -> Result<Combined> {
        self.combine_with_faults(partials)
            .map(|(combined, _)| combined)
    }

    /// Return the faulty node IDs found after an unsuccessful optimistic attempt.
    /// If fewer than threshold valid partials survive, name the first faulty node.
    pub fn combine_with_faults(&self, partials: &[Partial]) -> Result<(Combined, Vec<u16>)> {
        if partials.iter().any(|p| p.node == 0 || p.node > self.n) {
            return Err(Error::Share);
        }
        match self.combine_unchecked(partials) {
            Ok(combined) => Ok((combined, Vec::new())),
            Err(Error::Threshold) => Err(Error::Threshold),
            Err(error) => {
                let mut valid = Vec::with_capacity(partials.len());
                let mut faults = Vec::new();
                for partial in partials {
                    if self.verify_partial(partial) {
                        valid.push(*partial);
                    } else {
                        faults.push(partial.node);
                    }
                }
                let Some(&first) = faults.first() else {
                    return Err(error);
                };
                if valid.len() < self.threshold {
                    return Err(Error::BadPartial(first));
                }
                Ok((self.combine_unchecked(&valid)?, faults))
            }
        }
    }

    fn combine_unchecked(&self, partials: &[Partial]) -> Result<Combined> {
        let points: Vec<_> = partials.iter().map(|p| (p.node, p.value)).collect();
        let s = interpolate(&points, self.threshold)?;
        if s == Scalar::ZERO {
            return Err(Error::Signature);
        }
        let combined = if self.suite == 1 {
            finalize_ecdsa(self.nonce, s)?
        } else {
            let bytes = [&x_bytes(self.nonce)?[..], &s.to_bytes()].concat();
            Combined::Bip340(
                k256::schnorr::Signature::try_from(bytes.as_slice())
                    .map_err(|_| Error::Signature)?,
            )
        };
        combined.verify(self.public_key, &self.message)?;
        Ok(combined)
    }
}

pub fn finalize_ecdsa(nonce: ProjectivePoint, s: Scalar) -> Result<Combined> {
    let r = ecdsa_r(nonce)?;
    let flipped = bool::from(s.is_high());
    let low_s = if flipped { -s } else { s };
    let signature = k256::ecdsa::Signature::from_scalars(r.to_bytes(), low_s.to_bytes())
        .map_err(|_| Error::Signature)?;
    let recovery_id = RecoveryId::new(is_odd(nonce)? ^ flipped, false);
    Ok(Combined::Ecdsa {
        signature,
        recovery_id,
    })
}

impl Combined {
    pub fn verify(&self, public: ProjectivePoint, message: &[u8; 32]) -> Result<()> {
        match self {
            Self::Ecdsa { signature, .. } => {
                let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&encode_point(public)?)
                    .map_err(|_| Error::Point)?;
                key.verify_prehash(message, signature)
                    .map_err(|_| Error::Signature)
            }
            Self::Bip340(signature) => {
                if is_odd(public)? {
                    return Err(Error::Point);
                }
                let key = k256::schnorr::VerifyingKey::from_bytes(&x_bytes(public)?)
                    .map_err(|_| Error::Point)?;
                key.verify_raw(message, signature)
                    .map_err(|_| Error::Signature)
            }
        }
    }
}

/// Canonical LD1/dg input from section 3.1.
pub struct LockDigest<'a> {
    pub rid: [u8; 32],
    pub epoch: u64,
    pub generation: u16,
    pub attempt: u16,
    pub anchor_height: u64,
    pub anchor_hash: [u8; 32],
    pub transaction: &'a [u8],
    pub sighashes: &'a [[u8; 32]],
}
impl LockDigest<'_> {
    pub fn hash(&self) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let count = u16::try_from(self.sighashes.len()).map_err(|_| Error::Encoding)?;
        let mut data = [
            &self.rid[..],
            &self.epoch.to_be_bytes(),
            &self.generation.to_be_bytes(),
            &self.attempt.to_be_bytes(),
            &self.anchor_height.to_be_bytes(),
            &self.anchor_hash,
            &Sha256::digest(self.transaction),
            &count.to_be_bytes(),
        ]
        .concat();
        for m in self.sighashes {
            data.extend_from_slice(m);
        }
        Ok(h("LD1/dg", &data))
    }
}
