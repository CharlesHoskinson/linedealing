//! Section 5 polynomial transfer. The caller supplies the board-selected dealer
//! set after FREEZE. These records are in-memory transfers, not board messages.
use crate::{
    algebra::*,
    hash::*,
    message::{share_pad, AuthProof},
    Error, Result,
};
use k256::{elliptic_curve::rand_core::CryptoRngCore, ProjectivePoint, Scalar};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCommittee {
    pub keys: Vec<ProjectivePoint>,
    pub f: u16,
    pub threshold: u16,
}
impl NewCommittee {
    fn validate(&self) -> Result<()> {
        if self.keys.len() < 3 * self.f as usize + 1
            || self.keys.len() > u16::MAX as usize
            || self.threshold != self.f + 1
        {
            return Err(Error::Parameters);
        }
        encode_points(&self.keys)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Subdealing {
    pub domain: ReshareDomain,
    pub label: SlotLabel,
    pub committee: NewCommittee,
    pub ephemeral: ProjectivePoint,
    pub coefficients: Vec<ProjectivePoint>,
    pub ciphertexts: Vec<Scalar>,
    pub proof: AuthProof,
}
impl Subdealing {
    pub fn create(
        domain: ReshareDomain,
        label: SlotLabel,
        old: &Commitment,
        share: Scalar,
        committee: NewCommittee,
        ephemeral: Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        committee.validate()?;
        if domain.new_epoch <= domain.old_epoch || !old.verify(domain.dealer, share) {
            return Err(Error::Share);
        }
        let p = Polynomial::random(share, committee.threshold, rng)?;
        let coefficients = p.commit(old.base)?.coefficients;
        let e = mul_generator(ephemeral);
        let hd = transfer_digest(domain, label, &committee, e, &coefficients)?;
        let ciphertexts = committee
            .keys
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                Ok(p.evaluate(i as u16 + 1)?
                    + share_pad(&hd, i as u16 + 1, *pk, *pk * ephemeral, label, Some(domain))?)
            })
            .collect::<Result<Vec<_>>>()?;
        let ct: Vec<_> = ciphertexts.iter().flat_map(|s| s.to_bytes()).collect();
        let proof = AuthProof::create(&hd, &ct, ephemeral, share, old.base, Some(domain), rng)?;
        Ok(Self {
            domain,
            label,
            committee,
            ephemeral: e,
            coefficients,
            ciphertexts,
            proof,
        })
    }
    fn hd(&self) -> Result<[u8; 32]> {
        transfer_digest(
            self.domain,
            self.label,
            &self.committee,
            self.ephemeral,
            &self.coefficients,
        )
    }
    fn commitment(&self, old: &Commitment) -> Result<Commitment> {
        Ok(Commitment {
            base: old.base,
            constant: old.evaluate(self.domain.dealer)?,
            coefficients: self.coefficients.clone(),
        })
    }
    fn verify(&self, old: &Commitment) -> Result<()> {
        self.committee.validate()?;
        if self.domain.new_epoch <= self.domain.old_epoch
            || self.domain.dealer == 0
            || self.coefficients.len() + 1 != self.committee.threshold as usize
            || self.ciphertexts.len() != self.committee.keys.len()
        {
            return Err(Error::Parameters);
        }
        let ct: Vec<_> = self.ciphertexts.iter().flat_map(|s| s.to_bytes()).collect();
        self.proof.verify(
            &self.hd()?,
            &ct,
            self.ephemeral,
            old.base,
            old.evaluate(self.domain.dealer)?,
            Some(self.domain),
        )
    }
    fn decrypt(&self, old: &Commitment, node: u16, secret: Scalar) -> Result<Scalar> {
        if node == 0 || node as usize > self.committee.keys.len() {
            return Err(Error::Parameters);
        }
        let pk = self.committee.keys[node as usize - 1];
        if mul_generator(secret) != pk {
            return Err(Error::Share);
        }
        let share = self.ciphertexts[node as usize - 1]
            - share_pad(
                &self.hd()?,
                node,
                pk,
                self.ephemeral * secret,
                self.label,
                Some(self.domain),
            )?;
        if !self.commitment(old)?.verify(node, share) {
            return Err(Error::Share);
        }
        Ok(share)
    }
}

// Section 5 does not define a transfer wire envelope. This local header binds
// n(2), t'(2), f'(2), E(33), slot(8), and the n ordered recipient keys(33 each).
// LD1/rs-hd retains the exact prefix and length framing of section 3.1.
fn transfer_digest(
    domain: ReshareDomain,
    label: SlotLabel,
    committee: &NewCommittee,
    ephemeral: ProjectivePoint,
    coefficients: &[ProjectivePoint],
) -> Result<[u8; 32]> {
    committee.validate()?;
    let n = committee.keys.len() as u16;
    let mut header = [
        &n.to_be_bytes()[..],
        &committee.threshold.to_be_bytes(),
        &committee.f.to_be_bytes(),
        &encode_point(ephemeral)?,
        &label.bytes(),
    ]
    .concat();
    for key in encode_points(&committee.keys)? {
        header.extend_from_slice(&key);
    }
    let mut deal = Vec::new();
    for c in encode_points(coefficients)? {
        deal.extend_from_slice(&c);
    }
    domain.digest(&header, &deal)
}

pub struct Transfer {
    old: Commitment,
    dealers: Vec<Subdealing>,
    weights: Vec<Scalar>,
    commitment: Commitment,
}
impl Transfer {
    /// The caller must supply the first t_old eligible dealers selected by the board.
    pub fn verify(old: &Commitment, dealers: &[Subdealing]) -> Result<Self> {
        if dealers.len() != old.coefficients.len() + 1 {
            return Err(Error::Threshold);
        }
        let first = dealers.first().ok_or(Error::Threshold)?;
        first.committee.validate()?;
        let nodes: Vec<_> = dealers.iter().map(|d| d.domain.dealer).collect();
        let weights = lagrange(&nodes)?;
        let mut commitment = Commitment {
            base: old.base,
            constant: ProjectivePoint::IDENTITY,
            coefficients: vec![ProjectivePoint::IDENTITY; first.committee.threshold as usize - 1],
        };
        for (dealer, weight) in dealers.iter().zip(&weights) {
            if dealer.domain.rid != first.domain.rid
                || dealer.domain.old_epoch != first.domain.old_epoch
                || dealer.domain.new_epoch != first.domain.new_epoch
                || dealer.label != first.label
                || dealer.committee != first.committee
            {
                return Err(Error::Context);
            }
            dealer.verify(old)?;
            commitment.constant += old.evaluate(dealer.domain.dealer)? * weight;
            for (sum, c) in commitment.coefficients.iter_mut().zip(&dealer.coefficients) {
                *sum += *c * weight;
            }
        }
        if commitment.constant != old.constant {
            return Err(Error::Share);
        }
        Ok(Self {
            old: old.clone(),
            dealers: dealers.to_vec(),
            weights,
            commitment,
        })
    }
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }
    pub fn decrypt(&self, node: u16, secret: Scalar) -> Result<Scalar> {
        self.dealers
            .iter()
            .zip(&self.weights)
            .try_fold(Scalar::ZERO, |sum, (d, w)| {
                Ok(sum + d.decrypt(&self.old, node, secret)? * w)
            })
    }
}
