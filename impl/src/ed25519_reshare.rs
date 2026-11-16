//! Section 5 polynomial transfer. The caller supplies the board-selected dealer
//! set after FREEZE. These records are in-memory transfers, not board messages.
use crate::{
    ed25519::{encode_point, encode_scalar, hq, AuthProof, Commitment, DhProof, Polynomial},
    hash::*,
    Error, Result,
};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, traits::Identity};
use k256::elliptic_curve::rand_core::CryptoRngCore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCommittee {
    pub keys: Vec<EdwardsPoint>,
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
        for key in &self.keys {
            encode_point(*key)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Subdealing {
    pub domain: ReshareDomain,
    pub label: SlotLabel,
    pub committee: NewCommittee,
    pub ephemeral: EdwardsPoint,
    pub coefficients: Vec<EdwardsPoint>,
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
        let coefficients = p.commitments();
        let e = EdwardsPoint::mul_base(&ephemeral);
        let hd = transfer_digest(domain, label, &committee, e, &coefficients)?;
        let ciphertexts = committee
            .keys
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                Ok(p.evaluate(i as u16 + 1)
                    + share_pad(&hd, i as u16 + 1, *pk, *pk * ephemeral, label, Some(domain))?)
            })
            .collect::<Result<Vec<_>>>()?;
        let ct: Vec<_> = ciphertexts.iter().flat_map(|s| encode_scalar(*s)).collect();
        let proof = AuthProof::create(&hd, &ct, ephemeral, share, G, Some(domain), rng)?;
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
    pub fn hd(&self) -> Result<[u8; 32]> {
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
            constant: old.evaluate(self.domain.dealer)?,
            coefficients: self.coefficients.clone(),
        })
    }
    pub fn verify(&self, old: &Commitment) -> Result<()> {
        self.committee.validate()?;
        encode_point(old.constant)?;
        for point in &old.coefficients {
            encode_point(*point)?;
        }
        if self.domain.new_epoch <= self.domain.old_epoch
            || self.domain.dealer == 0
            || self.coefficients.len() + 1 != self.committee.threshold as usize
            || self.ciphertexts.len() != self.committee.keys.len()
        {
            return Err(Error::Parameters);
        }
        let ct: Vec<_> = self
            .ciphertexts
            .iter()
            .flat_map(|s| encode_scalar(*s))
            .collect();
        self.proof.verify(
            &self.hd()?,
            &ct,
            self.ephemeral,
            G,
            old.evaluate(self.domain.dealer)?,
            Some(self.domain),
        )
    }
    pub fn decrypt(&self, old: &Commitment, node: u16, secret: Scalar) -> Result<Scalar> {
        self.verify(old)?;
        if node == 0 || node as usize > self.committee.keys.len() {
            return Err(Error::Parameters);
        }
        let pk = self.committee.keys[node as usize - 1];
        if EdwardsPoint::mul_base(&secret) != pk {
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
    fn mid(&self) -> Result<[u8; 32]> {
        let mut bytes = self.hd()?.to_vec();
        bytes.extend(self.ciphertexts.iter().flat_map(|s| encode_scalar(*s)));
        bytes.extend(self.proof.encode()?);
        Ok(h("LD1/rs-mid", &bytes))
    }
    pub fn complain(
        &self,
        old: &Commitment,
        node: u16,
        secret: Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DhProof> {
        self.verify(old)?;
        let pk = *self
            .committee
            .keys
            .get(usize::from(node).checked_sub(1).ok_or(Error::Parameters)?)
            .ok_or(Error::Parameters)?;
        let proof = DhProof::create(&self.mid()?, pk, self.ephemeral, secret, rng)?;
        self.verify_complaint(old, node, &proof)?;
        Ok(proof)
    }
    pub fn verify_complaint(&self, old: &Commitment, node: u16, proof: &DhProof) -> Result<()> {
        self.verify(old)?;
        let pk = *self
            .committee
            .keys
            .get(usize::from(node).checked_sub(1).ok_or(Error::Parameters)?)
            .ok_or(Error::Parameters)?;
        proof.verify(&self.mid()?, pk, self.ephemeral)?;
        let share = self.ciphertexts[usize::from(node) - 1]
            - share_pad(
                &self.hd()?,
                node,
                pk,
                proof.key,
                self.label,
                Some(self.domain),
            )?;
        if self.commitment(old)?.verify(node, share) {
            return Err(Error::Share);
        }
        Ok(())
    }
}

// Section 5 does not define a transfer wire envelope. This local header binds
// n(2), t'(2), f'(2), E(33), slot(8), and the n ordered recipient keys(33 each).
// LD1/rs-hd retains the exact prefix and length framing of section 3.1.
fn transfer_digest(
    domain: ReshareDomain,
    label: SlotLabel,
    committee: &NewCommittee,
    ephemeral: EdwardsPoint,
    coefficients: &[EdwardsPoint],
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
    for key in &committee.keys {
        header.extend_from_slice(&encode_point(*key)?);
    }
    let mut deal = Vec::new();
    for c in coefficients {
        deal.extend_from_slice(&encode_point(*c)?);
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
            constant: EdwardsPoint::identity(),
            coefficients: vec![EdwardsPoint::identity(); first.committee.threshold as usize - 1],
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

fn share_pad(
    hd: &[u8; 32],
    node: u16,
    pk: EdwardsPoint,
    dh: EdwardsPoint,
    label: SlotLabel,
    domain: Option<ReshareDomain>,
) -> Result<Scalar> {
    let mut data = domain.map_or_else(Vec::new, |d| d.prefix());
    data.extend_from_slice(hd);
    data.extend_from_slice(&node.to_be_bytes());
    data.extend_from_slice(&encode_point(pk)?);
    data.extend_from_slice(&encode_point(dh)?);
    data.extend_from_slice(&label.bytes());
    Ok(hq("LD1/rs-enc", &data))
}

fn lagrange(nodes: &[u16]) -> Result<Vec<Scalar>> {
    let unique: std::collections::BTreeSet<_> = nodes.iter().copied().collect();
    if nodes.is_empty() || unique.len() != nodes.len() || unique.contains(&0) {
        return Err(Error::Parameters);
    }
    Ok(nodes
        .iter()
        .map(|i| {
            let mut numerator = Scalar::ONE;
            let mut denominator = Scalar::ONE;
            for j in nodes.iter().filter(|j| *j != i) {
                numerator *= -Scalar::from(u64::from(*j));
                denominator *= Scalar::from(u64::from(*i)) - Scalar::from(u64::from(*j));
            }
            numerator * denominator.invert()
        })
        .collect())
}
