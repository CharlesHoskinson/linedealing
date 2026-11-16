//! Batched committee nonce dealing (DESIGN §§4.1, 5.10).
//!
//! This uses the line-dealing DH-plus-scalar-pad construction with `SL1/slot`
//! labels. The existing message APIs bind address-specific headers, so this
//! module supplies the same construction for epoch-wide batches. Shares and
//! dealing secrets in the in-process simulator must never be persisted.

use super::group::{commitments, evaluate_commitments, evaluate_scalar, random_polynomial, Suite};
use crate::{Error, Result};
use k256::elliptic_curve::rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct DealerProof<S: Suite> {
    pub nonce: S::Point,
    pub response: S::Scalar,
}

/// Polynomial order is `(slot[0].d, slot[0].e, slot[1].d, ...)`.
#[derive(Clone, Debug)]
pub struct DealerMessage<S: Suite> {
    pub epoch: u64,
    pub dealer: u16,
    pub n: u16,
    pub threshold: u16,
    pub slot_ids: Vec<u64>,
    pub ephemeral: S::Point,
    pub commitments: Vec<Vec<S::Point>>,
    pub encrypted_shares: BTreeMap<u16, Vec<S::Scalar>>,
    pub proof: DealerProof<S>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadDealing {
    pub dealer: u16,
    pub node: u16,
    pub slot: u64,
    /// Zero denotes d, one denotes e.
    pub nonce: u8,
    pub polynomial: usize,
}

/// Public DH opening with a Chaum-Pedersen proof tied to this batch and item.
#[derive(Clone, Debug)]
pub struct SlotComplaint<S: Suite> {
    pub dealing: BadDealing,
    pub shared: S::Point,
    pub proof_g: S::Point,
    pub proof_e: S::Point,
    pub response: S::Scalar,
}

#[derive(Clone, Debug)]
pub struct CheckedBatch<S: Suite> {
    pub dealer: u16,
    pub node: u16,
    pub shares: Vec<S::Scalar>,
    pub batch_passed: bool,
    pub complaints: Vec<SlotComplaint<S>>,
}

#[derive(Clone, Debug)]
pub struct NonceSlot<S: Suite> {
    pub d: S::Point,
    pub e: S::Point,
    pub d_commitments: Vec<S::Point>,
    pub e_commitments: Vec<S::Point>,
    pub shares: BTreeMap<u16, (S::Scalar, S::Scalar)>,
    cache: BTreeMap<u16, (S::Point, S::Point)>,
}

impl<S: Suite> NonceSlot<S> {
    /// Evaluate only when a signature partial needs checking; cache the result.
    pub fn evaluate(&mut self, node: u16) -> Result<(S::Point, S::Point)> {
        if !self.shares.contains_key(&node) {
            return Err(Error::Parameters);
        }
        if let Some(points) = self.cache.get(&node) {
            return Ok(*points);
        }
        let points = (
            evaluate_commitments::<S>(&self.d_commitments, node)?,
            evaluate_commitments::<S>(&self.e_commitments, node)?,
        );
        self.cache.insert(node, points);
        Ok(points)
    }

    pub fn cached_nodes(&self) -> usize {
        self.cache.len()
    }
}

#[derive(Clone, Debug)]
pub struct CommitteeSlots<S: Suite> {
    pub n: u16,
    pub threshold: u16,
    pub qualified: Vec<u16>,
    pub slots: BTreeMap<u64, NonceSlot<S>>,
    pub complaints: Vec<SlotComplaint<S>>,
}

fn parameters(n: u16, threshold: u16, slots: &[u64]) -> Result<()> {
    if threshold == 0
        || threshold > n
        || slots.is_empty()
        || slots.iter().collect::<BTreeSet<_>>().len() != slots.len()
    {
        return Err(Error::Parameters);
    }
    Ok(())
}

fn point<S: Suite>(out: &mut Vec<u8>, value: S::Point) -> Result<()> {
    out.extend_from_slice(&S::encode_point(value)?);
    Ok(())
}

impl<S: Suite> DealerMessage<S> {
    /// Encode the complete board post, including its context and dealer proof.
    /// Dimensions determine the polynomial and recipient field lengths.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut bytes = b"SL1/slot".to_vec();
        bytes.push(S::SUITE_ID);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.dealer.to_be_bytes());
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes.extend_from_slice(&self.threshold.to_be_bytes());
        bytes.extend_from_slice(&(self.slot_ids.len() as u64).to_be_bytes());
        for id in &self.slot_ids {
            bytes.extend_from_slice(&id.to_be_bytes());
        }
        point::<S>(&mut bytes, self.ephemeral)?;
        for coefficients in &self.commitments {
            for coefficient in coefficients {
                point::<S>(&mut bytes, *coefficient)?;
            }
        }
        for (node, shares) in &self.encrypted_shares {
            bytes.extend_from_slice(&node.to_be_bytes());
            for share in shares {
                bytes.extend_from_slice(&S::encode_scalar(*share));
            }
        }
        point::<S>(&mut bytes, self.proof.nonce)?;
        bytes.extend_from_slice(&S::encode_scalar(self.proof.response));
        Ok(bytes)
    }

    fn validate_shape(&self) -> Result<()> {
        parameters(self.n, self.threshold, &self.slot_ids)?;
        if self.dealer == 0
            || self.dealer > self.n
            || self.ephemeral == S::identity()
            || self.commitments.len() != self.slot_ids.len() * 2
            || self
                .commitments
                .iter()
                .any(|c| c.len() != usize::from(self.threshold))
            || self.encrypted_shares.len() != usize::from(self.n)
            || (1..=self.n).any(|i| {
                self.encrypted_shares
                    .get(&i)
                    .is_none_or(|s| s.len() != self.commitments.len())
            })
        {
            return Err(Error::Parameters);
        }
        Ok(())
    }

    /// Binding data used by each polynomial's independent encryption pad.
    fn binding(&self) -> Result<[u8; 32]> {
        let mut bytes = b"SL1/slot".to_vec();
        bytes.push(S::SUITE_ID);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.dealer.to_be_bytes());
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes.extend_from_slice(&self.threshold.to_be_bytes());
        bytes.extend_from_slice(&(self.slot_ids.len() as u64).to_be_bytes());
        for id in &self.slot_ids {
            bytes.extend_from_slice(&id.to_be_bytes());
        }
        point::<S>(&mut bytes, self.ephemeral)?;
        for cs in &self.commitments {
            for p in cs {
                point::<S>(&mut bytes, *p)?;
            }
        }
        Ok(Sha256::digest(bytes).into())
    }

    fn digest(&self) -> Result<[u8; 32]> {
        Ok(self.digest_bound(&self.binding()?))
    }

    fn digest_bound(&self, binding: &[u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(binding);
        for (node, shares) in &self.encrypted_shares {
            hash.update(node.to_be_bytes());
            for share in shares {
                hash.update(S::encode_scalar(*share));
            }
        }
        hash.finalize().into()
    }

    fn proof_challenge(&self, nonce: S::Point) -> Result<S::Scalar> {
        Self::proof_challenge_bound(&self.digest()?, nonce)
    }

    fn proof_challenge_bound(digest: &[u8; 32], nonce: S::Point) -> Result<S::Scalar> {
        let mut bytes = digest.to_vec();
        point::<S>(&mut bytes, nonce)?;
        Ok(S::hash_to_scalar("SL1/slot/proof", &bytes))
    }

    fn sign(&mut self, ephemeral_secret: S::Scalar, rng: &mut impl CryptoRngCore) -> Result<()> {
        let nonce = S::random(rng);
        let r = S::generator_mul(nonce);
        self.proof = DealerProof {
            nonce: r,
            response: nonce + self.proof_challenge(r)? * ephemeral_secret,
        };
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_held().map(|_| ())
    }

    // Public structs need validation even when they did not come from a wire
    // decoder. Retain the binding and full-message digest for this check.
    fn verify_held(&self) -> Result<([u8; 32], [u8; 32])> {
        self.validate_shape()?;
        S::validate_point(self.ephemeral)?;
        S::validate_point(self.proof.nonce)?;
        for commitments in &self.commitments {
            for point in commitments {
                S::validate_point(*point)?;
            }
        }
        let binding = self.binding()?;
        let digest = self.digest_bound(&binding);
        if S::generator_mul(self.proof.response)
            != self.proof.nonce
                + S::mul(
                    self.ephemeral,
                    Self::proof_challenge_bound(&digest, self.proof.nonce)?,
                )
        {
            return Err(Error::Proof);
        }
        Ok((binding, digest))
    }
}

fn pad<S: Suite>(
    binding: &[u8; 32],
    node: u16,
    polynomial: usize,
    shared: S::Point,
) -> Result<S::Scalar> {
    let mut bytes = binding.to_vec();
    bytes.extend_from_slice(&node.to_be_bytes());
    bytes.extend_from_slice(&(polynomial as u64).to_be_bytes());
    point::<S>(&mut bytes, shared)?;
    Ok(S::hash_to_scalar("SL1/slot/pad", &bytes))
}

/// One ephemeral key, one proof, and two independent polynomials per slot.
pub fn create_dealer_message<S: Suite>(
    dealer: u16,
    epoch: u64,
    threshold: u16,
    slot_ids: &[u64],
    recipients: &BTreeMap<u16, S::Point>,
    rng: &mut impl CryptoRngCore,
) -> Result<DealerMessage<S>> {
    let n = u16::try_from(recipients.len()).map_err(|_| Error::Parameters)?;
    parameters(n, threshold, slot_ids)?;
    if dealer == 0
        || dealer > n
        || (1..=n).any(|i| recipients.get(&i).is_none_or(|p| *p == S::identity()))
    {
        return Err(Error::Parameters);
    }
    for key in recipients.values() {
        S::validate_point(*key)?;
    }
    let polynomials = (0..slot_ids.len() * 2)
        .map(|_| random_polynomial::<S>(S::random(rng), usize::from(threshold), rng))
        .collect::<Result<Vec<_>>>()?;
    let ephemeral_secret = S::random(rng);
    let mut message = DealerMessage {
        epoch,
        dealer,
        n,
        threshold,
        slot_ids: slot_ids.to_vec(),
        ephemeral: S::generator_mul(ephemeral_secret),
        commitments: polynomials.iter().map(|p| commitments::<S>(p)).collect(),
        encrypted_shares: BTreeMap::new(),
        proof: DealerProof {
            nonce: S::identity(),
            response: S::scalar_zero(),
        },
    };
    let binding = message.binding()?;
    for (&node, &key) in recipients {
        let shared = S::mul(key, ephemeral_secret);
        let encrypted = polynomials
            .iter()
            .enumerate()
            .map(|(m, polynomial)| {
                Ok(evaluate_scalar::<S>(polynomial, node)? + pad::<S>(&binding, node, m, shared)?)
            })
            .collect::<Result<Vec<_>>>()?;
        message.encrypted_shares.insert(node, encrypted);
    }
    message.sign(ephemeral_secret, rng)?;
    Ok(message)
}

/// Individually check all polynomials and identify every failed dealing.
pub fn fallback_check<S: Suite>(
    message: &DealerMessage<S>,
    node: u16,
    shares: &[S::Scalar],
) -> Result<Vec<BadDealing>> {
    message.verify()?;
    fallback_check_held(message, node, shares)
}

fn fallback_check_held<S: Suite>(
    message: &DealerMessage<S>,
    node: u16,
    shares: &[S::Scalar],
) -> Result<Vec<BadDealing>> {
    if node == 0 || node > message.n || shares.len() != message.commitments.len() {
        return Err(Error::Parameters);
    }
    let mut bad = Vec::new();
    for (m, (share, cs)) in shares.iter().zip(&message.commitments).enumerate() {
        if S::generator_mul(*share) != evaluate_commitments::<S>(cs, node)? {
            bad.push(BadDealing {
                dealer: message.dealer,
                node,
                slot: message.slot_ids[m / 2],
                nonce: (m % 2) as u8,
                polynomial: m,
            });
        }
    }
    Ok(bad)
}

fn complaint_challenge<S: Suite>(
    digest: &[u8; 32],
    key: S::Point,
    complaint: &SlotComplaint<S>,
) -> Result<S::Scalar> {
    let mut bytes = digest.to_vec();
    bytes.extend_from_slice(&complaint.dealing.node.to_be_bytes());
    bytes.extend_from_slice(&(complaint.dealing.polynomial as u64).to_be_bytes());
    for p in [key, complaint.shared, complaint.proof_g, complaint.proof_e] {
        point::<S>(&mut bytes, p)?;
    }
    Ok(S::hash_to_scalar("SL1/slot/complaint", &bytes))
}

/// Hold and authenticate the entire immutable message before drawing private
/// 128-bit batch coefficients. No coefficients are returned or retained.
pub fn decrypt_and_check<S: Suite>(
    message: &DealerMessage<S>,
    node: u16,
    secret: S::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<CheckedBatch<S>> {
    let (binding, digest) = message.verify_held()?;
    let encrypted = message
        .encrypted_shares
        .get(&node)
        .ok_or(Error::Parameters)?;
    let shared = S::mul(message.ephemeral, secret);
    let shares = encrypted
        .iter()
        .enumerate()
        .map(|(m, ciphertext)| Ok(*ciphertext - pad::<S>(&binding, node, m, shared)?))
        .collect::<Result<Vec<_>>>()?;
    // DESIGN §5.10 rule 1: evaluate each commitment vector at the small node
    // index first, then weight the 2·B_slot evaluations. Weighting every
    // coefficient instead costs t full-width multiplications per polynomial.
    let mut lhs = S::scalar_zero();
    let mut rhs = S::identity();
    for (share, cs) in shares.iter().zip(&message.commitments) {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide[48..]);
        let r = S::scalar_from_wide(&wide);
        lhs = lhs + r * *share;
        rhs = rhs + S::mul(evaluate_commitments::<S>(cs, node)?, r);
    }
    let batch_passed = S::generator_mul(lhs) == rhs;
    let mut complaints = Vec::new();
    if !batch_passed {
        for dealing in fallback_check_held(message, node, &shares)? {
            let nonce = S::random(rng);
            let mut complaint = SlotComplaint {
                dealing,
                shared,
                proof_g: S::generator_mul(nonce),
                proof_e: S::mul(message.ephemeral, nonce),
                response: S::scalar_zero(),
            };
            let c = complaint_challenge::<S>(&digest, S::generator_mul(secret), &complaint)?;
            complaint.response = nonce + c * secret;
            complaints.push(complaint);
        }
    }
    Ok(CheckedBatch {
        dealer: message.dealer,
        node,
        shares,
        batch_passed,
        complaints,
    })
}

/// Accept a public complaint only if the DH opening is correct and the named
/// share fails its commitment equation. A fabricated complaint excludes nobody.
pub fn verify_complaint<S: Suite>(
    message: &DealerMessage<S>,
    key: S::Point,
    complaint: &SlotComplaint<S>,
) -> Result<()> {
    let (binding, digest) = message.verify_held()?;
    for point in [key, complaint.shared, complaint.proof_g, complaint.proof_e] {
        S::validate_point(point)?;
    }
    let bad = complaint.dealing;
    if bad.dealer != message.dealer
        || bad.polynomial >= message.commitments.len()
        || bad.slot != message.slot_ids[bad.polynomial / 2]
        || usize::from(bad.nonce) != bad.polynomial % 2
        || key == S::identity()
        || bad.node == 0
        || bad.node > message.n
    {
        return Err(Error::Context);
    }
    let c = complaint_challenge::<S>(&digest, key, complaint)?;
    if S::generator_mul(complaint.response) != complaint.proof_g + S::mul(key, c)
        || S::mul(message.ephemeral, complaint.response)
            != complaint.proof_e + S::mul(complaint.shared, c)
    {
        return Err(Error::Proof);
    }
    let share = message.encrypted_shares[&bad.node][bad.polynomial]
        - pad::<S>(&binding, bad.node, bad.polynomial, complaint.shared)?;
    if S::generator_mul(share)
        == evaluate_commitments::<S>(&message.commitments[bad.polynomial], bad.node)?
    {
        return Err(Error::Share);
    }
    Ok(())
}

impl<S: Suite> CommitteeSlots<S> {
    /// In-process dealer simulation. The caller supplies board order through
    /// `messages`; the first threshold distinct, valid dealers are retained.
    pub fn assemble(
        messages: &[DealerMessage<S>],
        secrets: &BTreeMap<u16, S::Scalar>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let first = messages.first().ok_or(Error::Threshold)?;
        first.validate_shape()?;
        if secrets.len() != usize::from(first.n) || (1..=first.n).any(|i| !secrets.contains_key(&i))
        {
            return Err(Error::Parameters);
        }
        let mut qualified = Vec::new();
        let mut seen = BTreeSet::new();
        let mut complaints = Vec::new();
        let mut slots = BTreeMap::new();
        for id in &first.slot_ids {
            slots.insert(
                *id,
                NonceSlot {
                    d: S::identity(),
                    e: S::identity(),
                    d_commitments: vec![S::identity(); usize::from(first.threshold)],
                    e_commitments: vec![S::identity(); usize::from(first.threshold)],
                    shares: (1..=first.n)
                        .map(|i| (i, (S::scalar_zero(), S::scalar_zero())))
                        .collect(),
                    cache: BTreeMap::new(),
                },
            );
        }
        for message in messages {
            if !seen.insert(message.dealer) {
                return Err(Error::Parameters);
            }
            if message.epoch != first.epoch
                || message.n != first.n
                || message.threshold != first.threshold
                || message.slot_ids != first.slot_ids
            {
                return Err(Error::Context);
            }
            if message.verify().is_err() {
                continue;
            }
            let mut checked = Vec::new();
            let mut failed = false;
            for (&node, &secret) in secrets {
                let batch = decrypt_and_check(message, node, secret, rng)?;
                for complaint in &batch.complaints {
                    verify_complaint(message, S::generator_mul(secret), complaint)?;
                    complaints.push(complaint.clone());
                }
                failed |= !batch.batch_passed;
                checked.push(batch);
            }
            if failed {
                continue;
            }
            for (s, id) in message.slot_ids.iter().enumerate() {
                let slot = slots.get_mut(id).ok_or(Error::Parameters)?;
                for (sum, c) in slot
                    .d_commitments
                    .iter_mut()
                    .zip(&message.commitments[s * 2])
                {
                    *sum = *sum + *c;
                }
                for (sum, c) in slot
                    .e_commitments
                    .iter_mut()
                    .zip(&message.commitments[s * 2 + 1])
                {
                    *sum = *sum + *c;
                }
                for batch in &checked {
                    let pair = slot.shares.get_mut(&batch.node).ok_or(Error::Parameters)?;
                    pair.0 = pair.0 + batch.shares[s * 2];
                    pair.1 = pair.1 + batch.shares[s * 2 + 1];
                }
            }
            qualified.push(message.dealer);
            if qualified.len() == usize::from(first.threshold) {
                break;
            }
        }
        if qualified.len() != usize::from(first.threshold) {
            return Err(Error::Threshold);
        }
        for slot in slots.values_mut() {
            slot.d = slot.d_commitments[0];
            slot.e = slot.e_commitments[0];
            if slot.d == S::identity() || slot.e == S::identity() {
                return Err(Error::Nonce);
            }
        }
        Ok(Self {
            n: first.n,
            threshold: first.threshold,
            qualified,
            slots,
            complaints,
        })
    }

    pub fn generate(
        n: u16,
        threshold: u16,
        slot_ids: &[u64],
        epoch: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        parameters(n, threshold, slot_ids)?;
        let secrets: BTreeMap<_, _> = (1..=n).map(|i| (i, S::random(rng))).collect();
        let recipients = secrets
            .iter()
            .map(|(&i, &s)| (i, S::generator_mul(s)))
            .collect();
        let messages = (1..=threshold)
            .map(|dealer| {
                create_dealer_message::<S>(dealer, epoch, threshold, slot_ids, &recipients, rng)
            })
            .collect::<Result<Vec<_>>>()?;
        Self::assemble(&messages, &secrets, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::super::group::{lagrange, Edwards, Secp};
    use super::*;
    use k256::elliptic_curve::rand_core::{CryptoRng, Error as RngError, RngCore};

    #[derive(Default)]
    struct TestRng {
        counter: u64,
        widths: Vec<usize>,
    }
    impl CryptoRng for TestRng {}
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0; 8];
            self.fill_bytes(&mut b);
            u64::from_be_bytes(b)
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            self.widths.push(out.len());
            for chunk in out.chunks_mut(32) {
                self.counter += 1;
                let hash = Sha256::digest(self.counter.to_be_bytes());
                chunk.copy_from_slice(&hash[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> core::result::Result<(), RngError> {
            self.fill_bytes(out);
            Ok(())
        }
    }

    fn check_honest<S: Suite>(n: u16, threshold: u16) {
        let mut rng = TestRng::default();
        let mut pool =
            CommitteeSlots::<S>::generate(n, threshold, &[10, 11, 12, 13], 4, &mut rng).unwrap();
        assert_eq!(pool.qualified, (1..=threshold).collect::<Vec<_>>());
        assert!(pool.complaints.is_empty());
        let holders: Vec<_> = (n - threshold + 1..=n).collect();
        let weights = lagrange::<S>(&holders).unwrap();
        for slot in pool.slots.values_mut() {
            assert_eq!(slot.cached_nodes(), 0);
            let mut d = S::scalar_zero();
            let mut e = S::scalar_zero();
            for (&node, &weight) in holders.iter().zip(&weights) {
                let (d_i, e_i) = slot.shares[&node];
                d = d + weight * d_i;
                e = e + weight * e_i;
                assert_eq!(
                    slot.evaluate(node).unwrap(),
                    (S::generator_mul(d_i), S::generator_mul(e_i))
                );
            }
            assert_eq!(S::generator_mul(d), slot.d);
            assert_eq!(S::generator_mul(e), slot.e);
            assert_eq!(slot.cached_nodes(), usize::from(threshold));
            let points = slot.evaluate(n).unwrap();
            assert_eq!(points, slot.evaluate(n).unwrap());
            assert_eq!(slot.cached_nodes(), usize::from(threshold));
            assert_eq!(slot.evaluate(0), Err(Error::Parameters));
        }
    }

    // A dishonest dealer can authenticate its own invalid ciphertext. This
    // fixture tests the share equation, not merely a broken message signature.
    fn malicious<S: Suite>(
        n: u16,
        threshold: u16,
        recipients: &BTreeMap<u16, S::Point>,
        rng: &mut TestRng,
    ) -> DealerMessage<S> {
        let secret = S::random(rng);
        let polys = (0..4)
            .map(|_| random_polynomial::<S>(S::random(rng), usize::from(threshold), rng).unwrap())
            .collect::<Vec<_>>();
        let mut message = DealerMessage {
            epoch: 8,
            dealer: 1,
            n,
            threshold,
            slot_ids: vec![20, 21],
            ephemeral: S::generator_mul(secret),
            commitments: polys.iter().map(|p| commitments::<S>(p)).collect(),
            encrypted_shares: BTreeMap::new(),
            proof: DealerProof {
                nonce: S::identity(),
                response: S::scalar_zero(),
            },
        };
        let binding = message.binding().unwrap();
        for (&node, &key) in recipients {
            let shared = S::mul(key, secret);
            let shares = polys
                .iter()
                .enumerate()
                .map(|(m, p)| {
                    evaluate_scalar::<S>(p, node).unwrap()
                        + pad::<S>(&binding, node, m, shared).unwrap()
                })
                .collect();
            message.encrypted_shares.insert(node, shares);
        }
        // Equal and opposite errors would pass a fixed all-one batch check.
        let bad = message.encrypted_shares.get_mut(&n).unwrap();
        bad[1] = bad[1] + S::scalar_one();
        bad[2] = bad[2] - S::scalar_one();
        message.sign(secret, rng).unwrap();
        message
    }

    fn check_faults<S: Suite>(n: u16, threshold: u16) {
        let mut rng = TestRng::default();
        let secrets: BTreeMap<_, _> = (1..=n).map(|i| (i, S::random(&mut rng))).collect();
        let recipients = secrets
            .iter()
            .map(|(&i, &s)| (i, S::generator_mul(s)))
            .collect();
        let bad = malicious::<S>(n, threshold, &recipients, &mut rng);
        bad.verify().unwrap();
        let mut tampered = bad.clone();
        let altered = &mut tampered.encrypted_shares.get_mut(&n).unwrap()[0];
        *altered = *altered + S::scalar_one();
        let mut untouched_rng = TestRng::default();
        assert!(matches!(
            decrypt_and_check(&tampered, n, secrets[&n], &mut untouched_rng),
            Err(Error::Proof)
        ));
        assert!(untouched_rng.widths.is_empty());
        let mut verifier_rng = TestRng::default();
        let good_node = decrypt_and_check(&bad, 1, secrets[&1], &mut verifier_rng).unwrap();
        assert!(good_node.batch_passed);
        assert!(good_node.complaints.is_empty());
        assert_eq!(verifier_rng.widths, vec![16; 4]);
        let result = decrypt_and_check(&bad, n, secrets[&n], &mut rng).unwrap();
        assert!(!result.batch_passed);
        assert_eq!(
            result
                .complaints
                .iter()
                .map(|c| c.dealing.polynomial)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(result.complaints[0].dealing.slot, 20);
        assert_eq!(result.complaints[0].dealing.nonce, 1);
        assert_eq!(result.complaints[1].dealing.slot, 21);
        assert_eq!(result.complaints[1].dealing.nonce, 0);
        for complaint in &result.complaints {
            verify_complaint(&bad, recipients[&n], complaint).unwrap();
            let mut forged = complaint.clone();
            forged.response = forged.response + S::scalar_one();
            assert_eq!(
                verify_complaint(&bad, recipients[&n], &forged),
                Err(Error::Proof)
            );
            let mut renamed = complaint.clone();
            renamed.dealing.polynomial = 0;
            renamed.dealing.slot = 20;
            renamed.dealing.nonce = 0;
            assert_eq!(
                verify_complaint(&bad, recipients[&n], &renamed),
                Err(Error::Proof)
            );
        }
        // Even a valid DH proof cannot accuse a correctly dealt polynomial.
        let mut false_complaint = result.complaints[0].clone();
        false_complaint.dealing.polynomial = 0;
        false_complaint.dealing.nonce = 0;
        let proof_nonce = S::random(&mut rng);
        false_complaint.proof_g = S::generator_mul(proof_nonce);
        false_complaint.proof_e = S::mul(bad.ephemeral, proof_nonce);
        let challenge =
            complaint_challenge::<S>(&bad.digest().unwrap(), recipients[&n], &false_complaint)
                .unwrap();
        false_complaint.response = proof_nonce + challenge * secrets[&n];
        assert_eq!(
            verify_complaint(&bad, recipients[&n], &false_complaint),
            Err(Error::Share)
        );
        let mut messages = vec![bad];
        // The input order is board order, deliberately different from id order.
        for dealer in (2..=threshold + 1).rev() {
            messages.push(
                create_dealer_message::<S>(dealer, 8, threshold, &[20, 21], &recipients, &mut rng)
                    .unwrap(),
            );
        }
        let pool = CommitteeSlots::<S>::assemble(&messages, &secrets, &mut rng).unwrap();
        assert_eq!(
            pool.qualified,
            (2..=threshold + 1).rev().collect::<Vec<_>>()
        );
        assert_eq!(pool.complaints.len(), 2);
        assert!(pool.slots.values().all(|s| s.cached_nodes() == 0));
        assert!(matches!(
            CommitteeSlots::<S>::assemble(&messages[..usize::from(threshold)], &secrets, &mut rng),
            Err(Error::Threshold)
        ));
    }

    #[test]
    fn secp_batch_n9_t7() {
        check_honest::<Secp>(9, 7);
    }
    #[test]
    fn secp_batch_n17_t12() {
        check_honest::<Secp>(17, 12);
    }
    #[test]
    fn edwards_batch_n9_t7() {
        check_honest::<Edwards>(9, 7);
    }
    #[test]
    fn edwards_batch_n17_t12() {
        check_honest::<Edwards>(17, 12);
    }
    #[test]
    fn secp_complaints_n9_t7() {
        check_faults::<Secp>(9, 7);
    }
    #[test]
    fn secp_complaints_n17_t12() {
        check_faults::<Secp>(17, 12);
    }
    #[test]
    fn edwards_complaints_n9_t7() {
        check_faults::<Edwards>(9, 7);
    }
    #[test]
    fn edwards_complaints_n17_t12() {
        check_faults::<Edwards>(17, 12);
    }
    #[test]
    fn edwards_public_boundaries_reject_torsion() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        let torsion = EIGHT_TORSION[1];
        let mut forged = DealerMessage::<Edwards> {
            epoch: 1,
            dealer: 1,
            n: 1,
            threshold: 1,
            slot_ids: vec![1],
            ephemeral: torsion,
            commitments: vec![vec![Edwards::generator_mul(Edwards::scalar_one())]; 2],
            encrypted_shares: BTreeMap::from([(1, vec![Edwards::scalar_one(); 2])]),
            proof: DealerProof {
                nonce: Edwards::identity(),
                response: Edwards::scalar_zero(),
            },
        };
        // Grind a small-subgroup forgery against the raw proof equation.
        let mut found = false;
        for counter in 1..256 {
            let response = Edwards::scalar_from_u64(counter);
            forged.proof.nonce = Edwards::generator_mul(response);
            forged.proof.response = response;
            let c = forged.proof_challenge(forged.proof.nonce).unwrap();
            if Edwards::generator_mul(response) == forged.proof.nonce + Edwards::mul(torsion, c) {
                found = true;
                break;
            }
        }
        assert!(found);
        assert_eq!(forged.verify(), Err(Error::Point));
        let mut rng = TestRng::default();
        let secrets: BTreeMap<_, _> = (1..=9).map(|i| (i, Edwards::random(&mut rng))).collect();
        let keys = secrets
            .iter()
            .map(|(&i, &s)| (i, Edwards::generator_mul(s)))
            .collect();
        let message = malicious::<Edwards>(9, 7, &keys, &mut rng);
        let checked = decrypt_and_check(&message, 9, secrets[&9], &mut rng).unwrap();
        for field in 0..3 {
            let mut bad = checked.complaints[0].clone();
            match field {
                0 => bad.shared = torsion,
                1 => bad.proof_g = torsion,
                _ => bad.proof_e = torsion,
            }
            assert_eq!(
                verify_complaint(&message, keys[&9], &bad),
                Err(Error::Point)
            );
        }
        assert_eq!(
            verify_complaint(&message, torsion, &checked.complaints[0]),
            Err(Error::Point)
        );
        let mut bad = message.clone();
        bad.commitments[0][0] = torsion;
        assert_eq!(bad.verify(), Err(Error::Point));
        bad = message;
        bad.proof.nonce = torsion;
        assert_eq!(bad.verify(), Err(Error::Point));
    }
}
