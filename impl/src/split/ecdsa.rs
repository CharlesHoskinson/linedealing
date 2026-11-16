//! ECDSA split-line sessions. `F_presig` and `F_mul` below are IDEAL
//! functionalities: this simulator knows their inputs. O1, O2 and O19 remain
//! open. The public DLEQ, correction, contribution and signature checks are real.

use super::access::{Gate, LeafId};
use super::birth::{ActorShares, Committee};
use super::group::{mul_small, Secp, Suite};
use crate::algebra::{encode_point, inverse, is_odd, lagrange, random_nonzero, reduce, x_bytes};
use crate::{Error, Result};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId};
use k256::elliptic_curve::zeroize::Zeroize;
use k256::elliptic_curve::{rand_core::CryptoRngCore, scalar::IsHigh, sec1::ToEncodedPoint, Field};
use k256::{ProjectivePoint as Point, Scalar};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn polynomial(constant: Scalar, threshold: usize, rng: &mut impl CryptoRngCore) -> Vec<Scalar> {
    let mut p = vec![constant];
    p.extend((1..threshold).map(|_| Scalar::random(&mut *rng)));
    p
}
fn eval(p: &[Scalar], i: u16) -> Scalar {
    p.iter()
        .rev()
        .fold(Scalar::ZERO, |v, c| v * Scalar::from(i as u64) + c)
}
fn eval_points(p: &[Point], i: u16) -> Point {
    p.iter()
        .rev()
        .fold(Point::IDENTITY, |v, c| mul_small::<Secp>(v, i) + c)
}
fn commit(p: &[Scalar], base: Point) -> Vec<Point> {
    p.iter().map(|c| base * c).collect()
}
fn append_point(bytes: &mut Vec<u8>, p: Point) {
    let encoded = p.to_affine().to_encoded_point(true);
    bytes.push(encoded.as_bytes().len() as u8);
    bytes.extend_from_slice(encoded.as_bytes());
}
/// Canonical leaf-set digest. Duplicate leaves are rejected, not deduplicated.
pub fn leaf_set_hash(set: &[LeafId]) -> Result<[u8; 32]> {
    let sorted: BTreeSet<_> = set.iter().collect();
    if sorted.is_empty() || sorted.len() != set.len() {
        return Err(Error::Parameters);
    }
    let mut hash = Sha256::new();
    hash.update(b"SL1/ecdsa/leaf-set");
    hash.update((sorted.len() as u32).to_be_bytes());
    for leaf in sorted {
        let b = leaf.encode();
        hash.update((b.len() as u32).to_be_bytes());
        hash.update(b);
    }
    Ok(hash.finalize().into())
}

/// Batched Chaum-Pedersen proof: one exponent relates G to `public` and
/// every `bases[j]` to `products[j]`. Batch weights bind the entire statement.
#[derive(Clone, Debug)]
pub struct DleqProof {
    pub a: Point,
    pub b: Point,
    pub response: Scalar,
}
fn dleq_statement(
    context: &[u8],
    public: Point,
    bases: &[Point],
    products: &[Point],
) -> Result<(Vec<u8>, Point, Point)> {
    if bases.is_empty() || bases.len() != products.len() {
        return Err(Error::Proof);
    }
    let mut bytes = context.to_vec();
    append_point(&mut bytes, public);
    bytes.extend_from_slice(&(bases.len() as u32).to_be_bytes());
    for (b, p) in bases.iter().zip(products) {
        append_point(&mut bytes, *b);
        append_point(&mut bytes, *p);
    }
    let mut base = Point::IDENTITY;
    let mut product = Point::IDENTITY;
    for (j, (b, p)) in bases.iter().zip(products).enumerate() {
        let mut input = bytes.clone();
        input.extend_from_slice(&(j as u32).to_be_bytes());
        let weight = Secp::hash_to_scalar("SL1/ecdsa/dleq-weight", &input);
        base += *b * weight;
        product += *p * weight;
    }
    if base == Point::IDENTITY {
        return Err(Error::Proof);
    }
    Ok((bytes, base, product))
}
impl DleqProof {
    pub fn prove(
        context: &[u8],
        secret: Scalar,
        bases: &[Point],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<Point>, Self)> {
        let public = Secp::generator_mul(secret);
        let products: Vec<_> = bases.iter().map(|b| *b * secret).collect();
        let (mut bytes, base, _) = dleq_statement(context, public, bases, &products)?;
        let nonce = random_nonzero(rng);
        let a = Secp::generator_mul(nonce);
        let b = base * nonce;
        append_point(&mut bytes, a);
        append_point(&mut bytes, b);
        let challenge = Secp::hash_to_scalar("SL1/ecdsa/dleq", &bytes);
        Ok((
            products,
            Self {
                a,
                b,
                response: nonce + challenge * secret,
            },
        ))
    }
    pub fn verify(
        &self,
        context: &[u8],
        public: Point,
        bases: &[Point],
        products: &[Point],
    ) -> Result<()> {
        let (mut bytes, base, product) = dleq_statement(context, public, bases, products)?;
        append_point(&mut bytes, self.a);
        append_point(&mut bytes, self.b);
        let c = Secp::hash_to_scalar("SL1/ecdsa/dleq", &bytes);
        if Secp::generator_mul(self.response) != self.a + public * c
            || base * self.response != self.b + product * c
        {
            return Err(Error::Proof);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PartyTranscript {
    pub leaf: LeafId,
    pub part_public: Point,
    pub phi_products: Vec<Point>,
    pub proof: DleqProof,
    pub w_commitments: Vec<Point>,
    pub mu_commitments: Vec<Point>,
}
/// Public evidence for steps 1, 2, 5 and 6. Secret functionality inputs are
/// deliberately absent. Nonce-chain multiplication is checked by step 6.
#[derive(Clone, Debug)]
pub struct SetupTranscript {
    pub nonce_chain: Vec<Point>,
    pub phi: Vec<Point>,
    pub psi: Vec<Point>,
    pub parties: Vec<PartyTranscript>,
    pub actor_multiplications: usize,
    pub committee_multiplications: usize,
}
#[derive(Clone, Debug)]
pub struct LeafCommitment {
    pub w: Vec<Point>,
    pub mu: Vec<Point>,
    pub index: u16,
}
impl LeafCommitment {
    pub fn points(&self) -> (Point, Point) {
        (
            eval_points(&self.w, self.index),
            eval_points(&self.mu, self.index),
        )
    }
}
#[derive(Clone, Debug)]
enum HalfTree {
    Leaf(LeafId),
    And(Vec<HalfTree>),
    Threshold {
        w: Vec<Vec<Point>>,
        mu: Vec<Vec<Point>>,
        children: Vec<HalfTree>,
    },
    Or(Vec<HalfTree>),
}
/// All nodes hold this record, including escrow commitments keyed by LeafId.
#[derive(Clone, Debug)]
pub struct SlotRecord {
    pub slot: u64,
    pub nonce: Point,
    pub r: Scalar,
    pub public: Point,
    pub committee_public: Point,
    pub threshold: usize,
    pub n: u16,
    pub leaf_set_hash: [u8; 32],
    pub gate: Gate,
    pub leaves: BTreeMap<LeafId, LeafCommitment>,
    pub w_commitments: Vec<Point>,
    pub mu_commitments: Vec<Point>,
    expected_parts: BTreeMap<LeafId, Point>,
    half_tree: HalfTree,
}
struct Holder {
    w: Scalar,
    mu: Scalar,
    binding: [u8; 32],
    used: bool,
}
impl Holder {
    fn release(&mut self, binding: [u8; 32], h: Scalar, r: Scalar) -> Result<Scalar> {
        if self.binding != binding {
            return Err(Error::Context);
        }
        if self.used {
            return Err(Error::Nonce);
        }
        self.used = true;
        let value = h * self.w + r * self.mu;
        self.w.zeroize();
        self.mu.zeroize();
        Ok(value)
    }
}
impl Drop for Holder {
    fn drop(&mut self) {
        self.w.zeroize();
        self.mu.zeroize();
    }
}
struct Node {
    half: Holder,
    record: SlotRecord,
}
/// In-process experiment state. Holder states are deliberately non-Clone.
pub struct Slot {
    pub record: SlotRecord,
    pub transcript: SetupTranscript,
    holders: BTreeMap<LeafId, Holder>,
    nodes: Vec<Node>,
}
#[derive(Clone, Debug)]
pub struct Ticket {
    pub slot: u64,
    pub hash: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct Contribution {
    pub leaf: LeafId,
    pub value: Scalar,
}
#[derive(Clone, Debug)]
pub struct Partial {
    pub node: u16,
    pub value: Scalar,
}
/// Public blame evidence identifies the leaf or node whose equation fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CombineFailure {
    Invalid(Error),
    BadContribution(LeafId),
    BadPartial(u16),
}
impl From<Error> for CombineFailure {
    fn from(error: Error) -> Self {
        Self::Invalid(error)
    }
}
#[derive(Clone, Debug)]
pub struct Signature {
    pub signature: k256::ecdsa::Signature,
    pub recovery_id: RecoveryId,
}
impl Signature {
    pub fn verify(&self, public: Point, hash: &[u8; 32]) -> Result<()> {
        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&encode_point(public)?)
            .map_err(|_| Error::Point)?;
        key.verify_prehash(hash, &self.signature)
            .map_err(|_| Error::Signature)
    }
    pub fn recover(&self, hash: &[u8; 32]) -> Result<Point> {
        let key = k256::ecdsa::VerifyingKey::recover_from_prehash(
            hash,
            &self.signature,
            self.recovery_id,
        )
        .map_err(|_| Error::Signature)?;
        Ok(Point::from(*key.as_affine()))
    }
}
fn first_set(gate: &Gate) -> Vec<LeafId> {
    match gate {
        Gate::Leaf(id) => vec![id.clone()],
        Gate::And(children) => children.iter().flat_map(first_set).collect(),
        Gate::Threshold { k, children } => children.iter().take(*k).flat_map(first_set).collect(),
        Gate::Or(children) => first_set(&children[0]),
    }
}
fn session_leaves(gate: &Gate) -> Vec<LeafId> {
    match gate {
        Gate::Leaf(id) => vec![id.clone()],
        Gate::And(children) | Gate::Threshold { children, .. } => {
            children.iter().flat_map(session_leaves).collect()
        }
        Gate::Or(children) => session_leaves(&children[0]),
    }
}
fn context(record: &SlotRecord, leaf: &LeafId) -> Vec<u8> {
    let mut bytes = b"SL1/ecdsa/session".to_vec();
    bytes.extend_from_slice(&record.slot.to_be_bytes());
    bytes.extend_from_slice(&record.leaf_set_hash);
    append_point(&mut bytes, record.public);
    append_point(&mut bytes, record.nonce);
    bytes.extend_from_slice(&leaf.encode());
    bytes
}
/// IDEAL F_mul: uniformly split the product. This is not an MtA protocol.
fn ideal_mul(a: Scalar, b: Scalar, rng: &mut impl CryptoRngCore) -> (Scalar, Scalar) {
    let u = Scalar::random(rng);
    (u, a * b - u)
}
type Half = (Scalar, Scalar);
type Sources = BTreeMap<LeafId, Half>;
// Each dealer's halves remain separate through nested gates. Initial AND
// branches keep their own dealers; inherited AND shares are split additively.
#[allow(clippy::too_many_arguments)] // Recursive dealing context and its two distinct outputs.
fn distribute(
    gate: &Gate,
    sources: Option<&Sources>,
    inherited: &[Half],
    base: Point,
    binding: [u8; 32],
    rng: &mut impl CryptoRngCore,
    leaves: &mut BTreeMap<LeafId, LeafCommitment>,
    holders: &mut BTreeMap<LeafId, Holder>,
) -> Result<HalfTree> {
    let parts: Vec<Half> = sources
        .map(|s| s.values().copied().collect())
        .unwrap_or_else(|| inherited.to_vec());
    let total = parts
        .iter()
        .fold((Scalar::ZERO, Scalar::ZERO), |(w, m), (a, b)| {
            (w + a, m + b)
        });
    match gate {
        Gate::Leaf(id) => {
            leaves.insert(
                id.clone(),
                LeafCommitment {
                    w: vec![base * total.0],
                    mu: vec![base * total.1],
                    index: 1,
                },
            );
            holders.insert(
                id.clone(),
                Holder {
                    w: total.0,
                    mu: total.1,
                    binding,
                    used: false,
                },
            );
            Ok(HalfTree::Leaf(id.clone()))
        }
        Gate::And(children) => {
            let mut trees = Vec::new();
            if let Some(src) = sources {
                for child in children {
                    let ids: BTreeSet<_> = child.leaves()?.into_iter().collect();
                    let subset = src
                        .iter()
                        .filter(|(id, _)| ids.contains(*id))
                        .map(|(id, h)| (id.clone(), *h))
                        .collect();
                    trees.push(distribute(
                        child,
                        Some(&subset),
                        &[],
                        base,
                        binding,
                        rng,
                        leaves,
                        holders,
                    )?);
                }
            } else {
                let mut recipient_parts = vec![Vec::new(); children.len()];
                for part in parts {
                    let mut remaining = part;
                    for (j, recipient) in recipient_parts.iter_mut().enumerate() {
                        let split = if j + 1 == children.len() {
                            remaining
                        } else {
                            (Scalar::random(&mut *rng), Scalar::random(&mut *rng))
                        };
                        recipient.push(split);
                        remaining = (remaining.0 - split.0, remaining.1 - split.1);
                    }
                }
                for (child, parts) in children.iter().zip(recipient_parts) {
                    trees.push(distribute(
                        child, None, &parts, base, binding, rng, leaves, holders,
                    )?);
                }
            }
            Ok(HalfTree::And(trees))
        }
        Gate::Threshold { k, children } => {
            let mut ws = vec![Scalar::ZERO; *k];
            let mut ms = ws.clone();
            let mut wc = Vec::new();
            let mut mc = Vec::new();
            let mut recipient_parts = vec![Vec::new(); children.len()];
            for (w, m) in parts {
                let wp = polynomial(w, *k, rng);
                let mp = polynomial(m, *k, rng);
                wc.push(commit(&wp, base));
                mc.push(commit(&mp, base));
                for i in 0..*k {
                    ws[i] += wp[i];
                    ms[i] += mp[i];
                }
                for (j, recipient) in recipient_parts.iter_mut().enumerate() {
                    recipient.push((eval(&wp, (j + 1) as u16), eval(&mp, (j + 1) as u16)));
                }
            }
            let summed_w = commit(&ws, base);
            let summed_m = commit(&ms, base);
            let mut trees = Vec::new();
            for (j, (child, parts)) in children.iter().zip(recipient_parts).enumerate() {
                trees.push(distribute(
                    child, None, &parts, base, binding, rng, leaves, holders,
                )?);
                if let Gate::Leaf(id) = child {
                    leaves.insert(
                        id.clone(),
                        LeafCommitment {
                            w: summed_w.clone(),
                            mu: summed_m.clone(),
                            index: (j + 1) as u16,
                        },
                    );
                }
            }
            Ok(HalfTree::Threshold {
                w: wc,
                mu: mc,
                children: trees,
            })
        }
        Gate::Or(children) => {
            let mut trees = Vec::new();
            for (j, child) in children.iter().enumerate() {
                trees.push(distribute(
                    child,
                    if j == 0 { sources } else { None },
                    &parts,
                    base,
                    binding,
                    rng,
                    leaves,
                    holders,
                )?);
            }
            Ok(HalfTree::Or(trees))
        }
    }
}
fn verify_tree(
    tree: &HalfTree,
    gate: &Gate,
    leaves: &BTreeMap<LeafId, LeafCommitment>,
) -> Result<(Point, Point)> {
    match (tree, gate) {
        (HalfTree::Leaf(id), Gate::Leaf(expected)) if id == expected => {
            let c = leaves.get(id).ok_or(Error::Share)?;
            if c.w.is_empty() || c.w.len() != c.mu.len() || c.index == 0 {
                return Err(Error::Share);
            }
            Ok(c.points())
        }
        (HalfTree::And(trees), Gate::And(gates)) if trees.len() == gates.len() => {
            let mut sum = (Point::IDENTITY, Point::IDENTITY);
            for (tree, gate) in trees.iter().zip(gates) {
                let p = verify_tree(tree, gate, leaves)?;
                sum.0 += p.0;
                sum.1 += p.1;
            }
            Ok(sum)
        }
        (HalfTree::Or(trees), Gate::Or(gates))
            if trees.len() == gates.len() && !trees.is_empty() =>
        {
            let first = verify_tree(&trees[0], &gates[0], leaves)?;
            for (tree, gate) in trees.iter().zip(gates).skip(1) {
                if verify_tree(tree, gate, leaves)? != first {
                    return Err(Error::Share);
                }
            }
            Ok(first)
        }
        (HalfTree::Threshold { w, mu, children }, Gate::Threshold { k, children: gates })
            if children.len() == gates.len() =>
        {
            if w.is_empty() || w.len() != mu.len() || w.iter().chain(mu).any(|p| p.len() != *k) {
                return Err(Error::Share);
            }
            let mut wc = vec![Point::IDENTITY; *k];
            let mut mc = wc.clone();
            for (wp, mp) in w.iter().zip(mu) {
                for i in 0..*k {
                    wc[i] += wp[i];
                    mc[i] += mp[i];
                }
            }
            for (j, (tree, gate)) in children.iter().zip(gates).enumerate() {
                if verify_tree(tree, gate, leaves)?
                    != (
                        eval_points(&wc, (j + 1) as u16),
                        eval_points(&mc, (j + 1) as u16),
                    )
                {
                    return Err(Error::Share);
                }
            }
            Ok((wc[0], mc[0]))
        }
        _ => Err(Error::Context),
    }
}
impl Slot {
    /// Simulate DESIGN 3.6 with IDEAL F_presig/F_mul, then execute the real
    /// public checks. `actors` contains all nested group and escrow shares.
    pub fn ideal(
        slot: u64,
        committee: &Committee<Secp>,
        actors: &ActorShares<Secp>,
        tweak: Scalar,
        leaf_set: &[LeafId],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        actors.gate.weights::<Secp>(leaf_set)?;
        let binding = leaf_set_hash(leaf_set)?;
        let n = committee.n as usize;
        let t = committee.threshold;
        if t == 0 || t > n || committee.shares.len() != n {
            return Err(Error::Threshold);
        }
        let birth_set = first_set(&actors.gate);
        let weights = actors.gate.weights::<Secp>(&birth_set)?;
        let party_ids = session_leaves(&actors.gate);
        if party_ids.is_empty() {
            return Err(Error::Parameters);
        }
        let m = party_ids.len();
        let mut xp = Vec::new();
        let mut expected_parts = BTreeMap::new();
        for (j, id) in party_ids.iter().enumerate() {
            let weight = weights.get(id).copied().unwrap_or(Scalar::ZERO);
            let extra = if j == 0 { tweak } else { Scalar::ZERO };
            let part = *actors.shares.get(id).ok_or(Error::Share)? * weight + extra;
            let public =
                *actors.points.get(id).ok_or(Error::Share)? * weight + Secp::generator_mul(extra);
            if Secp::generator_mul(part) != public {
                return Err(Error::Share);
            }
            xp.push(part);
            expected_parts.insert(id.clone(), public);
        }
        let public = committee.public + actors.public + Secp::generator_mul(tweak);
        if expected_parts
            .values()
            .copied()
            .fold(committee.public, |a, b| a + b)
            != public
        {
            return Err(Error::Share);
        }
        encode_point(public)?;
        // IDEAL F_presig reconstructs x_f inside the simulator. No secure
        // distributed realization at t=n-f is claimed (O1/O2/O19).
        let indices: Vec<_> = (1..=t as u16).collect();
        let lambdas = lagrange(&indices)?;
        let xf = lambdas
            .iter()
            .zip(&committee.shares)
            .fold(Scalar::ZERO, |a, (l, s)| a + *l * s);
        if Secp::generator_mul(xf) != committee.public {
            return Err(Error::Share);
        }
        let kf = random_nonzero(rng);
        let rf = Secp::generator_mul(kf);
        let phi = polynomial(inverse(kf)?, t, rng);
        let psi = polynomial(inverse(kf)? * xf, t, rng);
        let phi_com = commit(&phi, rf);
        let psi_com = commit(&psi, rf);
        let mut chain = vec![rf];
        let mut inv = Vec::new();
        for _ in 0..m {
            let k = random_nonzero(rng);
            chain.push(*chain.last().ok_or(Error::Nonce)? * k);
            inv.push(inverse(k)?);
        }
        let nonce = *chain.last().ok_or(Error::Nonce)?;
        let r = reduce(&x_bytes(nonce)?);
        if r == Scalar::ZERO {
            return Err(Error::Nonce);
        }
        let mut alpha = vec![Scalar::ZERO; m];
        alpha[0] = inv[0];
        let mut count = 0;
        for j in 1..m {
            let mut next = vec![Scalar::ZERO; m];
            for b in 0..j {
                let (u, v) = ideal_mul(alpha[b], inv[j], rng);
                next[b] += u;
                next[j] += v;
                count += 1;
            }
            alpha = next;
        }
        let mut beta: Vec<_> = alpha.iter().zip(&xp).map(|(a, x)| *a * x).collect();
        for b in 0..m {
            for c in 0..m {
                if b != c {
                    let (u, v) = ideal_mul(alpha[b], xp[c], rng);
                    beta[b] += u;
                    beta[c] += v;
                    count += 1;
                }
            }
        }
        let mut wf = vec![Scalar::ZERO; n];
        let mut mf = wf.clone();
        let mut sources = Sources::new();
        let mut record = SlotRecord {
            slot,
            nonce,
            r,
            public,
            committee_public: committee.public,
            threshold: t,
            n: committee.n,
            leaf_set_hash: binding,
            gate: actors.gate.clone(),
            leaves: BTreeMap::new(),
            w_commitments: vec![],
            mu_commitments: vec![],
            expected_parts,
            half_tree: HalfTree::And(vec![]),
        };
        let mut parties = Vec::new();
        for p in 0..m {
            let w = Scalar::random(&mut *rng);
            let mu = Scalar::random(&mut *rng);
            let pw = polynomial(w, t, rng);
            let pm = polynomial(mu, t, rng);
            sources.insert(party_ids[p].clone(), (w, mu));
            for i in 1..=n {
                let id = i as u16;
                let ph = eval(&phi, id);
                let ps = eval(&psi, id);
                let (c1, d1) = ideal_mul(alpha[p], ph, rng);
                let (c2, d2) = ideal_mul(beta[p], ph, rng);
                let (c3, d3) = ideal_mul(alpha[p], ps, rng);
                wf[i - 1] += d1 + c1 - eval(&pw, id);
                mf[i - 1] += d2 + c2 + d3 + c3 - eval(&pm, id);
            }
            let (products, proof) =
                DleqProof::prove(&context(&record, &party_ids[p]), xp[p], &phi_com, rng)?;
            parties.push(PartyTranscript {
                leaf: party_ids[p].clone(),
                part_public: Secp::generator_mul(xp[p]),
                phi_products: products,
                proof,
                w_commitments: commit(&pw, nonce),
                mu_commitments: commit(&pm, nonce),
            });
        }
        record.w_commitments = phi_com.clone();
        record.mu_commitments = psi_com.clone();
        for p in &parties {
            for j in 0..t {
                record.w_commitments[j] -= p.w_commitments[j];
                record.mu_commitments[j] += p.phi_products[j] - p.mu_commitments[j];
            }
        }
        let mut holders = BTreeMap::new();
        record.half_tree = distribute(
            &actors.gate,
            Some(&sources),
            &[],
            nonce,
            binding,
            rng,
            &mut record.leaves,
            &mut holders,
        )?;
        let nodes = wf
            .into_iter()
            .zip(mf)
            .map(|(w, mu)| Node {
                half: Holder {
                    w,
                    mu,
                    binding,
                    used: false,
                },
                record: record.clone(),
            })
            .collect();
        let result = Self {
            record,
            transcript: SetupTranscript {
                nonce_chain: chain,
                phi: phi_com,
                psi: psi_com,
                parties,
                actor_multiplications: count,
                committee_multiplications: 3 * m * n,
            },
            holders,
            nodes,
        };
        result.verify_setup()?;
        Ok(result)
    }
    pub fn verify_setup(&self) -> Result<()> {
        self.record.verify_public_setup(&self.transcript)?;
        if self.nodes.len() < self.record.threshold {
            return Err(Error::Threshold);
        }
        for (j, node) in self.nodes.iter().enumerate() {
            let i = (j + 1) as u16;
            if node.half.binding != self.record.leaf_set_hash
                || (!node.half.used
                    && (self.record.nonce * node.half.w
                        != eval_points(&self.record.w_commitments, i)
                        || self.record.nonce * node.half.mu
                            != eval_points(&self.record.mu_commitments, i)))
            {
                return Err(Error::Share);
            }
        }
        for (id, half) in &self.holders {
            if half.binding != self.record.leaf_set_hash
                || (!half.used
                    && self.record.leaves.get(id).ok_or(Error::Share)?.points()
                        != (self.record.nonce * half.w, self.record.nonce * half.mu))
            {
                return Err(Error::Share);
            }
        }
        Ok(())
    }
    pub fn node_record(&self, node: u16) -> Result<&SlotRecord> {
        self.nodes
            .get(node.checked_sub(1).ok_or(Error::Parameters)? as usize)
            .map(|n| &n.record)
            .ok_or(Error::Parameters)
    }
    pub fn contribute(
        &mut self,
        leaf: &LeafId,
        set: &[LeafId],
        ticket: &Ticket,
    ) -> Result<Contribution> {
        let weights = self.record.check_request(set, ticket)?;
        let weight = *weights.get(leaf).ok_or(Error::Context)?;
        let h = reduce(&ticket.hash);
        let value = self.holders.get_mut(leaf).ok_or(Error::Share)?.release(
            leaf_set_hash(set)?,
            h,
            self.record.r,
        )? * weight;
        let result = Contribution {
            leaf: leaf.clone(),
            value,
        };
        self.record.verify_contribution(set, ticket, &result)?;
        Ok(result)
    }
    pub fn partial(&mut self, node: u16, set: &[LeafId], ticket: &Ticket) -> Result<Partial> {
        let entry = self
            .nodes
            .get_mut(node.checked_sub(1).ok_or(Error::Parameters)? as usize)
            .ok_or(Error::Parameters)?;
        entry.record.check_request(set, ticket)?;
        let value =
            entry
                .half
                .release(leaf_set_hash(set)?, reduce(&ticket.hash), entry.record.r)?;
        let partial = Partial { node, value };
        entry.record.verify_partial(ticket, &partial)?;
        Ok(partial)
    }
    /// Verify the final signature first; diagnose individual public equations
    /// only after failure. This wrapper preserves the crate's compact Error API.
    pub fn combine(
        &self,
        set: &[LeafId],
        ticket: &Ticket,
        contributions: &[Contribution],
        partials: &[Partial],
    ) -> Result<Signature> {
        self.combine_diagnosed(set, ticket, contributions, partials)
            .map_err(|failure| match failure {
                CombineFailure::Invalid(error) => error,
                CombineFailure::BadContribution(_) | CombineFailure::BadPartial(_) => Error::Share,
            })
    }
    pub fn combine_diagnosed(
        &self,
        set: &[LeafId],
        ticket: &Ticket,
        contributions: &[Contribution],
        partials: &[Partial],
    ) -> core::result::Result<Signature, CombineFailure> {
        self.record.check_request(set, ticket)?;
        let expected: BTreeSet<_> = set.iter().cloned().collect();
        let actual: BTreeSet<_> = contributions.iter().map(|c| c.leaf.clone()).collect();
        if expected != actual || actual.len() != contributions.len() {
            return Err(Error::Threshold.into());
        }
        if partials.len() < self.record.threshold
            || partials
                .iter()
                .any(|p| p.node == 0 || p.node > self.record.n)
        {
            return Err(Error::Threshold.into());
        }
        let ids: Vec<_> = partials.iter().map(|p| p.node).collect();
        let weights = lagrange(&ids)?;
        let mut s = contributions
            .iter()
            .fold(Scalar::ZERO, |sum, c| sum + c.value);
        for (p, lambda) in partials.iter().zip(weights) {
            s += p.value * lambda;
        }
        let optimistic = (|| -> Result<Signature> {
            let flipped = bool::from(s.is_high());
            let normalized = if flipped { -s } else { s };
            let signature = k256::ecdsa::Signature::from_scalars(
                self.record.r.to_bytes(),
                normalized.to_bytes(),
            )
            .map_err(|_| Error::Signature)?;
            let x = x_bytes(self.record.nonce)?;
            let reduced = self.record.r.to_bytes();
            let result = Signature {
                signature,
                recovery_id: RecoveryId::new(
                    is_odd(self.record.nonce)? ^ flipped,
                    x[..] != reduced[..],
                ),
            };
            result.verify(self.record.public, &ticket.hash)?;
            Ok(result)
        })();
        if let Ok(signature) = optimistic {
            return Ok(signature);
        }
        for c in contributions {
            if self.record.verify_contribution(set, ticket, c).is_err() {
                return Err(CombineFailure::BadContribution(c.leaf.clone()));
            }
        }
        for p in partials {
            if self.record.verify_partial(ticket, p).is_err() {
                return Err(CombineFailure::BadPartial(p.node));
            }
        }
        Err(CombineFailure::Invalid(Error::Signature))
    }
}
impl SlotRecord {
    pub fn verify_public_setup(&self, transcript: &SetupTranscript) -> Result<()> {
        self.gate.leaves()?;
        if self.threshold > self.n as usize {
            return Err(Error::Threshold);
        }
        let t = self.threshold;
        let m = transcript.parties.len();
        if t == 0
            || m == 0
            || transcript.phi.len() != t
            || transcript.psi.len() != t
            || self.w_commitments.len() != t
            || self.mu_commitments.len() != t
            || transcript.nonce_chain.len() != m + 1
            || transcript.nonce_chain.last() != Some(&self.nonce)
        {
            return Err(Error::Parameters);
        }
        for p in &transcript.nonce_chain {
            encode_point(*p)?;
        }
        if transcript.phi[0] != Point::GENERATOR || transcript.psi[0] != self.committee_public {
            return Err(Error::Proof);
        }
        if self.r == Scalar::ZERO || reduce(&x_bytes(self.nonce)?) != self.r {
            return Err(Error::Nonce);
        }
        let mut seen = BTreeSet::new();
        let mut wc = transcript.phi.clone();
        let mut mc = transcript.psi.clone();
        for p in &transcript.parties {
            if !seen.insert(p.leaf.clone())
                || self.expected_parts.get(&p.leaf) != Some(&p.part_public)
                || p.w_commitments.len() != t
                || p.mu_commitments.len() != t
            {
                return Err(Error::Proof);
            }
            p.proof.verify(
                &context(self, &p.leaf),
                p.part_public,
                &transcript.phi,
                &p.phi_products,
            )?;
            for j in 0..t {
                wc[j] -= p.w_commitments[j];
                mc[j] += p.phi_products[j] - p.mu_commitments[j];
            }
        }
        if seen.len() != self.expected_parts.len()
            || self
                .expected_parts
                .values()
                .copied()
                .fold(self.committee_public, |a, b| a + b)
                != self.public
            || wc != self.w_commitments
            || mc != self.mu_commitments
        {
            return Err(Error::Proof);
        }
        let totals = verify_tree(&self.half_tree, &self.gate, &self.leaves)?;
        if self.leaves.len() != self.gate.leaves()?.len()
            || wc[0] + totals.0 != Point::GENERATOR
            || mc[0] + totals.1 != self.public
        {
            return Err(Error::Share);
        }
        Ok(())
    }
    fn check_request(&self, set: &[LeafId], ticket: &Ticket) -> Result<BTreeMap<LeafId, Scalar>> {
        if ticket.slot != self.slot || leaf_set_hash(set)? != self.leaf_set_hash {
            return Err(Error::Context);
        }
        self.gate.weights::<Secp>(set)
    }
    pub fn verify_contribution(
        &self,
        set: &[LeafId],
        ticket: &Ticket,
        c: &Contribution,
    ) -> Result<()> {
        let weights = self.check_request(set, ticket)?;
        let lambda = *weights.get(&c.leaf).ok_or(Error::Context)?;
        let (w, mu) = self.leaves.get(&c.leaf).ok_or(Error::Share)?.points();
        if self.nonce * c.value != (w * reduce(&ticket.hash) + mu * self.r) * lambda {
            return Err(Error::Share);
        }
        Ok(())
    }
    pub fn verify_partial(&self, ticket: &Ticket, p: &Partial) -> Result<()> {
        if ticket.slot != self.slot || p.node == 0 || p.node > self.n {
            return Err(Error::Context);
        }
        if self.nonce * p.value
            != eval_points(&self.w_commitments, p.node) * reduce(&ticket.hash)
                + eval_points(&self.mu_commitments, p.node) * self.r
        {
            return Err(Error::Share);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::birth::BirthContext;
    use super::*;
    use crate::experiment::SeededRng;

    fn leaf(slot: u16, member: u16) -> Gate {
        Gate::Leaf(LeafId::new(slot, vec![], member))
    }
    fn group(slot: u16, k: usize, n: u16) -> Gate {
        Gate::Threshold {
            k,
            children: (1..=n).map(|i| leaf(slot, i)).collect(),
        }
    }
    fn fixture(
        gate: Gate,
        n: u16,
        t: usize,
        rng: &mut SeededRng,
    ) -> (Committee<Secp>, ActorShares<Secp>) {
        let committee = Committee::<Secp>::generate(n, t, rng).unwrap();
        let ctx = BirthContext {
            committee: committee.public,
            charter_id: [1; 32],
            chain_id: [2; 32],
        };
        let actors = ActorShares::generate(gate, &ctx, rng).unwrap();
        (committee, actors)
    }
    fn sign(slot: &mut Slot, set: &[LeafId], h: [u8; 32]) -> Signature {
        let ticket = Ticket {
            slot: slot.record.slot,
            hash: h,
        };
        let contributions = set
            .iter()
            .map(|id| slot.contribute(id, set, &ticket).unwrap())
            .collect::<Vec<_>>();
        let partials = (1..=slot.record.threshold as u16)
            .map(|i| slot.partial(i, set, &ticket).unwrap())
            .collect::<Vec<_>>();
        slot.combine(set, &ticket, &contributions, &partials)
            .unwrap()
    }
    #[test]
    fn ecdsa_and_one_to_five_both_committee_sizes() {
        let mut rng = SeededRng::new(400);
        for (n, t) in [(9, 7), (17, 12)] {
            for m in 1..=5 {
                let gate = Gate::And((1..=m).map(|i| leaf(i, 1)).collect());
                let set = gate.leaves().unwrap();
                let (committee, actors) = fixture(gate, n, t, &mut rng);
                let mut slot =
                    Slot::ideal(10, &committee, &actors, Scalar::from(7u64), &set, &mut rng)
                        .unwrap();
                assert_eq!(
                    slot.transcript.actor_multiplications,
                    3 * m as usize * (m as usize - 1) / 2
                );
                assert_eq!(
                    slot.transcript.committee_multiplications,
                    3 * m as usize * n as usize
                );
                slot.verify_setup().unwrap();
                let sig = sign(&mut slot, &set, [42; 32]);
                sig.verify(slot.record.public, &[42; 32]).unwrap();
                assert_eq!(sig.recover(&[42; 32]).unwrap(), slot.record.public);
            }
        }
    }
    #[test]
    fn ecdsa_group_subsets_nested_and_escrow_both_branches() {
        let mut rng = SeededRng::new(401);
        for (n, t) in [(9, 7), (17, 12)] {
            let gate = Gate::And(vec![leaf(1, 1), group(2, 2, 3)]);
            let (committee, actors) = fixture(gate, n, t, &mut rng);
            for pair in [[1, 2], [1, 3], [2, 3]] {
                let set = vec![
                    LeafId::new(1, vec![], 1),
                    LeafId::new(2, vec![], pair[0]),
                    LeafId::new(2, vec![], pair[1]),
                ];
                let mut slot =
                    Slot::ideal(20, &committee, &actors, Scalar::from(9u64), &set, &mut rng)
                        .unwrap();
                assert_eq!(slot.transcript.parties.len(), 4);
                let sig = sign(&mut slot, &set, [43; 32]);
                assert_eq!(sig.recover(&[43; 32]).unwrap(), slot.record.public);
            }
            let nested = Gate::Threshold {
                k: 2,
                children: vec![leaf(1, 1), group(2, 2, 3), leaf(1, 3)],
            };
            let set = vec![
                LeafId::new(1, vec![], 1),
                LeafId::new(2, vec![], 1),
                LeafId::new(2, vec![], 3),
            ];
            let (committee, actors) = fixture(nested, n, t, &mut rng);
            let mut slot =
                Slot::ideal(21, &committee, &actors, Scalar::from(10u64), &set, &mut rng).unwrap();
            sign(&mut slot, &set, [44; 32]);
            let gate = Gate::Or(vec![leaf(1, 1), group(2, 3, 5)]);
            let (committee, actors) = fixture(gate, n, t, &mut rng);
            for set in [
                vec![LeafId::new(1, vec![], 1)],
                vec![
                    LeafId::new(2, vec![], 2),
                    LeafId::new(2, vec![], 4),
                    LeafId::new(2, vec![], 5),
                ],
            ] {
                let mut slot =
                    Slot::ideal(22, &committee, &actors, Scalar::from(11u64), &set, &mut rng)
                        .unwrap();
                assert_eq!(slot.transcript.parties.len(), 1);
                for node in 1..=n {
                    let record = slot.node_record(node).unwrap();
                    record.verify_public_setup(&slot.transcript).unwrap();
                    for guardian in 1..=5 {
                        let commitments = &record.leaves[&LeafId::new(2, vec![], guardian)];
                        assert_eq!(commitments.w.len(), 3);
                        assert_eq!(commitments.mu.len(), 3);
                    }
                }
                sign(&mut slot, &set, [45; 32]);
            }
        }
    }
    #[test]
    fn ecdsa_public_checks_reject_mutated_proofs_shares_and_escrow() {
        let mut rng = SeededRng::new(402);
        let gate = Gate::Or(vec![leaf(1, 1), group(2, 3, 5)]);
        let set = vec![
            LeafId::new(2, vec![], 2),
            LeafId::new(2, vec![], 4),
            LeafId::new(2, vec![], 5),
        ];
        let (committee, actors) = fixture(gate, 9, 7, &mut rng);
        let mut slot =
            Slot::ideal(30, &committee, &actors, Scalar::from(12u64), &set, &mut rng).unwrap();
        let original = slot.transcript.clone();
        slot.transcript.parties[0].proof.response += Scalar::ONE;
        assert_eq!(slot.verify_setup(), Err(Error::Proof));
        slot.transcript = original.clone();
        slot.transcript.parties[0].phi_products[1] += Point::GENERATOR;
        assert_eq!(slot.verify_setup(), Err(Error::Proof));
        slot.transcript = original;
        slot.nodes[0].half.w += Scalar::ONE;
        assert_eq!(slot.verify_setup(), Err(Error::Share));
        slot.nodes[0].half.w -= Scalar::ONE;
        let escrow = set[0].clone();
        slot.record.leaves.get_mut(&escrow).unwrap().mu[0] += Point::GENERATOR;
        assert_eq!(slot.verify_setup(), Err(Error::Share));
        slot.record.leaves.get_mut(&escrow).unwrap().mu[0] -= Point::GENERATOR;
        slot.verify_setup().unwrap();
        let ticket = Ticket {
            slot: 30,
            hash: [46; 32],
        };
        let mut contributions = set
            .iter()
            .map(|id| slot.contribute(id, &set, &ticket).unwrap())
            .collect::<Vec<_>>();
        let mut partials = (1..=7)
            .map(|i| slot.partial(i, &set, &ticket).unwrap())
            .collect::<Vec<_>>();
        contributions[0].value += Scalar::ONE;
        assert_eq!(
            slot.record
                .verify_contribution(&set, &ticket, &contributions[0]),
            Err(Error::Share)
        );
        assert!(slot
            .combine(&set, &ticket, &contributions, &partials)
            .is_err());
        contributions[0].value -= Scalar::ONE;
        partials[2].value += Scalar::ONE;
        assert_eq!(
            slot.record.verify_partial(&ticket, &partials[2]),
            Err(Error::Share)
        );
        assert!(slot
            .combine(&set, &ticket, &contributions, &partials)
            .is_err());
        partials[2].value -= Scalar::ONE;
        assert!(slot
            .combine(&set, &ticket, &contributions[..2], &partials)
            .is_err());
        assert!(slot
            .combine(&set, &ticket, &contributions, &partials[..6])
            .is_err());
        slot.combine(&set, &ticket, &contributions, &partials)
            .unwrap();
    }
    fn unchecked_line(slot: &Slot, set: &[LeafId], h: Scalar) -> Scalar {
        let weights = slot.record.gate.weights::<Secp>(set).unwrap();
        weights.iter().fold(Scalar::ZERO, |sum, (id, weight)| {
            let half = &slot.holders[id];
            sum + *weight * (h * half.w + slot.record.r * half.mu)
        })
    }
    fn committee_halves(slot: &Slot) -> Half {
        let ids = (1..=slot.record.threshold as u16).collect::<Vec<_>>();
        lagrange(&ids)
            .unwrap()
            .iter()
            .zip(&slot.nodes)
            .fold((Scalar::ZERO, Scalar::ZERO), |(w, m), (l, n)| {
                (w + *l * n.half.w, m + *l * n.half.mu)
            })
    }
    #[test]
    fn ecdsa_attack_d_recovers_group_line_and_key_but_binding_refuses() {
        let mut rng = SeededRng::new(403);
        let gate = group(1, 2, 3);
        let first = vec![LeafId::new(1, vec![], 1), LeafId::new(1, vec![], 2)];
        let second = vec![LeafId::new(1, vec![], 1), LeafId::new(1, vec![], 3)];
        let (committee, actors) = fixture(gate, 9, 7, &mut rng);
        let mut slot = Slot::ideal(
            40,
            &committee,
            &actors,
            Scalar::from(13u64),
            &first,
            &mut rng,
        )
        .unwrap();
        let h1 = Scalar::from(17u64);
        let h2 = Scalar::from(29u64);
        // B and C each answer once, A and the committee are corrupt. This
        // intentionally bypasses the local policy to reproduce check.py (d).
        let u1 = unchecked_line(&slot, &first, h1);
        let u2 = unchecked_line(&slot, &second, h2);
        let w = (u1 - u2) * inverse(h1 - h2).unwrap();
        let mu = (u1 - h1 * w) * inverse(slot.record.r).unwrap();
        let points = verify_tree(
            &slot.record.half_tree,
            &slot.record.gate,
            &slot.record.leaves,
        )
        .unwrap();
        assert_eq!((slot.record.nonce * w, slot.record.nonce * mu), points);
        let (wf, mf) = committee_halves(&slot);
        let x = (mf + mu) * inverse(wf + w).unwrap();
        assert_eq!(Secp::generator_mul(x), slot.record.public);
        let ticket1 = Ticket {
            slot: 40,
            hash: h1.to_bytes().into(),
        };
        let ticket2 = Ticket {
            slot: 40,
            hash: h2.to_bytes().into(),
        };
        slot.contribute(&first[1], &first, &ticket1).unwrap();
        assert_eq!(slot.holders[&first[1]].w, Scalar::ZERO);
        assert_eq!(slot.holders[&first[1]].mu, Scalar::ZERO);
        assert_eq!(
            slot.contribute(&second[1], &second, &ticket2).unwrap_err(),
            Error::Context
        );
        assert_eq!(
            slot.contribute(&first[1], &first, &ticket2).unwrap_err(),
            Error::Nonce
        );
        assert_eq!(
            slot.contribute(&first[1], &first, &ticket1).unwrap_err(),
            Error::Nonce
        );
        slot.partial(1, &first, &ticket1).unwrap();
        assert_eq!(slot.nodes[0].half.w, Scalar::ZERO);
        assert_eq!(slot.nodes[0].half.mu, Scalar::ZERO);
        assert_eq!(slot.partial(1, &first, &ticket2).unwrap_err(), Error::Nonce);
        assert_eq!(
            slot.partial(2, &second, &ticket2).unwrap_err(),
            Error::Context
        );
        // A silent B does not prevent using a distinct slot reserved for A,C.
        let mut independent = Slot::ideal(
            41,
            &committee,
            &actors,
            Scalar::from(13u64),
            &second,
            &mut rng,
        )
        .unwrap();
        assert_eq!(slot.record.public, independent.record.public);
        sign(&mut independent, &second, [47; 32]);
    }
    #[test]
    fn ecdsa_attack_d_escrow_branch_recovery_and_primary_refusal() {
        let mut rng = SeededRng::new(404);
        let gate = Gate::Or(vec![leaf(1, 1), group(2, 3, 5)]);
        let primary = vec![LeafId::new(1, vec![], 1)];
        let guardians = vec![
            LeafId::new(2, vec![], 2),
            LeafId::new(2, vec![], 4),
            LeafId::new(2, vec![], 5),
        ];
        let (committee, actors) = fixture(gate, 17, 12, &mut rng);
        let mut slot = Slot::ideal(
            50,
            &committee,
            &actors,
            Scalar::from(14u64),
            &guardians,
            &mut rng,
        )
        .unwrap();
        let h1 = Scalar::from(31u64);
        let h2 = Scalar::from(41u64);
        let u1 = unchecked_line(&slot, &primary, h1);
        let u2 = unchecked_line(&slot, &guardians, h2);
        let w = (u1 - u2) * inverse(h1 - h2).unwrap();
        let mu = (u1 - h1 * w) * inverse(slot.record.r).unwrap();
        assert_eq!(w, slot.holders[&primary[0]].w);
        assert_eq!(mu, slot.holders[&primary[0]].mu);
        let (wf, mf) = committee_halves(&slot);
        assert_eq!(
            Secp::generator_mul((mf + mu) * inverse(wf + w).unwrap()),
            slot.record.public
        );
        let ticket = Ticket {
            slot: 50,
            hash: [48; 32],
        };
        assert_eq!(
            slot.contribute(&primary[0], &primary, &ticket).unwrap_err(),
            Error::Context
        );
        assert_eq!(
            slot.contribute(&primary[0], &guardians, &ticket)
                .unwrap_err(),
            Error::Context
        );
        for (id, half) in &slot.holders {
            assert_eq!(half.binding, slot.record.leaf_set_hash, "{id:?}");
        }
        sign(&mut slot, &guardians, [48; 32]);
        assert_eq!(
            slot.contribute(&guardians[0], &guardians, &ticket)
                .unwrap_err(),
            Error::Nonce
        );
    }
    #[test]
    fn ecdsa_low_s_flips_recovery_parity_and_dleq_zero_exponent() {
        let mut rng = SeededRng::new(405);
        let gate = group(1, 2, 3);
        let set = first_set(&gate);
        let (committee, actors) = fixture(gate, 9, 7, &mut rng);
        let mut seen = [false; 2];
        for index in 0..12 {
            let mut slot = Slot::ideal(
                index,
                &committee,
                &actors,
                Scalar::from(15u64),
                &set,
                &mut rng,
            )
            .unwrap();
            // The third session party is outside T0 and proves x'_p=0.
            assert_eq!(slot.transcript.parties[2].part_public, Point::IDENTITY);
            slot.verify_setup().unwrap();
            let hash = [49; 32];
            let h = reduce(&hash);
            let (w, m) = committee_halves(&slot);
            let raw = unchecked_line(&slot, &set, h) + h * w + slot.record.r * m;
            let high = bool::from(raw.is_high());
            seen[high as usize] = true;
            let sig = sign(&mut slot, &set, hash);
            assert!(!bool::from(sig.signature.s().is_high()));
            assert_eq!(
                sig.recovery_id.is_y_odd(),
                is_odd(slot.record.nonce).unwrap() ^ high
            );
            assert_eq!(sig.recover(&hash).unwrap(), slot.record.public);
        }
        assert_eq!(seen, [true, true]);
    }
    #[test]
    fn ecdsa_leaf_hash_order_and_invalid_requests() {
        let mut rng = SeededRng::new(406);
        let gate = group(1, 2, 3);
        let set = first_set(&gate);
        let mut reversed = set.clone();
        reversed.reverse();
        assert_eq!(
            leaf_set_hash(&set).unwrap(),
            leaf_set_hash(&reversed).unwrap()
        );
        assert!(leaf_set_hash(&[set[0].clone(), set[0].clone()]).is_err());
        let (committee, actors) = fixture(gate, 9, 7, &mut rng);
        assert!(Slot::ideal(60, &committee, &actors, Scalar::ONE, &set[..1], &mut rng).is_err());
        let mut slot = Slot::ideal(60, &committee, &actors, Scalar::ONE, &set, &mut rng).unwrap();
        let bad = Ticket {
            slot: 61,
            hash: [50; 32],
        };
        assert_eq!(
            slot.contribute(&set[0], &set, &bad).unwrap_err(),
            Error::Context
        );
        let ticket = Ticket {
            slot: 60,
            hash: [50; 32],
        };
        assert_eq!(
            slot.contribute(&set[0], &set[..1], &ticket).unwrap_err(),
            Error::Context
        );
        sign(&mut slot, &reversed, [50; 32]);
    }
    #[test]
    fn ecdsa_malformed_public_transcripts_return_errors() {
        let mut rng = SeededRng::new(407);
        let gate = group(1, 2, 3);
        let set = first_set(&gate);
        let (committee, actors) = fixture(gate, 9, 7, &mut rng);
        let slot = Slot::ideal(70, &committee, &actors, Scalar::ONE, &set, &mut rng).unwrap();
        let mut transcript = slot.transcript.clone();
        transcript.parties[0].phi_products.clear();
        assert!(slot.record.verify_public_setup(&transcript).is_err());
        let mut transcript = slot.transcript.clone();
        transcript.phi.clear();
        assert!(slot.record.verify_public_setup(&transcript).is_err());
        let mut transcript = slot.transcript.clone();
        transcript.nonce_chain.clear();
        assert!(slot.record.verify_public_setup(&transcript).is_err());
        let mut record = slot.record.clone();
        record.gate = Gate::Threshold {
            k: 0,
            children: vec![],
        };
        assert!(record.verify_public_setup(&slot.transcript).is_err());
        let ticket = Ticket {
            slot: 70,
            hash: [51; 32],
        };
        for node in [0, 10, u16::MAX] {
            assert!(slot
                .record
                .verify_partial(
                    &ticket,
                    &Partial {
                        node,
                        value: Scalar::ZERO
                    }
                )
                .is_err());
        }
    }
}
