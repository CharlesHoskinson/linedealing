//! In-process DKG and recursive address birth (DESIGN §3.1–3.8).
//! Dealer transport, board certificates and secret erasure are external adapters.
use super::{
    access::{Gate, LeafId},
    group::{commitments, evaluate_commitments, evaluate_scalar, random_polynomial, Secp, Suite},
};
use crate::{Error, Result};
use k256::elliptic_curve::rand_core::CryptoRngCore;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct KnowledgeProof<S: Suite> {
    pub nonce: S::Point,
    pub response: S::Scalar,
}
impl<S: Suite> KnowledgeProof<S> {
    pub fn create(secret: S::Scalar, context: &[u8], rng: &mut impl CryptoRngCore) -> Result<Self> {
        let public = S::generator_mul(secret);
        let nonce = S::random(rng);
        let r = S::generator_mul(nonce);
        let c = Self::challenge(public, r, context)?;
        Ok(Self {
            nonce: r,
            response: nonce + c * secret,
        })
    }
    fn challenge(public: S::Point, nonce: S::Point, context: &[u8]) -> Result<S::Scalar> {
        let mut bytes = vec![S::SUITE_ID];
        crate::hash::length_prefixed(&mut bytes, context)?;
        for point in S::encode_points(&[public, nonce])? {
            bytes.extend_from_slice(&point);
        }
        Ok(S::hash_to_scalar("SL1/pop", &bytes))
    }
    pub fn verify(&self, public: S::Point, context: &[u8]) -> Result<()> {
        S::validate_point(public)?;
        S::validate_point(self.nonce)?;
        let c = Self::challenge(public, self.nonce, context)?;
        if S::generator_mul(self.response) != self.nonce + S::mul(public, c) {
            return Err(Error::Proof);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct BirthContext<S: Suite> {
    pub committee: S::Point,
    pub charter_id: [u8; 32],
    pub chain_id: [u8; 32],
}
impl<S: Suite> BirthContext<S> {
    pub fn actor_context(&self, point: S::Point, slot: u16) -> Result<Vec<u8>> {
        let mut out = b"SL1/pop".to_vec();
        for p in S::encode_points(&[self.committee, point])? {
            out.extend_from_slice(&p);
        }
        out.extend_from_slice(&slot.to_be_bytes());
        out.extend_from_slice(&self.charter_id);
        out.extend_from_slice(&self.chain_id);
        Ok(out)
    }
    fn tree_context(&self, gate: &Gate, path: &[u16]) -> Result<Vec<u8>> {
        let mut out = b"SL1/birth-tree".to_vec();
        out.extend_from_slice(&S::encode_point(self.committee)?);
        out.extend_from_slice(&self.charter_id);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&gate.hash()?);
        out.extend_from_slice(&(path.len() as u16).to_be_bytes());
        for p in path {
            out.extend_from_slice(&p.to_be_bytes());
        }
        Ok(out)
    }
}

#[derive(Clone, Debug)]
pub struct Dealer<S: Suite> {
    pub id: u16,
    pub commitments: Vec<S::Point>,
    pub proof: KnowledgeProof<S>,
    pub shares: Vec<S::Scalar>,
}
fn dealer_context(base: &[u8], id: u16) -> Vec<u8> {
    let mut out = base.to_vec();
    out.extend_from_slice(&id.to_be_bytes());
    out
}
impl<S: Suite> Dealer<S> {
    pub fn create(
        id: u16,
        n: u16,
        threshold: usize,
        constant: S::Scalar,
        context: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if id == 0 || threshold > n as usize || n == 0 {
            return Err(Error::Threshold);
        }
        let coefficients = random_polynomial::<S>(constant, threshold, rng)?;
        let shares = (1..=n)
            .map(|i| evaluate_scalar::<S>(&coefficients, i))
            .collect::<Result<_>>()?;
        Ok(Self {
            id,
            commitments: commitments::<S>(&coefficients),
            proof: KnowledgeProof::create(constant, &dealer_context(context, id), rng)?,
            shares,
        })
    }
    /// A failed Feldman equation is a valid complaint in this in-process simulation.
    pub fn verify(&self, n: u16, threshold: usize, context: &[u8]) -> Result<()> {
        if self.id == 0
            || self.commitments.len() != threshold
            || self.shares.len() != n as usize
            || threshold == 0
        {
            return Err(Error::Parameters);
        }
        self.proof
            .verify(self.commitments[0], &dealer_context(context, self.id))?;
        S::encode_points(&self.commitments)?;
        for point in &self.commitments {
            S::validate_point(*point)?;
        }
        for (i, share) in self.shares.iter().enumerate() {
            if S::generator_mul(*share)
                != evaluate_commitments::<S>(&self.commitments, (i + 1) as u16)?
            {
                return Err(Error::Share);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Committee<S: Suite> {
    pub n: u16,
    pub threshold: usize,
    pub public: S::Point,
    pub shares: Vec<S::Scalar>,
    pub commitments: Vec<S::Point>,
    pub share_points: Vec<S::Point>,
    pub qualified: Vec<u16>,
}
impl<S: Suite> Committee<S> {
    pub fn context(n: u16, threshold: usize) -> Vec<u8> {
        let mut out = b"SL1/dkg-root".to_vec();
        out.push(S::SUITE_ID);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&(threshold as u64).to_be_bytes());
        out
    }
    pub fn generate(n: u16, threshold: usize, rng: &mut impl CryptoRngCore) -> Result<Self> {
        if threshold == 0 || threshold > n as usize {
            return Err(Error::Threshold);
        }
        let context = Self::context(n, threshold);
        let dealers = (1..=n)
            .map(|id| Dealer::create(id, n, threshold, S::random(rng), &context, rng))
            .collect::<Result<Vec<_>>>()?;
        Self::from_dealers(n, threshold, &dealers)
    }
    /// Input order is board order; take the first t distinct dealers without a valid complaint.
    pub fn from_dealers(n: u16, threshold: usize, dealers: &[Dealer<S>]) -> Result<Self> {
        if threshold == 0 || threshold > n as usize {
            return Err(Error::Threshold);
        }
        let context = Self::context(n, threshold);
        let mut seen = BTreeSet::new();
        let mut qualified = Vec::new();
        let mut sum = vec![S::identity(); threshold];
        let mut shares = vec![S::scalar_zero(); n as usize];
        for dealer in dealers {
            if dealer.id > n || !seen.insert(dealer.id) {
                return Err(Error::Parameters);
            }
            if dealer.verify(n, threshold, &context).is_err() {
                continue;
            }
            qualified.push(dealer.id);
            for (a, b) in sum.iter_mut().zip(&dealer.commitments) {
                *a = *a + *b;
            }
            for (a, b) in shares.iter_mut().zip(&dealer.shares) {
                *a = *a + *b;
            }
            if qualified.len() == threshold {
                break;
            }
        }
        if qualified.len() != threshold {
            return Err(Error::Threshold);
        }
        S::encode_point(sum[0])?;
        let share_points = (1..=n)
            .map(|i| evaluate_commitments::<S>(&sum, i))
            .collect::<Result<_>>()?;
        Ok(Self {
            n,
            threshold,
            public: sum[0],
            shares,
            commitments: sum,
            share_points,
            qualified,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PublicDealer<S: Suite> {
    pub id: u16,
    pub commitments: Vec<S::Point>,
    pub proof: KnowledgeProof<S>,
}
#[derive(Clone, Debug)]
pub enum PublicTree<S: Suite> {
    Network(NetworkShard<S>),
    Leaf {
        point: S::Point,
        proof: KnowledgeProof<S>,
    },
    And(Vec<PublicTree<S>>),
    Threshold {
        dealers: Vec<PublicDealer<S>>,
        children: Vec<PublicTree<S>>,
    },
    Or(Vec<PublicTree<S>>),
}
pub type VerifiedTree<S> = (<S as Suite>::Point, BTreeMap<LeafId, <S as Suite>::Point>);
impl<S: Suite> PublicTree<S> {
    fn verify_at(
        &self,
        gate: &Gate,
        root: &Gate,
        context: &BirthContext<S>,
        path: &mut Vec<u16>,
        points: &mut BTreeMap<LeafId, S::Point>,
    ) -> Result<S::Point> {
        let binding = context.tree_context(root, path)?;
        match (self, gate) {
            (Self::Network(shard), Gate::Leaf(id)) => {
                if shard.slot != id.slot {
                    return Err(Error::Context);
                }
                shard.verify(context)?;
                points.insert(id.clone(), shard.public);
                Ok(shard.public)
            }
            (Self::Leaf { point, proof }, Gate::Leaf(id)) => {
                let mut ctx = context.actor_context(*point, id.slot)?;
                ctx.extend_from_slice(&binding);
                ctx.extend_from_slice(&id.encode());
                proof.verify(*point, &ctx)?;
                points.insert(id.clone(), *point);
                Ok(*point)
            }
            (Self::And(tree), Gate::And(children))
            | (Self::Or(tree), Gate::Or(children))
            | (Self::Threshold { children: tree, .. }, Gate::Threshold { children, .. }) => {
                if tree.len() != children.len() {
                    return Err(Error::Parameters);
                }
                let mut child_points = Vec::new();
                for (i, (node, g)) in tree.iter().zip(children).enumerate() {
                    path.push((i + 1) as u16);
                    let p = node.verify_at(g, root, context, path, points)?;
                    path.pop();
                    child_points.push(p);
                }
                match (self, gate) {
                    (Self::And(_), _) => Ok(child_points.iter().fold(S::identity(), |a, b| a + *b)),
                    (Self::Or(_), _) => {
                        if child_points.iter().any(|p| *p != child_points[0]) {
                            return Err(Error::Share);
                        }
                        Ok(child_points[0])
                    }
                    (Self::Threshold { dealers, .. }, Gate::Threshold { k, .. }) => {
                        if dealers.len() != children.len() {
                            return Err(Error::Threshold);
                        }
                        let mut sum = vec![S::identity(); *k];
                        let mut ids = BTreeSet::new();
                        for dealer in dealers {
                            if dealer.id == 0
                                || dealer.id as usize > children.len()
                                || !ids.insert(dealer.id)
                                || dealer.commitments.len() != *k
                            {
                                return Err(Error::Parameters);
                            }
                            S::encode_points(&dealer.commitments)?;
                            for point in &dealer.commitments {
                                S::validate_point(*point)?;
                            }
                            dealer.proof.verify(
                                dealer.commitments[0],
                                &dealer_context(&binding, dealer.id),
                            )?;
                            for (a, b) in sum.iter_mut().zip(&dealer.commitments) {
                                *a = *a + *b;
                            }
                        }
                        for (i, point) in child_points.iter().enumerate() {
                            if *point != evaluate_commitments::<S>(&sum, (i + 1) as u16)? {
                                return Err(Error::Share);
                            }
                        }
                        S::encode_point(sum[0])?;
                        Ok(sum[0])
                    }
                    _ => Err(Error::Parameters),
                }
            }
            _ => Err(Error::Parameters),
        }
    }
    pub fn verify(&self, gate: &Gate, context: &BirthContext<S>) -> Result<VerifiedTree<S>> {
        gate.validate()?;
        let mut points = BTreeMap::new();
        let public = self.verify_at(gate, gate, context, &mut Vec::new(), &mut points)?;
        S::encode_point(public)?;
        Ok((public, points))
    }
}
#[derive(Clone, Debug)]
pub struct ActorShares<S: Suite> {
    pub gate: Gate,
    pub public: S::Point,
    pub shares: BTreeMap<LeafId, S::Scalar>,
    pub points: BTreeMap<LeafId, S::Point>,
    pub tree: PublicTree<S>,
}
fn split_secret<S: Suite>(
    secret: S::Scalar,
    count: usize,
    rng: &mut impl CryptoRngCore,
) -> Vec<S::Scalar> {
    loop {
        let mut parts: Vec<_> = (1..count).map(|_| S::random(rng)).collect();
        let sum = parts.iter().fold(S::scalar_zero(), |a, b| a + *b);
        let last = secret - sum;
        if last != S::scalar_zero() {
            parts.push(last);
            return parts;
        }
    }
}
impl<S: Suite> ActorShares<S> {
    pub fn generate(
        gate: Gate,
        context: &BirthContext<S>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        gate.validate()?;
        fn deal<S: Suite>(
            gate: &Gate,
            root: &Gate,
            forced: Option<S::Scalar>,
            context: &BirthContext<S>,
            path: &mut Vec<u16>,
            shares: &mut BTreeMap<LeafId, S::Scalar>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<(S::Scalar, PublicTree<S>)> {
            let binding = context.tree_context(root, path)?;
            match gate {
                Gate::Leaf(id) => {
                    let secret = forced.unwrap_or_else(|| S::random(rng));
                    let point = S::generator_mul(secret);
                    let mut ctx = context.actor_context(point, id.slot)?;
                    ctx.extend_from_slice(&binding);
                    ctx.extend_from_slice(&id.encode());
                    let proof = KnowledgeProof::create(secret, &ctx, rng)?;
                    shares.insert(id.clone(), secret);
                    Ok((secret, PublicTree::Leaf { point, proof }))
                }
                Gate::And(children) | Gate::Or(children) | Gate::Threshold { children, .. } => {
                    let (secret, constants, dealers) = match gate {
                        Gate::And(_) => {
                            let constants = match forced {
                                Some(x) => split_secret::<S>(x, children.len(), rng),
                                None => (0..children.len()).map(|_| S::random(rng)).collect(),
                            };
                            let sum = constants.iter().fold(S::scalar_zero(), |a, b| a + *b);
                            (sum, constants, vec![])
                        }
                        Gate::Or(_) => {
                            let x = forced.unwrap_or_else(|| S::random(rng));
                            (x, vec![x; children.len()], vec![])
                        }
                        Gate::Threshold { k, .. } => {
                            let cs = match forced {
                                Some(x) => split_secret::<S>(x, children.len(), rng),
                                None => (0..children.len()).map(|_| S::random(rng)).collect(),
                            };
                            let mut constants = vec![S::scalar_zero(); children.len()];
                            let mut dealers = Vec::new();
                            let mut secret = S::scalar_zero();
                            for (i, c) in cs.into_iter().enumerate() {
                                let d = Dealer::<S>::create(
                                    (i + 1) as u16,
                                    children.len() as u16,
                                    *k,
                                    c,
                                    &binding,
                                    rng,
                                )?;
                                secret = secret + c;
                                for (a, b) in constants.iter_mut().zip(d.shares) {
                                    *a = *a + b;
                                }
                                dealers.push(PublicDealer {
                                    id: d.id,
                                    commitments: d.commitments,
                                    proof: d.proof,
                                });
                            }
                            (secret, constants, dealers)
                        }
                        _ => unreachable!(),
                    };
                    let mut tree = Vec::new();
                    for (i, (child, x)) in children.iter().zip(constants).enumerate() {
                        path.push((i + 1) as u16);
                        let (_, node) = deal(child, root, Some(x), context, path, shares, rng)?;
                        path.pop();
                        tree.push(node);
                    }
                    let node = match gate {
                        Gate::And(_) => PublicTree::And(tree),
                        Gate::Or(_) => PublicTree::Or(tree),
                        _ => PublicTree::Threshold {
                            dealers,
                            children: tree,
                        },
                    };
                    Ok((secret, node))
                }
            }
        }
        let mut shares = BTreeMap::new();
        let (_, tree) = deal(
            &gate,
            &gate,
            None,
            context,
            &mut Vec::new(),
            &mut shares,
            rng,
        )?;
        let (public, points) = tree.verify(&gate, context)?;
        Ok(Self {
            gate,
            public,
            shares,
            points,
            tree,
        })
    }
    pub fn verify(&self, context: &BirthContext<S>) -> Result<()> {
        let (public, points) = self.tree.verify(&self.gate, context)?;
        if public != self.public || points != self.points || self.shares.len() != points.len() {
            return Err(Error::Share);
        }
        for (id, p) in points {
            if self.shares.get(&id).map(|s| S::generator_mul(*s)) != Some(p) {
                return Err(Error::Share);
            }
        }
        Ok(())
    }
    /// Every leaf, including an escrow holder, receives the coordinator's seed.
    /// The caller seals each entry to that leaf's registered request key.
    pub fn seed_deliveries(&self, seed: [u8; 32]) -> BTreeMap<LeafId, [u8; 32]> {
        self.shares.keys().cloned().map(|id| (id, seed)).collect()
    }
    pub fn reconstruct(&self, signers: &[LeafId]) -> Result<S::Scalar> {
        let weights = self.gate.weights::<S>(signers)?;
        weights
            .into_iter()
            .try_fold(S::scalar_zero(), |sum, (id, w)| {
                Ok(sum + w * *self.shares.get(&id).ok_or(Error::Share)?)
            })
    }
    pub fn top_points(&self, context: &BirthContext<S>) -> Result<Vec<S::Point>> {
        match (&self.tree, &self.gate) {
            (PublicTree::And(nodes), Gate::And(children)) => nodes
                .iter()
                .zip(children)
                .enumerate()
                .map(|(i, (node, gate))| {
                    node.verify_at(
                        gate,
                        &self.gate,
                        context,
                        &mut vec![(i + 1) as u16],
                        &mut BTreeMap::new(),
                    )
                })
                .collect(),
            _ => Ok(vec![self.public]),
        }
    }
}

pub fn derive_tweak<S: Suite>(
    committee: S::Point,
    top_shards: &[S::Point],
    charter_id: &[u8; 32],
    seed: &[u8; 32],
) -> Result<S::Scalar> {
    if top_shards.is_empty() {
        return Err(Error::Parameters);
    }
    let mut points = vec![committee];
    points.extend_from_slice(top_shards);
    let mut input = S::encode_points(&points)?.concat();
    input.extend_from_slice(charter_id);
    input.extend_from_slice(seed);
    Ok(S::hash_to_scalar("SL1/tw", &input))
}
#[derive(Clone, Debug)]
pub struct ReceiveKey<S: Suite> {
    pub public: S::Point,
    pub proof: KnowledgeProof<S>,
}
impl<S: Suite> ReceiveKey<S> {
    fn context(public: S::Point, charter: &[u8; 32]) -> Result<Vec<u8>> {
        let mut out = b"SL1/pop-rk".to_vec();
        out.extend_from_slice(&S::encode_point(public)?);
        out.extend_from_slice(charter);
        Ok(out)
    }
    pub fn register(
        secret: S::Scalar,
        charter: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let public = S::generator_mul(secret);
        Ok(Self {
            public,
            proof: KnowledgeProof::create(secret, &Self::context(public, charter)?, rng)?,
        })
    }
    pub fn verify(&self, charter: &[u8; 32]) -> Result<()> {
        self.proof
            .verify(self.public, &Self::context(self.public, charter)?)
    }
}
#[derive(Clone, Debug)]
pub struct NetworkShard<S: Suite> {
    pub receive: ReceiveKey<S>,
    pub ephemeral: S::Point,
    pub public: S::Point,
    pub delta_proof: KnowledgeProof<S>,
    pub slot: u16,
}
impl<S: Suite> NetworkShard<S> {
    fn context(&self, context: &BirthContext<S>) -> Result<Vec<u8>> {
        let mut bytes = context.actor_context(self.public, self.slot)?;
        bytes.extend_from_slice(b"SL1/pop-delta");
        for p in S::encode_points(&[self.receive.public, self.ephemeral])? {
            bytes.extend_from_slice(&p);
        }
        Ok(bytes)
    }
    pub fn create(
        receive: ReceiveKey<S>,
        slot: u16,
        context: &BirthContext<S>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        receive.verify(&context.charter_id)?;
        let e = S::random(rng);
        let ephemeral = S::generator_mul(e);
        let delta = S::hash_to_scalar("SL1/st", &S::encode_point(S::mul(receive.public, e))?);
        let public = receive.public + S::generator_mul(delta);
        let mut binding = context.actor_context(public, slot)?;
        binding.extend_from_slice(b"SL1/pop-delta");
        for point in S::encode_points(&[receive.public, ephemeral])? {
            binding.extend_from_slice(&point);
        }
        let delta_proof = KnowledgeProof::create(delta, &binding, rng)?;
        Ok(Self {
            receive,
            ephemeral,
            public,
            delta_proof,
            slot,
        })
    }
    pub fn verify(&self, context: &BirthContext<S>) -> Result<()> {
        self.receive.verify(&context.charter_id)?;
        S::validate_point(self.ephemeral)?;
        S::validate_point(self.public)?;
        self.delta_proof
            .verify(self.public - self.receive.public, &self.context(context)?)
    }
    pub fn recover(
        &self,
        receive_secret: S::Scalar,
        context: &BirthContext<S>,
    ) -> Result<S::Scalar> {
        self.verify(context)?;
        if S::generator_mul(receive_secret) != self.receive.public {
            return Err(Error::Context);
        }
        let x = receive_secret
            + S::hash_to_scalar(
                "SL1/st",
                &S::encode_point(S::mul(self.ephemeral, receive_secret))?,
            );
        if S::generator_mul(x) != self.public {
            return Err(Error::Proof);
        }
        Ok(x)
    }
}

/// Hash commitment prototype; the opening is inside the sealed BIRTH request.
pub fn address_commitment<S: Suite>(
    public: S::Point,
    context: &BirthContext<S>,
    root: Option<&[u8; 32]>,
    profile: u8,
    gate: &Gate,
    opening: &[u8; 32],
) -> Result<[u8; 32]> {
    if !matches!(profile, 1 | 2) {
        return Err(Error::Parameters);
    }
    let mut out = S::encode_point(public)?;
    out.extend_from_slice(&context.chain_id);
    out.push(u8::from(root.is_some()));
    if let Some(root) = root {
        out.extend_from_slice(root);
    }
    out.extend_from_slice(&context.charter_id);
    out.push(profile);
    out.extend_from_slice(&gate.hash()?);
    out.extend_from_slice(opening);
    Ok(crate::hash::h("SL1/cm-addr", &out))
}
#[derive(Clone, Debug)]
pub struct Birth<S: Suite> {
    pub context: BirthContext<S>,
    pub gate: Gate,
    pub tree: PublicTree<S>,
    pub seed: [u8; 32],
    pub tweak: S::Scalar,
    pub public: S::Point,
    pub root: Option<[u8; 32]>,
    pub profile: u8,
    pub commitment: [u8; 32],
    pub opening: [u8; 32],
    pub escrow_certificates: BTreeMap<Vec<u16>, EscrowCertificate<S>>,
    /// Simulator-generated registration proposal. A caller must anchor these
    /// independent holder authentication keys in its trusted charter registry.
    pub proposed_escrow_keys: BTreeMap<LeafId, S::Point>,
}
impl<S: Suite> Birth<S> {
    pub fn create(
        context: BirthContext<S>,
        actors: &ActorShares<S>,
        seed: [u8; 32],
        root: Option<[u8; 32]>,
        profile: u8,
        opening: [u8; 32],
    ) -> Result<Self> {
        actors.verify(&context)?;
        let tweak = derive_tweak::<S>(
            context.committee,
            &actors.top_points(&context)?,
            &context.charter_id,
            &seed,
        )?;
        let public = context.committee + actors.public + S::generator_mul(tweak);
        let commitment = address_commitment::<S>(
            public,
            &context,
            root.as_ref(),
            profile,
            &actors.gate,
            &opening,
        )?;
        let mut escrow_certificates = BTreeMap::new();
        let mut authentication_secrets = BTreeMap::new();
        let mut proposed_escrow_keys = BTreeMap::new();
        for (path, holders) in escrow_branches(&actors.gate)? {
            let binding = escrow_binding(&context, &actors.gate, &path, public, &seed)?;
            let acknowledgements = holders
                .into_iter()
                .map(|id| {
                    // Simulate an independent holder's receipt signature. The
                    // share dealer cannot derive this authentication secret.
                    let secret = **authentication_secrets.entry(id.clone()).or_insert_with(|| {
                        k256::elliptic_curve::zeroize::Zeroizing::new(S::random(
                            &mut k256::elliptic_curve::rand_core::OsRng,
                        ))
                    });
                    proposed_escrow_keys.insert(id.clone(), S::generator_mul(secret));
                    let proof = KnowledgeProof::create(
                        secret,
                        &ack_binding(&binding, &id),
                        &mut k256::elliptic_curve::rand_core::OsRng,
                    )?;
                    Ok((id, proof))
                })
                .collect::<Result<_>>()?;
            escrow_certificates.insert(path, EscrowCertificate { acknowledgements });
        }
        let birth = Self {
            context,
            gate: actors.gate.clone(),
            tree: actors.tree.clone(),
            seed,
            tweak,
            public,
            root,
            profile,
            commitment,
            opening,
            escrow_certificates,
            proposed_escrow_keys,
        };
        birth.verify_with_escrow_keys(&birth.proposed_escrow_keys)?;
        Ok(birth)
    }
    /// Verify a birth without escrow. Escrow births require an independently
    /// trusted charter key registry via `verify_with_escrow_keys`.
    pub fn verify(&self) -> Result<()> {
        if !escrow_branches(&self.gate)?.is_empty() {
            return Err(Error::Context);
        }
        self.verify_with_escrow_keys(&BTreeMap::new())
    }
    pub fn verify_with_escrow_keys(&self, trusted_keys: &BTreeMap<LeafId, S::Point>) -> Result<()> {
        if S::SUITE_ID == 3 && self.root.is_some() {
            return Err(Error::Context);
        }
        S::validate_point(self.context.committee)?;
        let (actors, _) = self.tree.verify(&self.gate, &self.context)?;
        let branches = escrow_branches(&self.gate)?;
        if branches.len() != self.escrow_certificates.len() {
            return Err(Error::Proof);
        }
        for (path, holders) in branches {
            for holder in &holders {
                if !self.proposed_escrow_keys.contains_key(holder)
                    || self.proposed_escrow_keys.get(holder) != trusted_keys.get(holder)
                {
                    return Err(Error::Context);
                }
            }
            let certificate = self.escrow_certificates.get(&path).ok_or(Error::Proof)?;
            let binding =
                escrow_binding(&self.context, &self.gate, &path, self.public, &self.seed)?;
            certificate.verify(&holders, trusted_keys, &binding)?;
        }
        let tops = match (&self.tree, &self.gate) {
            (PublicTree::And(nodes), Gate::And(gates)) => nodes
                .iter()
                .zip(gates)
                .enumerate()
                .map(|(i, (node, gate))| {
                    node.verify_at(
                        gate,
                        &self.gate,
                        &self.context,
                        &mut vec![(i + 1) as u16],
                        &mut BTreeMap::new(),
                    )
                })
                .collect::<Result<Vec<_>>>()?,
            _ => vec![actors],
        };
        let tweak = derive_tweak::<S>(
            self.context.committee,
            &tops,
            &self.context.charter_id,
            &self.seed,
        )?;
        if self.tweak != tweak
            || self.public != self.context.committee + actors + S::generator_mul(tweak)
        {
            return Err(Error::Proof);
        }
        if address_commitment::<S>(
            self.public,
            &self.context,
            self.root.as_ref(),
            self.profile,
            &self.gate,
            &self.opening,
        )? != self.commitment
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct TaprootKey {
    pub internal: k256::ProjectivePoint,
    pub output: k256::ProjectivePoint,
    pub tweak: k256::Scalar,
    pub g_p: k256::Scalar,
    pub g_q: k256::Scalar,
}
impl Birth<Secp> {
    pub fn taproot_with_escrow_keys(
        &self,
        keys: &BTreeMap<LeafId, k256::ProjectivePoint>,
    ) -> Result<TaprootKey> {
        self.verify_with_escrow_keys(keys)?;
        taproot_key(self.public, self.root.as_ref())
    }
    pub fn taproot(&self) -> Result<TaprootKey> {
        self.verify()?;
        taproot_key(self.public, self.root.as_ref())
    }
    pub fn check_taproot_address(&self, output_x: &[u8; 32]) -> Result<()> {
        if crate::algebra::x_bytes(self.taproot()?.output)? != *output_x {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn check_taproot_address_with_escrow_keys(
        &self,
        output_x: &[u8; 32],
        keys: &BTreeMap<LeafId, k256::ProjectivePoint>,
    ) -> Result<()> {
        if crate::algebra::x_bytes(self.taproot_with_escrow_keys(keys)?.output)? != *output_x {
            return Err(Error::Context);
        }
        Ok(())
    }
}
pub fn taproot_key(public: k256::ProjectivePoint, root: Option<&[u8; 32]>) -> Result<TaprootKey> {
    let g_p = if crate::algebra::is_odd(public)? {
        -k256::Scalar::ONE
    } else {
        k256::Scalar::ONE
    };
    let internal = public * g_p;
    let mut input = crate::algebra::x_bytes(internal)?.to_vec();
    if let Some(root) = root {
        input.extend_from_slice(root);
    }
    let tweak = crate::algebra::decode_scalar(&crate::hash::h("TapTweak", &input))?;
    let output = internal + Secp::generator_mul(tweak);
    let g_q = if crate::algebra::is_odd(output)? {
        -k256::Scalar::ONE
    } else {
        k256::Scalar::ONE
    };
    Ok(TaprootKey {
        internal,
        output,
        tweak,
        g_p,
        g_q,
    })
}

impl Birth<super::group::Edwards> {
    pub fn check_ed25519_address_with_escrow_keys(
        &self,
        address: &[u8; 32],
        keys: &BTreeMap<LeafId, curve25519_dalek::edwards::EdwardsPoint>,
    ) -> Result<()> {
        self.verify_with_escrow_keys(keys)?;
        if self.public.compress().to_bytes() != *address {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn check_ed25519_address(&self, address: &[u8; 32]) -> Result<()> {
        self.verify()?;
        if self.public.compress().to_bytes() != *address {
            return Err(Error::Context);
        }
        Ok(())
    }
}
impl Birth<Secp> {
    pub fn check_ecdsa_address_with_escrow_keys(
        &self,
        kind: u8,
        address: &[u8],
        keys: &BTreeMap<LeafId, k256::ProjectivePoint>,
    ) -> Result<()> {
        self.verify_with_escrow_keys(keys)?;
        if !matches!(kind, 1..=3 | 5)
            || self.root.is_some()
            || crate::wire::address_for(kind, self.public)? != address
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    /// Existing wire address kinds 1–3 (HASH160) and 5 (Ethereum).
    pub fn check_ecdsa_address(&self, kind: u8, address: &[u8]) -> Result<()> {
        self.verify()?;
        if !matches!(kind, 1..=3 | 5)
            || self.root.is_some()
            || crate::wire::address_for(kind, self.public)? != address
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::group::{lagrange, Edwards};
    use super::*;
    use k256::elliptic_curve::rand_core::OsRng;
    fn leaf(slot: u16, path: Vec<u16>, member: u16) -> Gate {
        Gate::Leaf(LeafId::new(slot, path, member))
    }
    fn group(slot: u16, k: usize, n: u16) -> Gate {
        Gate::Threshold {
            k,
            children: (1..=n).map(|i| leaf(slot, vec![], i)).collect(),
        }
    }
    fn context<S: Suite>() -> BirthContext<S> {
        BirthContext {
            committee: S::generator_mul(S::scalar_from_u64(97)),
            charter_id: [3; 32],
            chain_id: [4; 32],
        }
    }
    fn check_sets<S: Suite>(gate: Gate, sets: Vec<Vec<LeafId>>) {
        let ctx = context::<S>();
        let actors = ActorShares::<S>::generate(gate, &ctx, &mut OsRng).unwrap();
        actors.verify(&ctx).unwrap();
        for set in sets {
            assert_eq!(
                S::generator_mul(actors.reconstruct(&set).unwrap()),
                actors.public
            );
        }
        let birth = Birth::create(ctx.clone(), &actors, [1; 32], None, 1, [2; 32]).unwrap();
        let trusted_keys = birth.proposed_escrow_keys.clone();
        birth.verify_with_escrow_keys(&trusted_keys).unwrap();
        assert_eq!(actors.seed_deliveries([1; 32]).len(), actors.shares.len());
        let mut bad = birth.clone();
        bad.tweak = bad.tweak + S::scalar_one();
        assert!(bad.verify_with_escrow_keys(&trusted_keys).is_err());
        let mut bad = birth.clone();
        bad.context.chain_id[0] ^= 1;
        assert!(bad.verify_with_escrow_keys(&trusted_keys).is_err());
        let mut bad = birth.clone();
        bad.commitment[0] ^= 1;
        assert!(bad.verify_with_escrow_keys(&trusted_keys).is_err());
    }
    fn all_structures<S: Suite>() {
        for count in 1..=5 {
            let gate = Gate::And((1..=count).map(|i| leaf(i, vec![], 1)).collect());
            let ids = gate.leaves().unwrap();
            check_sets::<S>(gate, vec![ids]);
        }
        let gate = group(1, 2, 3);
        let ids = gate.leaves().unwrap();
        check_sets::<S>(
            gate,
            vec![
                vec![ids[0].clone(), ids[1].clone()],
                vec![ids[0].clone(), ids[2].clone()],
                vec![ids[1].clone(), ids[2].clone()],
            ],
        );
        let gate = Gate::Or(vec![
            leaf(1, vec![1], 1),
            Gate::Threshold {
                k: 3,
                children: (1..=5).map(|i| leaf(1, vec![2], i)).collect(),
            },
        ]);
        let mut sets = vec![vec![LeafId::new(1, vec![1], 1)]];
        for i in 1..=3 {
            for j in i + 1..=4 {
                for k in j + 1..=5 {
                    sets.push(
                        vec![i, j, k]
                            .into_iter()
                            .map(|m| LeafId::new(1, vec![2], m))
                            .collect(),
                    );
                }
            }
        }
        check_sets::<S>(gate, sets);
        let nested = Gate::Threshold {
            k: 2,
            children: vec![
                leaf(1, vec![1], 1),
                Gate::Threshold {
                    k: 2,
                    children: (1..=3).map(|i| leaf(1, vec![2], i)).collect(),
                },
                leaf(1, vec![3], 3),
            ],
        };
        check_sets::<S>(
            nested,
            vec![
                vec![LeafId::new(1, vec![1], 1), LeafId::new(1, vec![3], 3)],
                vec![
                    LeafId::new(1, vec![1], 1),
                    LeafId::new(1, vec![2], 1),
                    LeafId::new(1, vec![2], 3),
                ],
                vec![
                    LeafId::new(1, vec![2], 1),
                    LeafId::new(1, vec![2], 2),
                    LeafId::new(1, vec![3], 3),
                ],
            ],
        );
    }
    #[test]
    fn recursive_secp_birth() {
        all_structures::<Secp>();
    }
    #[test]
    fn recursive_edwards_birth() {
        all_structures::<Edwards>();
    }
    fn committee<S: Suite>() {
        for (n, t) in [(9, 7), (17, 12)] {
            let c = Committee::<S>::generate(n, t, &mut OsRng).unwrap();
            assert_eq!(c.qualified, (1..=t as u16).collect::<Vec<_>>());
            let ids: Vec<_> = (n - t as u16 + 1..=n).collect();
            let weights = lagrange::<S>(&ids).unwrap();
            let recovered = ids
                .into_iter()
                .zip(weights)
                .fold(S::scalar_zero(), |a, (i, w)| {
                    a + w * c.shares[i as usize - 1]
                });
            assert_eq!(S::generator_mul(recovered), c.public);
            for (x, p) in c.shares.iter().zip(&c.share_points) {
                assert_eq!(S::generator_mul(*x), *p);
            }
        }
    }
    #[test]
    fn committee_sizes_both_suites() {
        committee::<Secp>();
        committee::<Edwards>();
    }
    #[test]
    fn valid_complaint_excludes_dealer_in_board_order() {
        let ctx = Committee::<Secp>::context(5, 3);
        let mut dealers: Vec<_> = (1..=5)
            .map(|i| {
                Dealer::<Secp>::create(i, 5, 3, Secp::random(&mut OsRng), &ctx, &mut OsRng).unwrap()
            })
            .collect();
        dealers[0].shares[2] += k256::Scalar::ONE;
        dealers[2].proof.response += k256::Scalar::ONE;
        let c = Committee::from_dealers(5, 3, &dealers).unwrap();
        assert_eq!(c.qualified, vec![2, 4, 5]);
        dealers[3].shares[0] += k256::Scalar::ONE;
        assert!(Committee::from_dealers(5, 3, &dealers).is_err());
    }
    #[test]
    fn rogue_key_and_replayed_proofs_refused() {
        let ctx = context::<Secp>();
        let actors = ActorShares::<Secp>::generate(
            Gate::And(vec![leaf(1, vec![], 1), leaf(2, vec![], 1)]),
            &ctx,
            &mut OsRng,
        )
        .unwrap();
        let mut rogue = actors.tree.clone();
        if let PublicTree::And(children) = &mut rogue {
            let honest = match children[0] {
                PublicTree::Leaf { point, .. } => point,
                _ => unreachable!(),
            };
            if let PublicTree::Leaf { point, .. } = &mut children[1] {
                *point = Secp::generator_mul(k256::Scalar::from(42u64)) - ctx.committee - honest;
            }
        }
        assert!(rogue.verify(&actors.gate, &ctx).is_err());
        let mut replay = actors.tree.clone();
        if let PublicTree::And(children) = &mut replay {
            children.swap(0, 1);
        }
        assert!(replay.verify(&actors.gate, &ctx).is_err());
        let group = ActorShares::<Secp>::generate(group(1, 2, 3), &ctx, &mut OsRng).unwrap();
        let mut bad = group.tree.clone();
        if let PublicTree::Threshold { dealers, .. } = &mut bad {
            dealers[0].proof.response += k256::Scalar::ONE;
        }
        assert!(bad.verify(&group.gate, &ctx).is_err());
        let mut bad = group.tree.clone();
        if let PublicTree::Threshold { dealers, .. } = &mut bad {
            dealers[0].commitments[1] += Secp::generator_mul(k256::Scalar::ONE);
        }
        assert!(bad.verify(&group.gate, &ctx).is_err());
    }
    fn network<S: Suite>() {
        let ctx = context::<S>();
        let u = S::random(&mut OsRng);
        let registered = ReceiveKey::<S>::register(u, &ctx.charter_id, &mut OsRng).unwrap();
        let shard = NetworkShard::create(registered, 4, &ctx, &mut OsRng).unwrap();
        let x = shard.recover(u, &ctx).unwrap();
        assert_eq!(S::generator_mul(x), shard.public);
        let tree = PublicTree::Network(shard.clone());
        assert_eq!(
            tree.verify(&leaf(4, vec![], 1), &ctx).unwrap().0,
            shard.public
        );
        assert!(tree.verify(&leaf(5, vec![], 1), &ctx).is_err());
        let mut bad = shard.clone();
        bad.public = bad.public + S::generator_mul(S::scalar_one());
        assert!(bad.verify(&ctx).is_err());
        let mut bad = shard.clone();
        bad.ephemeral = bad.ephemeral + S::generator_mul(S::scalar_one());
        assert!(bad.verify(&ctx).is_err());
        let mut badctx = ctx.clone();
        badctx.charter_id[0] ^= 1;
        assert!(shard.verify(&badctx).is_err());
        assert!(shard.recover(u + S::scalar_one(), &ctx).is_err());
    }
    #[test]
    fn network_shards_both_suites() {
        network::<Secp>();
        network::<Edwards>();
    }
    #[test]
    fn commitment_binds_chain_root_profile_and_gate() {
        let ctx = context::<Secp>();
        let gate = leaf(1, vec![], 1);
        let actors = ActorShares::<Secp>::generate(gate.clone(), &ctx, &mut OsRng).unwrap();
        let birth =
            Birth::create(ctx.clone(), &actors, [8; 32], Some([7; 32]), 2, [6; 32]).unwrap();
        let q = birth.taproot().unwrap();
        birth
            .check_taproot_address(&crate::algebra::x_bytes(q.output).unwrap())
            .unwrap();
        assert!(birth.check_taproot_address(&[0; 32]).is_err());
        let mut changed = birth.clone();
        changed.root = None;
        assert!(changed.verify().is_err());
        let mut changed = birth.clone();
        changed.profile = 1;
        assert!(changed.verify().is_err());
        let mut changed = birth.clone();
        changed.opening[0] ^= 1;
        assert!(changed.verify().is_err());
        let mut ctx2 = ctx.clone();
        ctx2.chain_id[0] ^= 1;
        assert_ne!(
            birth.commitment,
            address_commitment::<Secp>(
                birth.public,
                &ctx2,
                birth.root.as_ref(),
                2,
                &gate,
                &birth.opening
            )
            .unwrap()
        );
    }
    #[test]
    fn excluded_coalition_cannot_reconstruct() {
        let ctx = context::<Secp>();
        let actors = ActorShares::<Secp>::generate(group(1, 2, 3), &ctx, &mut OsRng).unwrap();
        let ids = actors.gate.leaves().unwrap();
        assert!(actors.reconstruct(&ids[..1]).is_err());
        assert!(actors.reconstruct(&ids).is_err());
    }
}

/// In-process receipt signatures use independent holder authentication keys.
/// A trusted charter registry anchors these keys; share points are not ACK keys.
#[derive(Clone, Debug)]
pub struct EscrowCertificate<S: Suite> {
    pub acknowledgements: Vec<(LeafId, KnowledgeProof<S>)>,
}
fn ack_binding(binding: &[u8], id: &LeafId) -> Vec<u8> {
    let mut out = binding.to_vec();
    out.extend_from_slice(&id.encode());
    out
}
fn escrow_binding<S: Suite>(
    context: &BirthContext<S>,
    gate: &Gate,
    path: &[u16],
    public: S::Point,
    seed: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut binding = context.tree_context(gate, path)?;
    binding.extend_from_slice(b"SL1/escrow-ack");
    binding.extend_from_slice(&S::encode_point(public)?);
    binding.extend_from_slice(&crate::hash::h("SL1/seed-commitment", seed));
    Ok(binding)
}
fn escrow_branches(gate: &Gate) -> Result<BTreeMap<Vec<u16>, Vec<LeafId>>> {
    gate.validate()?;
    fn walk(
        gate: &Gate,
        path: &mut Vec<u16>,
        out: &mut BTreeMap<Vec<u16>, Vec<LeafId>>,
    ) -> Result<()> {
        let children = match gate {
            Gate::Leaf(_) => return Ok(()),
            Gate::And(c) | Gate::Or(c) | Gate::Threshold { children: c, .. } => c,
        };
        for (i, child) in children.iter().enumerate() {
            path.push((i + 1) as u16);
            if matches!(gate, Gate::Or(_)) && i != 0 {
                out.insert(path.clone(), child.leaves()?);
            }
            walk(child, path, out)?;
            path.pop();
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(gate, &mut Vec::new(), &mut out)?;
    Ok(out)
}
impl<S: Suite> EscrowCertificate<S> {
    pub fn verify(
        &self,
        holders: &[LeafId],
        points: &BTreeMap<LeafId, S::Point>,
        binding: &[u8],
    ) -> Result<()> {
        if holders.is_empty() {
            return Err(Error::Threshold);
        }
        let n = holders.len();
        let f = (n - 1) / 3;
        let quorum = (n + f + 2) / 2;
        if self.acknowledgements.len() < quorum {
            return Err(Error::Threshold);
        }
        let mut seen = BTreeSet::new();
        for (id, proof) in &self.acknowledgements {
            if !holders.contains(id) || !seen.insert(id) {
                return Err(Error::Proof);
            }
            proof.verify(
                *points.get(id).ok_or(Error::Proof)?,
                &ack_binding(binding, id),
            )?;
        }
        Ok(())
    }
}

/// Authenticated DH-pad delivery for the algebra simulator. Production routes
/// these seeds through the separately implemented X25519 HPKE actor capsules.
#[derive(Clone, Debug)]
pub struct SeedDelivery<S: Suite> {
    pub leaf: LeafId,
    pub ephemeral: S::Point,
    pub ciphertext: [u8; 32],
    pub tag: [u8; 32],
}
impl<S: Suite> SeedDelivery<S> {
    fn key(
        shared: S::Point,
        ephemeral: S::Point,
        recipient: S::Point,
        leaf: &LeafId,
        context: &BirthContext<S>,
    ) -> Result<Vec<u8>> {
        let mut input = b"SL1/seed".to_vec();
        input.push(S::SUITE_ID);
        for p in S::encode_points(&[shared, ephemeral, recipient, context.committee])? {
            input.extend_from_slice(&p);
        }
        input.extend_from_slice(&leaf.encode());
        input.extend_from_slice(&context.charter_id);
        input.extend_from_slice(&context.chain_id);
        Ok(input)
    }
    pub fn seal(
        seed: [u8; 32],
        leaf: LeafId,
        recipient: S::Point,
        context: &BirthContext<S>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        S::validate_point(recipient)?;
        let e = S::random(rng);
        let ephemeral = S::generator_mul(e);
        let mut key = Self::key(S::mul(recipient, e), ephemeral, recipient, &leaf, context)?;
        let pad = crate::hash::h("SL1/seed-pad", &key);
        let mut ciphertext = [0; 32];
        for i in 0..32 {
            ciphertext[i] = seed[i] ^ pad[i];
        }
        key.extend_from_slice(&ciphertext);
        let tag = crate::hash::h("SL1/seed-auth", &key);
        Ok(Self {
            leaf,
            ephemeral,
            ciphertext,
            tag,
        })
    }
    pub fn open(&self, secret: S::Scalar, context: &BirthContext<S>) -> Result<[u8; 32]> {
        S::validate_point(self.ephemeral)?;
        let mut key = Self::key(
            S::mul(self.ephemeral, secret),
            self.ephemeral,
            S::generator_mul(secret),
            &self.leaf,
            context,
        )?;
        let pad = crate::hash::h("SL1/seed-pad", &key);
        key.extend_from_slice(&self.ciphertext);
        let tag = crate::hash::h("SL1/seed-auth", &key);
        use k256::elliptic_curve::subtle::ConstantTimeEq;
        if !bool::from(tag.ct_eq(&self.tag)) {
            return Err(Error::Proof);
        }
        let mut seed = [0; 32];
        for i in 0..32 {
            seed[i] = self.ciphertext[i] ^ pad[i];
        }
        Ok(seed)
    }
}
impl<S: Suite> ActorShares<S> {
    pub fn seal_seed_deliveries(
        &self,
        seed: [u8; 32],
        recipients: &BTreeMap<LeafId, S::Point>,
        context: &BirthContext<S>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<SeedDelivery<S>>> {
        if recipients.len() != self.shares.len() {
            return Err(Error::Parameters);
        }
        self.shares
            .keys()
            .map(|id| {
                SeedDelivery::seal(
                    seed,
                    id.clone(),
                    *recipients.get(id).ok_or(Error::Context)?,
                    context,
                    rng,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod escrow_tests {
    use super::*;
    use k256::elliptic_curve::rand_core::OsRng;
    #[test]
    fn missing_invalid_and_short_escrow_certificate_refused() {
        let ctx = BirthContext::<Secp> {
            committee: Secp::generator_mul(k256::Scalar::from(9u64)),
            charter_id: [1; 32],
            chain_id: [2; 32],
        };
        let gate = Gate::Or(vec![
            Gate::Leaf(LeafId::new(1, vec![1], 1)),
            Gate::Threshold {
                k: 3,
                children: (1..=5)
                    .map(|i| Gate::Leaf(LeafId::new(1, vec![2], i)))
                    .collect(),
            },
        ]);
        let actors = ActorShares::generate(gate, &ctx, &mut OsRng).unwrap();
        let birth = Birth::create(ctx, &actors, [3; 32], None, 2, [4; 32]).unwrap();
        let trusted_keys = birth.proposed_escrow_keys.clone();
        assert!(birth.verify().is_err());
        birth.verify_with_escrow_keys(&trusted_keys).unwrap();
        assert_eq!(birth.escrow_certificates.len(), 1);
        let output = birth
            .taproot_with_escrow_keys(&trusted_keys)
            .unwrap()
            .output;
        birth
            .check_taproot_address_with_escrow_keys(
                &crate::algebra::x_bytes(output).unwrap(),
                &trusted_keys,
            )
            .unwrap();
        for kind in [1, 5] {
            birth
                .check_ecdsa_address_with_escrow_keys(
                    kind,
                    &crate::wire::address_for(kind, birth.public).unwrap(),
                    &trusted_keys,
                )
                .unwrap();
        }
        let mut short = birth.clone();
        short
            .escrow_certificates
            .values_mut()
            .next()
            .unwrap()
            .acknowledgements
            .truncate(3);
        assert!(short.verify_with_escrow_keys(&trusted_keys).is_err());
        let mut quorum = birth.clone();
        quorum
            .escrow_certificates
            .values_mut()
            .next()
            .unwrap()
            .acknowledgements
            .truncate(4);
        quorum.verify_with_escrow_keys(&trusted_keys).unwrap();
        let mut missing = birth.clone();
        missing.escrow_certificates.clear();
        assert!(missing.verify_with_escrow_keys(&trusted_keys).is_err());
        let mut bad = birth.clone();
        bad.escrow_certificates
            .values_mut()
            .next()
            .unwrap()
            .acknowledgements[0]
            .1
            .response += k256::Scalar::ONE;
        assert!(bad.verify_with_escrow_keys(&trusted_keys).is_err());
        let mut duplicate = birth;
        let cert = duplicate.escrow_certificates.values_mut().next().unwrap();
        cert.acknowledgements[1] = cert.acknowledgements[0].clone();
        assert!(duplicate.verify_with_escrow_keys(&trusted_keys).is_err());
    }
    #[test]
    fn seed_delivery_authenticates_leaf_recipient_context_ciphertext() {
        let ctx = BirthContext::<Secp> {
            committee: Secp::generator_mul(k256::Scalar::from(9u64)),
            charter_id: [1; 32],
            chain_id: [2; 32],
        };
        let secret = Secp::random(&mut OsRng);
        let leaf = LeafId::new(1, vec![2], 3);
        let seed = [7; 32];
        let delivery =
            SeedDelivery::seal(seed, leaf, Secp::generator_mul(secret), &ctx, &mut OsRng).unwrap();
        assert_eq!(delivery.open(secret, &ctx).unwrap(), seed);
        let mut bad = delivery.clone();
        bad.ciphertext[0] ^= 1;
        assert!(bad.open(secret, &ctx).is_err());
        let mut bad = delivery.clone();
        bad.leaf.member += 1;
        assert!(bad.open(secret, &ctx).is_err());
        assert!(delivery.open(secret + k256::Scalar::ONE, &ctx).is_err());
        let mut badctx = ctx;
        badctx.chain_id[0] ^= 1;
        assert!(delivery.open(secret, &badctx).is_err());
    }
}

#[cfg(test)]
mod public_boundary_tests {
    use super::super::group::Edwards;
    use super::*;
    use k256::elliptic_curve::rand_core::OsRng;
    #[test]
    fn torsion_polynomial_that_vanishes_at_all_indices_is_rejected() {
        let context = Committee::<Edwards>::context(3, 3);
        let mut dealer =
            Dealer::<Edwards>::create(1, 3, 3, Edwards::scalar_one(), &context, &mut OsRng)
                .unwrap();
        let torsion = curve25519_dalek::constants::EIGHT_TORSION[4];
        dealer.commitments[1] -= torsion;
        dealer.commitments[2] += torsion;
        for i in 1..=3 {
            assert_eq!(
                evaluate_commitments::<Edwards>(&dealer.commitments, i).unwrap(),
                Edwards::generator_mul(dealer.shares[i as usize - 1])
            );
        }
        assert_eq!(dealer.verify(3, 3, &context), Err(Error::Point));
    }
    #[test]
    fn edwards_escrow_address_uses_trusted_registry() {
        let context = BirthContext::<Edwards> {
            committee: Edwards::generator_mul(Edwards::scalar_one()),
            charter_id: [1; 32],
            chain_id: [2; 32],
        };
        let gate = Gate::Or(vec![
            Gate::Leaf(LeafId::new(1, vec![1], 1)),
            Gate::Leaf(LeafId::new(1, vec![2], 1)),
        ]);
        let actors = ActorShares::generate(gate, &context, &mut OsRng).unwrap();
        let birth = Birth::create(context, &actors, [3; 32], None, 2, [4; 32]).unwrap();
        let address = birth.public.compress().to_bytes();
        birth
            .check_ed25519_address_with_escrow_keys(&address, &birth.proposed_escrow_keys)
            .unwrap();
        assert!(birth.check_ed25519_address(&address).is_err());
        assert!(birth
            .check_ed25519_address_with_escrow_keys(&address, &BTreeMap::new())
            .is_err());
    }
    #[test]
    fn typed_edwards_torsion_forgery_is_rejected() {
        let torsion = curve25519_dalek::constants::EIGHT_TORSION[1];
        let forged = (1..512)
            .find_map(|i| {
                let response = Edwards::scalar_from_u64(i);
                let nonce = Edwards::generator_mul(response);
                let challenge =
                    KnowledgeProof::<Edwards>::challenge(torsion, nonce, b"forged").unwrap();
                (Edwards::mul(torsion, challenge) == Edwards::identity())
                    .then_some(KnowledgeProof::<Edwards> { nonce, response })
            })
            .expect("one of 512 challenges annihilates the order-eight point");
        assert_eq!(
            Edwards::generator_mul(forged.response),
            forged.nonce
                + Edwards::mul(
                    torsion,
                    KnowledgeProof::<Edwards>::challenge(torsion, forged.nonce, b"forged").unwrap()
                )
        );
        assert_eq!(forged.verify(torsion, b"forged"), Err(Error::Point));
        let context = BirthContext::<Edwards> {
            committee: Edwards::generator_mul(Edwards::scalar_one()),
            charter_id: [1; 32],
            chain_id: [2; 32],
        };
        assert!(SeedDelivery::<Edwards>::seal(
            [0; 32],
            LeafId::new(1, vec![], 1),
            torsion,
            &context,
            &mut OsRng
        )
        .is_err());
        let delivery = SeedDelivery::<Edwards> {
            leaf: LeafId::new(1, vec![], 1),
            ephemeral: torsion,
            ciphertext: [0; 32],
            tag: [0; 32],
        };
        assert_eq!(
            delivery.open(Edwards::scalar_from_u64(8), &context),
            Err(Error::Point)
        );
        let receive =
            ReceiveKey::register(Edwards::scalar_from_u64(9), &context.charter_id, &mut OsRng)
                .unwrap();
        let mut shard = NetworkShard::create(receive, 1, &context, &mut OsRng).unwrap();
        shard.ephemeral = torsion;
        assert_eq!(shard.verify(&context), Err(Error::Point));
    }
    #[test]
    fn dealer_share_knowledge_cannot_forge_holder_receipts() {
        let context = BirthContext::<Secp> {
            committee: Secp::generator_mul(Secp::scalar_from_u64(7)),
            charter_id: [1; 32],
            chain_id: [2; 32],
        };
        let gate = Gate::Or(vec![
            Gate::Leaf(LeafId::new(1, vec![1], 1)),
            Gate::Threshold {
                k: 3,
                children: (1..=5)
                    .map(|i| Gate::Leaf(LeafId::new(1, vec![2], i)))
                    .collect(),
            },
        ]);
        let actors = ActorShares::generate(gate, &context, &mut OsRng).unwrap();
        let mut birth = Birth::create(context, &actors, [3; 32], None, 2, [4; 32]).unwrap();
        let trusted_registry = birth.proposed_escrow_keys.clone();
        birth.verify_with_escrow_keys(&trusted_registry).unwrap();
        let (path, holders) = escrow_branches(&birth.gate)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let binding = escrow_binding(
            &birth.context,
            &birth.gate,
            &path,
            birth.public,
            &birth.seed,
        )
        .unwrap();
        let acknowledgements = holders
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    KnowledgeProof::create(
                        actors.shares[id],
                        &ack_binding(&binding, id),
                        &mut OsRng,
                    )
                    .unwrap(),
                )
            })
            .collect();
        birth
            .escrow_certificates
            .insert(path, EscrowCertificate { acknowledgements });
        assert!(birth.verify_with_escrow_keys(&trusted_registry).is_err());
        // Replacing the embedded key proposal cannot replace the charter registry.
        for id in holders {
            birth
                .proposed_escrow_keys
                .insert(id.clone(), actors.points[&id]);
        }
        assert!(birth.verify_with_escrow_keys(&trusted_registry).is_err());
        assert!(birth.verify().is_err());
    }
}
