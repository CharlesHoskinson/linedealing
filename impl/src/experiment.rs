//! Deterministic, public-key fixtures for benchmarks and the in-process simulator.
//! These seeds and keys are public test data. Never use them with real funds.
use crate::{
    algebra::{is_odd, reduce},
    hash::h,
    message::*,
    signing::SigningPackage,
    wire::{address_for, Header, Intent, Output},
    Result,
};
use k256::{
    elliptic_curve::rand_core::{CryptoRng, Error as RngError, RngCore},
    ProjectivePoint, Scalar,
};

pub struct SeededRng {
    seed: u64,
    counter: u64,
}
impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self { seed, counter: 0 }
    }
}
impl CryptoRng for SeededRng {}
impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut out = [0; 8];
        self.fill_bytes(&mut out);
        u64::from_be_bytes(out)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            self.counter += 1;
            let value = h(
                "experiment/rng",
                &[self.seed.to_be_bytes(), self.counter.to_be_bytes()].concat(),
            );
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[derive(Clone)]
pub struct SecpSetup {
    pub header: Header,
    pub keys: Vec<ProjectivePoint>,
    pub secrets: Vec<Scalar>,
    pub messages: Vec<[u8; 32]>,
    state: crate::builder::UtxoState,
    policy: crate::builder::UtxoPolicy,
    secret: Scalar,
    seed: u64,
    ecdsa: Vec<([u8; 32], k256::ecdsa::Signature)>,
    bip340: Vec<([u8; 32], k256::schnorr::Signature)>,
}
impl SecpSetup {
    pub fn new(n: u16, threshold: u16, suite: u8, sealed: bool, seed: u64) -> Result<Self> {
        let secret = reduce(&h("experiment/key", &seed.to_be_bytes()));
        let secret = if suite == 2 && is_odd(crate::algebra::mul_generator(secret))? {
            -secret
        } else {
            secret
        };
        let key = crate::algebra::mul_generator(secret);
        let secrets: Vec<_> = (1..=n)
            .map(|i| reduce(&h("experiment/node", &i.to_be_bytes())))
            .collect();
        let keys = secrets
            .iter()
            .map(|s| crate::algebra::mul_generator(*s))
            .collect();
        use crate::builder::*;
        let address = address_for(if suite == 1 { 3 } else { 4 }, key)?;
        let owner_script = [
            if suite == 1 {
                vec![0, 20]
            } else {
                vec![0x51, 32]
            },
            address.clone(),
        ]
        .concat();
        let outpoint = OutPoint {
            txid: h("experiment/coin", &seed.to_be_bytes()),
            vout: 0,
        };
        let mut pin = [0; 72];
        pin[0] = 1;
        pin[1..33].copy_from_slice(&outpoint.txid);
        pin[37..45].copy_from_slice(&200_000u64.to_be_bytes());
        let state = UtxoState {
            height: 100,
            utxos: vec![Utxo {
                outpoint,
                value: 200_000,
                script_pubkey: owner_script.clone(),
                confirmations: 10,
            }],
            block_median_rates: [FeeRate::integer(1); 6],
        };
        let policy = UtxoPolicy {
            owner_script: owner_script.clone(),
            spend_kind: if suite == 1 {
                SpendKind::P2wpkh
            } else {
                SpendKind::P2tr
            },
            max_inputs: 1,
            late_inputs: false,
            dust_threshold: 294,
            replacement_increment: FeeRate::integer(1),
        };
        let f = (n - 1) / 3;
        let header = Header {
            version: 1,
            suite,
            mode: if sealed { 1 } else { 2 },
            addr_type: if suite == 1 { 3 } else { 4 },
            on_rotation: 1,
            late_inputs: 0,
            chain_id: [1; 32],
            board_id: [2; 32],
            owner_nonce: h("experiment/owner", &seed.to_be_bytes()),
            keylist_hash: [4; 32],
            builder_hash: [5; 32],
            public_key: key,
            ephemeral: ProjectivePoint::GENERATOR,
            address,
            epoch: 1,
            not_before: 0,
            expires: 1_000_000,
            n,
            threshold,
            f,
            variants: if sealed { 8 } else { 0 },
            inputs: 1,
            generations: if sealed { 0 } else { 1 },
            trigger_id: 0,
            trigger_params: [0; 32],
            intent: Intent {
                outputs: vec![Output {
                    script: [vec![0, 20], vec![1; 20]].concat(),
                    amount: 20_000,
                }],
                change_to: owner_script,
                pin,
                allowed: vec![],
                fee_ceiling: 100_000,
                fee_rule: 0,
                bump_delay: 6,
                grid_ratio: [2, 1],
                min_conf: 1,
            },
        };
        let mut result = Self {
            header,
            keys,
            secrets,
            messages: vec![],
            state,
            policy,
            secret,
            seed,
            ecdsa: vec![],
            bip340: vec![],
        };
        result.messages = result
            .transactions()?
            .iter()
            .map(|tx| {
                tx.sighashes()
                    .map(|hashes| hashes[0])
                    .map_err(|_| crate::Error::Context)
            })
            .collect::<Result<_>>()?;
        if sealed {
            if suite == 1 {
                use k256::ecdsa::signature::hazmat::PrehashSigner;
                let key = k256::ecdsa::SigningKey::from_bytes(&secret.to_bytes())
                    .map_err(|_| crate::Error::Scalar)?;
                for m in &result.messages {
                    result.ecdsa.push((
                        *m,
                        key.sign_prehash(m).map_err(|_| crate::Error::Signature)?,
                    ));
                }
            } else {
                let key = k256::schnorr::SigningKey::from_bytes(&secret.to_bytes())
                    .map_err(|_| crate::Error::Scalar)?;
                for m in &result.messages {
                    result.bip340.push((
                        *m,
                        key.sign_raw(m, &[0; 32])
                            .map_err(|_| crate::Error::Signature)?,
                    ));
                }
            }
        }
        Ok(result)
    }
    /// Deal and encrypt. Sealed wallet signatures are prepared outside the timed operation.
    pub fn owner_message(&self, rng: &mut SeededRng) -> Result<OwnerMessage> {
        let nonce = reduce(&h("experiment/nonce", &self.seed.to_be_bytes()));
        let owner = match (self.header.suite, self.header.mode) {
            (1, 2) => Owner::open_ecdsa(self.header.clone(), self.secret, &[nonce], rng)?,
            (2, 2) => Owner::open_bip340(
                self.header.clone(),
                self.secret,
                &[(nonce, nonce + Scalar::ONE)],
                rng,
            )?,
            (1, 1) => Owner::sealed_ecdsa(self.header.clone(), &self.ecdsa, rng)?,
            (2, 1) => Owner::sealed_bip340(self.header.clone(), &self.bip340, rng)?,
            _ => return Err(crate::Error::Parameters),
        };
        owner.encrypt(
            reduce(&h("experiment/eph", &self.seed.to_be_bytes())),
            &self.keys,
            rng,
        )
    }
    pub fn package(&self, accepted: &Accepted) -> Result<SigningPackage> {
        let tx = self.transactions()?.remove(0);
        let sighash = tx.sighashes().map_err(|_| crate::Error::Context)?[0];
        accepted.signing_package(1, 1, sighash, self.lock_digest(accepted.message().rid()?)?)
    }
    fn transactions(&self) -> Result<Vec<crate::builder::UtxoTransaction>> {
        use crate::builder::*;
        if self.header.mode == 1 {
            let sealed = SealedUtxoIntent {
                intent: self.header.intent.clone(),
                inputs: self.state.utxos.clone(),
                policy: self.policy.clone(),
            };
            (1..=8)
                .map(|j| variant_utxo(&sealed, j, 8).map_err(|_| crate::Error::Context))
                .collect()
        } else {
            Ok(vec![build_utxo(
                &self.header.intent,
                &self.state,
                &self.policy,
                1,
                &[],
            )
            .map_err(|_| crate::Error::Context)?])
        }
    }
    pub fn transaction(&self) -> Result<Vec<u8>> {
        self.transactions()?
            .remove(0)
            .unsigned_bytes()
            .map_err(|_| crate::Error::Context)
    }
    pub fn lock_digest(&self, rid: [u8; 32]) -> Result<[u8; 32]> {
        crate::signing::LockDigest {
            rid,
            epoch: 1,
            generation: 1,
            attempt: 1,
            anchor_height: 100,
            anchor_hash: h("simulation/block", &100u64.to_be_bytes()),
            transaction: &self.transaction()?,
            sighashes: &self.messages[..1],
        }
        .hash()
    }
}
impl AcceptanceContext for SecpSetup {
    fn committee(&self) -> CommitteeState {
        CommitteeState {
            chain_id: self.header.chain_id,
            board_id: self.header.board_id,
            epoch: self.header.epoch,
            keylist_hash: self.header.keylist_hash,
            n: self.header.n,
            f: self.header.f,
            board_height: 1,
            grace_end: 1_000_001,
        }
    }
    fn check_header(&self, hdr: &Header) -> Result<()> {
        if hdr.builder_hash != self.header.builder_hash {
            return Err(crate::Error::Context);
        }
        Ok(())
    }
    fn is_bound_or_tombstoned(&self, _: &[u8; 32]) -> bool {
        false
    }
    fn sealed_sighashes(&self, _: &Header) -> Result<Vec<[u8; 32]>> {
        self.transactions()?
            .iter()
            .map(|tx| {
                tx.sighashes()
                    .map(|hashes| hashes[0])
                    .map_err(|_| crate::Error::Context)
            })
            .collect()
    }
    fn node_keys(&self) -> &[ProjectivePoint] {
        &self.keys
    }
}

#[derive(Clone)]
pub struct EdSetup {
    pub header: crate::ed25519::Header,
    pub keys: Vec<curve25519_dalek::edwards::EdwardsPoint>,
    pub secrets: Vec<curve25519_dalek::scalar::Scalar>,
    pub messages: Vec<Vec<u8>>,
    pub digest: [u8; 32],
    seed: [u8; 32],
    signatures: Vec<(Vec<u8>, ed25519_dalek::Signature)>,
}
impl EdSetup {
    pub fn new(n: u16, threshold: u16, sealed: bool, seed: u64) -> Result<Self> {
        use crate::ed25519::{hq, secret_from_seed, Header};
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint};
        use ed25519_dalek::Signer;
        let seed = h("experiment/ed-key", &seed.to_be_bytes());
        let public_key = EdwardsPoint::mul_base(&secret_from_seed(&seed));
        let secrets: Vec<_> = (1..=n)
            .map(|i| hq("experiment/node", &i.to_be_bytes()))
            .collect();
        let keys = secrets.iter().map(EdwardsPoint::mul_base).collect();
        let messages: Vec<_> = (0..if sealed { 8u16 } else { 1 })
            .map(|j| {
                h(
                    "experiment/ed-tx",
                    &[seed.as_slice(), j.to_be_bytes().as_slice()].concat(),
                )
                .to_vec()
            })
            .collect();
        let mut pin = [0; 72];
        pin[0] = 3;
        pin[1..33].copy_from_slice(&seed);
        pin[33..65].copy_from_slice(&seed);
        let header = Header {
            version: 1,
            suite: 3,
            mode: if sealed { 1 } else { 2 },
            addr_type: 6,
            on_rotation: 1,
            late_inputs: 0,
            chain_id: [1; 32],
            board_id: [2; 32],
            owner_nonce: seed,
            keylist_hash: [4; 32],
            builder_hash: [5; 32],
            public_key,
            ephemeral: G,
            address: public_key.compress().to_bytes().to_vec(),
            epoch: 1,
            not_before: 0,
            expires: 1_000_000,
            n,
            threshold,
            f: (n - 1) / 3,
            variants: if sealed { 8 } else { 0 },
            inputs: 1,
            generations: if sealed { 0 } else { 1 },
            trigger_id: 0,
            trigger_params: [0; 32],
            intent: Intent {
                outputs: vec![Output {
                    script: vec![1; 32],
                    amount: 100,
                }],
                change_to: vec![2; 32],
                pin,
                allowed: vec![],
                fee_ceiling: 100_000,
                fee_rule: 0,
                bump_delay: 6,
                grid_ratio: [2, 1],
                min_conf: 1,
            },
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let signatures = if sealed {
            messages.iter().map(|m| (m.clone(), key.sign(m))).collect()
        } else {
            vec![]
        };
        Ok(Self {
            header,
            keys,
            secrets,
            messages,
            digest: h("experiment/ed-lock", &seed),
            seed,
            signatures,
        })
    }
    pub fn owner_message(&self, rng: &mut SeededRng) -> Result<crate::ed25519::OwnerMessage> {
        use crate::ed25519::{hq, Owner};
        use curve25519_dalek::scalar::Scalar;
        let d = hq("experiment/nonce", &self.seed);
        let owner = if self.header.mode == 1 {
            Owner::sealed(self.header.clone(), &self.signatures, rng)?
        } else {
            Owner::open(self.header.clone(), self.seed, &[(d, d + Scalar::ONE)], rng)?
        };
        owner.encrypt(hq("experiment/eph", &self.seed), &self.keys, rng)
    }
    pub fn package(
        &self,
        accepted: &crate::ed25519::Accepted,
    ) -> Result<crate::ed25519::SigningPackage> {
        accepted.signing_package(1, 1, &self.messages[0], self.digest)
    }
}
impl crate::ed25519::AcceptanceContext for EdSetup {
    fn committee(&self) -> CommitteeState {
        CommitteeState {
            chain_id: self.header.chain_id,
            board_id: self.header.board_id,
            epoch: self.header.epoch,
            keylist_hash: self.header.keylist_hash,
            n: self.header.n,
            f: self.header.f,
            board_height: 1,
            grace_end: 1_000_001,
        }
    }
    fn check_header(&self, hdr: &crate::ed25519::Header) -> Result<()> {
        if hdr.builder_hash != self.header.builder_hash {
            return Err(crate::Error::Context);
        }
        Ok(())
    }
    fn is_bound_or_tombstoned(&self, _: &[u8; 32]) -> bool {
        false
    }
    fn sealed_messages(&self, _: &crate::ed25519::Header) -> Result<Vec<Vec<u8>>> {
        Ok(self.messages.clone())
    }
    fn node_keys(&self) -> &[curve25519_dalek::edwards::EdwardsPoint] {
        &self.keys
    }
}
