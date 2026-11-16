#![allow(dead_code)]
use k256::{
    elliptic_curve::rand_core::{CryptoRng, Error as RngError, RngCore},
    ProjectivePoint, Scalar,
};
use line_dealing::{algebra::*, hash::*, message::*, wire::*, Error, Result};

pub const G: ProjectivePoint = ProjectivePoint::GENERATOR;
pub struct TestRng {
    counter: u64,
}
impl TestRng {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
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
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            self.counter += 1;
            let hash = h("test/rng", &self.counter.to_be_bytes());
            chunk.copy_from_slice(&hash[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
pub fn sc(label: &str) -> Scalar {
    reduce(&h("test/scalar", label.as_bytes()))
}
pub fn msg(label: &str) -> [u8; 32] {
    h("test/msg", label.as_bytes())
}
pub fn secret() -> Scalar {
    sc("owner-key")
}
pub fn normalized_secret() -> Scalar {
    if is_odd(G * secret()).unwrap() {
        -secret()
    } else {
        secret()
    }
}
pub fn node_secret(i: u16) -> Scalar {
    sc(&format!("node-sk/{i}"))
}
pub fn keys() -> Vec<ProjectivePoint> {
    (1..=16).map(|i| G * node_secret(i)).collect()
}
pub fn header(suite: u8, mode: u8, slots: u16) -> Header {
    let key = G * if suite == 2 {
        normalized_secret()
    } else {
        secret()
    };
    let mut pin = [0; 72];
    pin[0] = if suite == 2 { 1 } else { 2 };
    Header {
        version: 1,
        suite,
        mode,
        addr_type: if suite == 2 { 4 } else { 5 },
        on_rotation: 2,
        late_inputs: 0,
        chain_id: [1; 32],
        board_id: [2; 32],
        owner_nonce: [3; 32],
        keylist_hash: [4; 32],
        builder_hash: [5; 32],
        public_key: key,
        ephemeral: G,
        address: address_for(if suite == 2 { 4 } else { 5 }, key).unwrap(),
        epoch: 7,
        not_before: 10,
        expires: 100,
        n: 16,
        threshold: 6,
        f: 5,
        variants: if mode == 1 { slots } else { 0 },
        inputs: 1,
        generations: if mode == 2 { slots } else { 0 },
        trigger_id: 0,
        trigger_params: [0; 32],
        intent: Intent {
            outputs: vec![Output {
                script: vec![1; 20],
                amount: 100,
            }],
            change_to: vec![2; 20],
            pin,
            allowed: vec![],
            fee_ceiling: 1000,
            fee_rule: 0,
            bump_delay: 6,
            grid_ratio: [2, 1],
            min_conf: 6,
        },
    }
}
pub struct Context {
    pub keys: Vec<ProjectivePoint>,
    pub messages: Vec<[u8; 32]>,
    pub bound: bool,
}
impl Context {
    pub fn new(messages: Vec<[u8; 32]>) -> Self {
        Self {
            keys: keys(),
            messages,
            bound: false,
        }
    }
}
impl AcceptanceContext for Context {
    fn committee(&self) -> CommitteeState {
        CommitteeState {
            chain_id: [1; 32],
            board_id: [2; 32],
            epoch: 7,
            keylist_hash: [4; 32],
            n: 16,
            f: 5,
            board_height: 20,
            grace_end: 200,
        }
    }
    fn check_header(&self, h: &Header) -> Result<()> {
        if h.chain_id != [1; 32]
            || h.board_id != [2; 32]
            || h.epoch != 7
            || h.keylist_hash != [4; 32]
            || h.builder_hash != [5; 32]
            || h.n != 16
            || h.f != 5
            || h.expires < 20
            || (h.on_rotation == 1 && h.expires > 200)
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn is_bound_or_tombstoned(&self, _: &[u8; 32]) -> bool {
        self.bound
    }
    fn sealed_sighashes(&self, _: &Header) -> Result<Vec<[u8; 32]>> {
        Ok(self.messages.clone())
    }
    fn node_keys(&self) -> &[ProjectivePoint] {
        &self.keys
    }
}
pub fn open_ecdsa() -> (OwnerMessage, Accepted) {
    let mut rng = TestRng::new();
    let message = Owner::open_ecdsa(header(1, 2, 1), secret(), &[sc("nonce-1")], &mut rng)
        .unwrap()
        .encrypt(sc("eph"), &keys(), &mut rng)
        .unwrap();
    let accepted = message.step_a(&Context::new(vec![])).unwrap();
    (message, accepted)
}
pub fn shares(accepted: &Accepted) -> Vec<NodeShares> {
    (1..=16)
        .map(|i| accepted.decrypt(i, node_secret(i)).unwrap())
        .collect()
}
