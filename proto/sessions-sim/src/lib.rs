//! Deterministic discovery model, not production cryptography or a service.
//! Not modeled: rekey/epochs beyond one epoch; anchor_before_release;
//! evidence/PCR/key-set checks; JSON API; general refusal ordering (the requested
//! slot-bind ordering is modeled); value/name rules; size/line limits; actual
//! filesystem IO, mount failures, share repair protocol, or network timing.
//! SS-007/008 crypto is the task's SHA-256 abstraction, with plaintext typed
//! bodies inaccessible to protocol decisions until authentication. All operations
//! are synchronous and serialized (SS-107); crashes interrupt explicit boundaries.

pub mod board;
pub mod experiments;
pub mod faults;
pub mod ledger;
pub mod measurements;
pub mod node;
pub mod oracle;
pub mod params;
pub mod sim;
pub use faults::*;
pub use node::{Body, Error, Record, Slot, Statement};
pub use params::*;
use sha2::{Digest as _, Sha256};
pub use sim::Sim;
pub type Digest = [u8; 32];
pub type Sid = Digest;
pub fn hash(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

/// SplitMix64. The RNG is simulation infrastructure and is not disk-rollback state.
#[derive(Clone, Debug)]
pub struct Rng(pub u64);
impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    pub fn nonce(&mut self) -> [u8; 24] {
        let mut out = [0; 24];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_be_bytes());
        }
        out
    }
}
