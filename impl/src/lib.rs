//! Line dealing with ECDSA, BIP340, Ed25519, builders, and an ordered board.
//!
//! Route cryptographic operations through the board's persisted signer policy.
//! Chain verification, authenticated transport, and physical erasure are adapters.

pub mod algebra;
pub mod board;
pub mod builder;
pub mod ed25519;
pub mod experiment;
pub mod hash;
pub mod simulation;
pub mod split;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Point,
    Scalar,
    Parameters,
    Threshold,
    Share,
    BadPartial(u16),
    Proof,
    Signature,
    Context,
    Nonce,
}

pub type Result<T> = core::result::Result<T, Error>;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "line dealing: {self:?}")
    }
}

impl std::error::Error for Error {}
pub mod message;
pub mod reshare;
pub mod signing;
pub mod wire;
