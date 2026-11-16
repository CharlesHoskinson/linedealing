//! Split-line discovery prototype: key algebra, in-process protocol parties,
//! the envelope, the request state machine and the charter profiles.
//! Ordering, authorization and durable rollback protection belong to the board.
pub mod access;
pub mod birth;
pub mod contribution;
pub mod ecdsa;
pub mod envelope;
pub mod group;
pub mod hpke;
pub mod prf;
pub mod profile;
pub mod request;
pub mod schnorr;
pub mod slots;
pub mod state;
