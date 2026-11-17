//! Per-chain addresses and signed transaction encodings.
#![allow(dead_code)]

use super::codec::*;
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint};
use line_dealing::builder::{Eip1559Transaction, OutPoint, SpendKind, Utxo, UtxoTransaction};
use line_dealing::wire::Output;
use sha3::{Digest, Keccak256};

// ---------------- Bitcoin ----------------

pub fn compressed(pk: ProjectivePoint) -> [u8; 33] {
    pk.to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}
pub fn x_only(pk: ProjectivePoint) -> [u8; 32] {
    compressed(pk)[1..].try_into().unwrap()
}
pub fn p2wpkh_script(pk: ProjectivePoint) -> Vec<u8> {
    segwit_script(0, &hash160(&compressed(pk)))
}
pub fn p2tr_script(q: ProjectivePoint) -> Vec<u8> {
    segwit_script(1, &x_only(q))
}
pub fn btc_address(hrp: &str, script: &[u8]) -> String {
    let version = if script[0] == 0 { 0 } else { script[0] - 0x50 };
    segwit_encode(hrp, version, &script[2..])
}
pub fn script_for_address(hrp: &str, address: &str) -> Vec<u8> {
    let (v, p) = segwit_decode(hrp, address).expect("segwit address");
    segwit_script(v, &p)
}

/// One-input, one-output RBF spend in the builder's subset (version 2).
pub fn btc_spend(prev: Utxo, to: Vec<u8>, fee: u64, kind: SpendKind) -> UtxoTransaction {
    let amount = prev.value - fee;
    UtxoTransaction {
        inputs: vec![prev],
        outputs: vec![Output {
            amount: u128::from(amount),
            script: to,
        }],
        fee,
        vsize: 0,
        signed_vsize: None,
        anchor_height: 0,
        lock_time: 0,
        spend_kind: kind,
    }
}
/// BIP144 serialization with witnesses.
pub fn btc_signed(tx: &UtxoTransaction, witnesses: &[Vec<Vec<u8>>]) -> Vec<u8> {
    assert_eq!(tx.inputs.len(), witnesses.len());
    let unsigned = tx.unsigned_bytes().unwrap();
    // unsigned = version(4) | inputs+outputs | locktime(4)
    let mut out = unsigned[..4].to_vec();
    out.extend([0x00, 0x01]);
    out.extend(&unsigned[4..unsigned.len() - 4]);
    for stack in witnesses {
        compact(stack.len(), &mut out);
        for item in stack {
            compact(item.len(), &mut out);
            out.extend(item);
        }
    }
    out.extend(&unsigned[unsigned.len() - 4..]);
    out
}
/// txid in display order (what explorers show).
pub fn btc_txid(tx: &UtxoTransaction) -> [u8; 32] {
    let mut id = sha256d(&tx.unsigned_bytes().unwrap());
    id.reverse();
    id
}
pub fn btc_vsize(signed: &[u8], unsigned_len: usize) -> u64 {
    let weight = unsigned_len * 3 + signed.len();
    weight.div_ceil(4) as u64
}
pub fn utxo(txid_display: &str, vout: u32, value: u64, script: Vec<u8>) -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: unhex(txid_display).try_into().unwrap(),
            vout,
        },
        value,
        script_pubkey: script,
        confirmations: 1,
    }
}

// ---------------- Ethereum ----------------

pub fn eth_address(pk: ProjectivePoint) -> [u8; 20] {
    let point = pk.to_affine().to_encoded_point(false);
    Keccak256::digest(&point.as_bytes()[1..])[12..]
        .try_into()
        .unwrap()
}
/// EIP-55 mixed-case checksum encoding.
pub fn eip55(addr: &[u8; 20]) -> String {
    let lower = hex(addr);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}
/// EIP-1559 signed envelope: 0x02 || rlp([... nine fields, y_parity, r, s]).
pub fn eth_signed(tx: &Eip1559Transaction, y_parity: bool, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::new();
    for n in [
        u128::from(tx.chain_id),
        u128::from(tx.nonce),
        tx.max_priority_fee_per_gas,
        tx.max_fee_per_gas,
        u128::from(tx.gas_limit),
    ] {
        rlp_uint(&n.to_be_bytes(), &mut body);
    }
    rlp_bytes(&tx.to, &mut body);
    rlp_uint(&tx.value.to_be_bytes(), &mut body);
    body.extend([0x80, 0xc0]); // empty data, empty access list
    rlp_uint(&[u8::from(y_parity)], &mut body);
    rlp_uint(r, &mut body);
    rlp_uint(s, &mut body);
    let mut out = vec![2];
    rlp_list(&body, &mut out);
    out
}
pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

// ---------------- Cardano ----------------

/// Shelley enterprise address (CIP-19 type 6), testnet network id 0.
pub fn ada_enterprise(vk: &[u8; 32]) -> Vec<u8> {
    let mut a = vec![0x60];
    a.extend(blake2b224(vk));
    a
}
pub fn ada_bech32(addr: &[u8]) -> String {
    bech32_bytes("addr_test", addr, Variant::Bech32)
}
pub struct AdaTx {
    pub inputs: Vec<([u8; 32], u32)>,
    pub outputs: Vec<(Vec<u8>, u64)>,
    pub fee: u64,
    pub ttl: u64,
}
impl AdaTx {
    /// Transaction body: {0: inputs, 1: outputs, 2: fee, 3: ttl}.
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        cbor_map(4, &mut b);
        cbor_uint(0, &mut b);
        cbor_array(self.inputs.len(), &mut b);
        for (id, ix) in &self.inputs {
            cbor_array(2, &mut b);
            cbor_bytes(id, &mut b);
            cbor_uint(u64::from(*ix), &mut b);
        }
        cbor_uint(1, &mut b);
        cbor_array(self.outputs.len(), &mut b);
        for (addr, coin) in &self.outputs {
            cbor_array(2, &mut b);
            cbor_bytes(addr, &mut b);
            cbor_uint(*coin, &mut b);
        }
        cbor_uint(2, &mut b);
        cbor_uint(self.fee, &mut b);
        cbor_uint(3, &mut b);
        cbor_uint(self.ttl, &mut b);
        b
    }
    pub fn id(&self) -> [u8; 32] {
        blake2b256(&self.body())
    }
    /// [body, {0: [[vkey, sig]]}, true, null]
    pub fn signed(&self, vk: &[u8; 32], sig: &[u8; 64]) -> Vec<u8> {
        let mut t = Vec::new();
        cbor_array(4, &mut t);
        t.extend(self.body());
        cbor_map(1, &mut t);
        cbor_uint(0, &mut t);
        cbor_array(1, &mut t);
        cbor_array(2, &mut t);
        cbor_bytes(vk, &mut t);
        cbor_bytes(sig, &mut t);
        t.push(CBOR_TRUE);
        t.push(CBOR_NULL);
        t
    }
}

// ---------------- Solana ----------------

pub const SYSTEM_PROGRAM: [u8; 32] = [0; 32];
/// Legacy message with one SystemProgram::Transfer instruction.
pub fn sol_transfer_message(
    from: &[u8; 32],
    to: &[u8; 32],
    blockhash: &[u8; 32],
    lamports: u64,
) -> Vec<u8> {
    let mut m = vec![1, 0, 1, 3];
    m.extend(from);
    m.extend(to);
    m.extend(SYSTEM_PROGRAM);
    m.extend(blockhash);
    m.extend([1, 2, 2, 0, 1, 12]);
    m.extend(2u32.to_le_bytes());
    m.extend(lamports.to_le_bytes());
    m
}
pub fn sol_signed(sig: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let mut t = vec![1];
    t.extend(sig);
    t.extend(message);
    t
}
