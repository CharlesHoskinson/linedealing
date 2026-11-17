//! Independent decoders and a consensus check from the chains' own tools,
//! installed by the funding lane under ~/testnet-wallets/bin. Gated by
//! `TESTNET_TOOLS=1`; the plain `cargo test` skips them.
//!
//! - Bitcoin Core 32.1 in regtest: the committee spends a mined coinbase and
//!   `testmempoolaccept` runs full script and signature validation.
//! - cardano-cli: reads the committee-signed CBOR as a Conway transaction and
//!   reports the same txid.
//! - solana CLI: decodes the committee-signed transfer and checks the signature;
//!   devnet `simulateTransaction` with `sigVerify` rejects only the unfunded payer.

use super::{chains::*, codec::*, committee::*};
use line_dealing::builder::SpendKind;
use line_dealing::split::{group::Edwards, request::SpendVariant, schnorr::SchnorrSuite};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn enabled() -> bool {
    std::env::var("TESTNET_TOOLS").as_deref() == Ok("1")
}
fn bin(name: &str) -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap())
        .join("testnet-wallets/bin")
        .join(name)
}
fn run(cmd: &PathBuf, args: &[&str]) -> String {
    let out = Command::new(cmd).args(args).output().expect("tool");
    assert!(
        out.status.success(),
        "{} {:?}: {}{}",
        cmd.display(),
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("testnet-tools-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

struct Regtest {
    dir: PathBuf,
    args: Vec<String>,
}
impl Regtest {
    fn start() -> Self {
        let dir = scratch("regtest");
        std::fs::create_dir_all(&dir).unwrap();
        let port = 20000 + (std::process::id() % 20000);
        let args = vec![
            "-regtest".to_string(),
            format!("-datadir={}", dir.display()),
            format!("-rpcport={port}"),
        ];
        let mut d = args.clone();
        d.extend(["-daemon", "-listen=0", "-txindex=0", "-fallbackfee=0.0001"].map(String::from));
        let d: Vec<&str> = d.iter().map(String::as_str).collect();
        run(&bin("bitcoind"), &d);
        let r = Self { dir, args };
        for _ in 0..60 {
            if r.try_cli(&["getblockchaininfo"]).is_some() {
                return r;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        panic!("bitcoind regtest did not start");
    }
    fn try_cli(&self, args: &[&str]) -> Option<String> {
        let mut a: Vec<&str> = self.args.iter().map(String::as_str).collect();
        a.extend(args);
        let out = Command::new(bin("bitcoin-cli")).args(&a).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8(out.stdout).unwrap())
    }
    fn cli(&self, args: &[&str]) -> String {
        self.try_cli(args)
            .unwrap_or_else(|| panic!("bitcoin-cli {args:?} failed"))
    }
}
impl Drop for Regtest {
    fn drop(&mut self) {
        let _ = self.try_cli(&["stop"]);
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn regtest_spend(kind: SpendKind) {
    let node = Regtest::start();
    let mut rng = fresh();
    let seed = sha256(format!("testnet/regtest/{kind:?}").as_bytes());
    let ecdsa = EcdsaCommittee::new(seed);
    let script = match kind {
        SpendKind::P2wpkh => p2wpkh_script(ecdsa.public_key()),
        _ => p2tr_script(Bip340Committee::new(seed, &mut rng).output_key()),
    };
    let address = btc_address("bcrt", &script);
    node.cli(&["generatetoaddress", "101", &address]);
    let hash = node.cli(&["getblockhash", "1"]);
    let block: Value = serde_json::from_str(&node.cli(&["getblock", hash.trim(), "2"])).unwrap();
    let coinbase = &block["tx"][0];
    let out = &coinbase["vout"][0];
    assert_eq!(out["scriptPubKey"]["hex"].as_str().unwrap(), hex(&script));
    let value = (out["value"].as_f64().unwrap() * 1e8).round() as u64;
    let prev = utxo(coinbase["txid"].as_str().unwrap(), 0, value, script.clone());
    let tx = btc_spend(prev, script.clone(), 1_000, kind);
    let signed = match kind {
        SpendKind::P2wpkh => {
            let sig = ecdsa.sign_p2wpkh(&tx, &mut rng).remove(0).signature;
            let mut item = der(&sig.r().to_bytes().into(), &sig.s().to_bytes().into());
            item.push(1);
            btc_signed(&tx, &[vec![item, compressed(ecdsa.public_key()).to_vec()]])
        }
        _ => {
            let mut c = Bip340Committee::new(seed, &mut rng);
            let (sig, _) = c.sign_variant(SpendVariant::bitcoin(&tx).unwrap(), &mut rng);
            btc_signed(&tx, &[vec![sig.to_vec()]])
        }
    };
    let raw = hex(&signed);
    let accept: Value =
        serde_json::from_str(&node.cli(&["testmempoolaccept", &format!("[\"{raw}\"]")])).unwrap();
    assert_eq!(accept[0]["allowed"], Value::Bool(true), "{accept}");
    assert_eq!(accept[0]["txid"].as_str().unwrap(), hex(&btc_txid(&tx)));
    let decoded: Value = serde_json::from_str(&node.cli(&["decoderawtransaction", &raw])).unwrap();
    assert_eq!(
        decoded["vsize"].as_u64().unwrap(),
        btc_vsize(&signed, tx.unsigned_bytes().unwrap().len())
    );
    let sent = node.cli(&["sendrawtransaction", &raw]);
    assert_eq!(sent.trim(), hex(&btc_txid(&tx)));
    node.cli(&["generatetoaddress", "1", &address]);
    let conf: Value = serde_json::from_str(&node.cli(&["gettxout", sent.trim(), "0"])).unwrap();
    assert_eq!(conf["confirmations"].as_u64(), Some(1));
}

#[test]
fn tools_bitcoind_regtest_accepts_committee_p2wpkh() {
    if enabled() {
        regtest_spend(SpendKind::P2wpkh);
    }
}
#[test]
fn tools_bitcoind_regtest_accepts_committee_p2tr() {
    if enabled() {
        regtest_spend(SpendKind::P2tr);
    }
}

/// cardano-cli reads the committee-signed transaction (Conway text envelope)
/// and reports the txid that the Rust code signed.
#[test]
fn tools_cardano_cli_reads_committee_tx() {
    if !enabled() {
        return;
    }
    let mut rng = fresh();
    let mut committee = Ed25519Committee::new(sha256(b"testnet/tools/cardano"), &mut rng);
    let vk: [u8; 32] = Edwards::signature_point(committee.output_key()).unwrap();
    let addr = ada_enterprise(&vk);
    let tx = AdaTx {
        inputs: vec![(sha256(b"input"), 0)],
        outputs: vec![(addr.clone(), 9_800_000)],
        fee: 200_000,
        ttl: 140_000_000,
    };
    let (sig, _) = committee.sign_variant(
        SpendVariant {
            transaction: tx.id().to_vec(),
            prevouts: vec![],
            destination: addr,
        },
        &mut rng,
    );
    let signed = tx.signed(&vk, &sig);
    let file = scratch("cardano.tx.json");
    let envelope = serde_json::json!({
        "type": "Tx ConwayEra",
        "description": "Ledger Cddl Format",
        "cborHex": hex(&signed),
    });
    std::fs::write(&file, envelope.to_string()).unwrap();
    let path = file.display().to_string();
    let out = run(
        &bin("cardano-cli"),
        &["latest", "transaction", "txid", "--tx-file", &path],
    );
    assert!(out.contains(&hex(&tx.id())), "cardano-cli txid: {out}");
    eprintln!("cardano-cli txid output: {}", out.trim());
}

/// Always run: the body above has the txid that cardano-cli 11.2.3.0 printed
/// for it on 2026-11-15 (the body is deterministic; only the witness varies).
#[test]
fn cardano_body_matches_recorded_cardano_cli_txid() {
    let mut rng = fresh();
    let committee = Ed25519Committee::new(sha256(b"testnet/tools/cardano"), &mut rng);
    let vk: [u8; 32] = Edwards::signature_point(committee.output_key()).unwrap();
    let tx = AdaTx {
        inputs: vec![(sha256(b"input"), 0)],
        outputs: vec![(ada_enterprise(&vk), 9_800_000)],
        fee: 200_000,
        ttl: 140_000_000,
    };
    assert_eq!(
        hex(&tx.id()),
        "3ebf92e23f3cd02eee94977f28611278c4ebf1d509e3aca85347efd893bdced6"
    );
}

/// The Solana CLI decodes the committee-signed transfer and verifies its
/// signature; devnet simulation with sigVerify fails only on the empty payer.
#[test]
fn tools_solana_cli_decodes_committee_transfer() {
    if !enabled() {
        return;
    }
    let mut rng = fresh();
    let mut committee = Ed25519Committee::new(sha256(b"testnet/tools/solana"), &mut rng);
    let from: [u8; 32] = Edwards::signature_point(committee.output_key()).unwrap();
    let to = unbase58("6sNDyQQqz2gqK6Lwbs1b8PqTditFtsXtmJRYWkpW81Zd")
        .unwrap()
        .try_into()
        .unwrap();
    let reply = Command::new("curl")
        .args([
            "-sS",
            "-m",
            "30",
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "-d",
            r#"{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}"#,
            "https://api.devnet.solana.com",
        ])
        .output()
        .unwrap();
    let reply: Value = serde_json::from_slice(&reply.stdout).unwrap();
    let blockhash: [u8; 32] = unbase58(reply["result"]["value"]["blockhash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let message = sol_transfer_message(&from, &to, &blockhash, 1_000_000);
    let (sig, _) = committee.sign_variant(
        SpendVariant {
            transaction: message.clone(),
            prevouts: vec![],
            destination: to.to_vec(),
        },
        &mut rng,
    );
    let wire = base64(&sol_signed(&sig, &message));
    let out = run(&bin("solana"), &["decode-transaction", &wire, "base64"]);
    eprintln!("{out}");
    assert!(
        out.contains(&format!("Signature 0: {} (pass)", base58(&sig))),
        "{out}"
    );
    assert!(out.contains(&base58(&from)) && out.contains("11111111111111111111111111111111"));
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "simulateTransaction",
        "params": [wire, {"encoding": "base64", "sigVerify": true, "commitment": "finalized"}]});
    let sim = Command::new("curl")
        .args([
            "-sS",
            "-m",
            "30",
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "-d",
            &body.to_string(),
            "https://api.devnet.solana.com",
        ])
        .output()
        .unwrap();
    let sim: Value = serde_json::from_slice(&sim.stdout).unwrap();
    eprintln!("simulate: {sim}");
    assert!(sim.get("error").is_none(), "{sim}");
    // Parsing and sigVerify passed; the runtime rejects only the unfunded fee
    // payer (a bad signature would be SignatureFailure, a bad layout an RPC error).
    let err = sim["result"]["value"]["err"].as_str().unwrap_or_default();
    assert!(
        ["InvalidAccountForFee", "AccountNotFound"].contains(&err),
        "{sim}"
    );
}
