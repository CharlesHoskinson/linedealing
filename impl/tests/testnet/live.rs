//! Live testnet runs: fund the committee address, spend back, wait, record.
//!
//! Gate: `TESTNET_E2E=1` plus `--ignored`. HTTP goes through the installed
//! `curl`. Funding uses `~/testnet-wallets/bin/fund-<net> <address> <amount>`
//! and `return-address-<net>`; without them the test prints the address and
//! polls. Key seeds live in the git-ignored `impl/testnet/keys.local` (0600).
//! Every broadcast is preceded by a chain identity check; no mainnet endpoint
//! appears in this file.
#![allow(dead_code)]

use super::{chains::*, codec::*, committee::*};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, VerifyingKey};
use line_dealing::builder::{Eip1559Transaction, SpendKind};
use line_dealing::split::{group::Edwards, request::SpendVariant, schnorr::SchnorrSuite};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const BTC_TESTNET4_GENESIS: &str =
    "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";
const BTC_SIGNET_GENESIS: &str = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const SEPOLIA_RPC: &str = "https://ethereum-sepolia-rpc.publicnode.com";
const KOIOS: &str = "https://preprod.koios.rest/api/v1";
const SOLANA_RPC: &str = "https://api.devnet.solana.com";
const SOLANA_DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

fn enabled() -> bool {
    let on = std::env::var("TESTNET_E2E").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set TESTNET_E2E=1 to run live testnet tests");
    }
    on
}
fn impl_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").expect("HOME"))
}
fn wait_secs(default: u64) -> Duration {
    Duration::from_secs(
        std::env::var("TESTNET_WAIT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default),
    )
}
fn sleep(secs: u64) {
    std::thread::sleep(Duration::from_secs(secs));
}

// ---------------- key seeds ----------------

/// Seed for `name` from impl/testnet/keys.local, created by OsRng on first use.
/// The file is mode 0600 and git-ignored; nothing prints its contents.
pub fn live_seed(name: &str) -> [u8; 32] {
    use k256::elliptic_curve::rand_core::RngCore;
    use std::os::unix::fs::PermissionsExt;
    let path = impl_dir().join("testnet/keys.local");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    for line in text.lines() {
        if let Some((n, h)) = line.split_once(' ') {
            if n == name {
                return unhex(h.trim()).try_into().expect("32-byte seed");
            }
        }
    }
    let mut seed = [0u8; 32];
    fresh().fill_bytes(&mut seed);
    let mut text = text;
    text.push_str(&format!("{name} {}\n", hex(&seed)));
    std::fs::write(&path, text).expect("write keys.local");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    seed
}

// ---------------- HTTP through curl ----------------

fn curl(args: &[&str]) -> String {
    let out = Command::new("curl")
        .args(["-sS", "-m", "60", "--retry", "3", "--retry-delay", "2"])
        .args(args)
        .output()
        .expect("curl");
    assert!(
        out.status.success(),
        "curl {:?}: {}",
        args.first(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn get(url: &str) -> String {
    curl(&["-H", "accept: application/json", url])
}
fn get_json(url: &str) -> Value {
    serde_json::from_str(&get(url)).unwrap_or_else(|e| panic!("{url}: {e}"))
}
fn post(url: &str, content_type: &str, body: &str) -> String {
    curl(&[
        "-X",
        "POST",
        "-H",
        &format!("content-type: {content_type}"),
        "-H",
        "accept: application/json",
        "--data-binary",
        body,
        url,
    ])
}
fn post_json(url: &str, body: &Value) -> Value {
    let text = post(url, "application/json", &body.to_string());
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{url}: {e}: {text}"))
}
fn rpc(url: &str, method: &str, params: Value) -> Value {
    let reply = post_json(
        url,
        &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
    );
    if let Some(err) = reply.get("error") {
        panic!("{method}: {err}");
    }
    reply["result"].clone()
}
fn hex_u128(v: &Value) -> u128 {
    u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

// ---------------- funding wallets ----------------

fn tool(name: &str) -> Option<PathBuf> {
    let p = home().join("testnet-wallets/bin").join(name);
    p.exists().then_some(p)
}
/// Ask the funding wallet to pay `amount` base units to `address`.
fn fund(net: &str, address: &str, amount: u128) -> Option<String> {
    let Some(script) = tool(&format!("fund-{net}")) else {
        eprintln!(
            "[{net}] no funding script; send {amount} base units to {address} (the test polls)"
        );
        return None;
    };
    Some(try_fund(&script, net, address, amount).unwrap_or_else(|e| panic!("{e}")))
}
/// Run one funding script. An error carries the script's stderr.
fn try_fund(script: &Path, net: &str, address: &str, amount: u128) -> Result<String, String> {
    let out = Command::new(script)
        .args([address, &amount.to_string()])
        .output()
        .expect("fund script");
    if !out.status.success() {
        return Err(format!(
            "fund-{net} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let txid = String::from_utf8(out.stdout).unwrap().trim().to_string();
    eprintln!("[{net}] funding tx {txid}");
    Ok(txid)
}
fn return_address(net: &str) -> String {
    if let Some(script) = tool(&format!("return-address-{net}")) {
        let out = Command::new(script).output().expect("return-address");
        assert!(out.status.success());
        return String::from_utf8(out.stdout).unwrap().trim().to_string();
    }
    let var = format!("TESTNET_RETURN_{}", net.to_uppercase().replace('-', "_"));
    std::env::var(&var)
        .unwrap_or_else(|_| panic!("no return-address-{net} script and no {var} set"))
}
/// Poll `check` every `every` seconds until it returns Some or time runs out.
fn poll<T>(what: &str, limit: Duration, every: u64, mut check: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = check() {
            return v;
        }
        assert!(start.elapsed() < limit, "timed out waiting for {what}");
        eprintln!("waiting for {what} ({}s)", start.elapsed().as_secs());
        sleep(every);
    }
}

// ---------------- results ----------------

pub struct Row<'a> {
    pub network: &'a str,
    pub scheme: &'a str,
    pub path: &'a str,
    pub address: &'a str,
    pub funding: &'a str,
    pub spend: &'a str,
    pub explorer: String,
}
fn record(row: Row) {
    use std::io::Write;
    let path = impl_dir().join("testnet/RESULTS.md");
    let date = String::from_utf8(
        Command::new("date")
            .args(["-u", "+%Y-%m-%d %H:%M"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let line = format!(
        "| {} | {} | {} | `{}` | `{}` | [`{}`]({}) | {} |\n",
        row.network,
        row.scheme,
        row.path,
        row.address,
        row.funding,
        row.spend,
        row.explorer,
        date.trim()
    );
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("RESULTS.md exists");
    f.write_all(line.as_bytes()).unwrap();
    eprintln!("recorded: {line}");
}

// ---------------- Bitcoin testnet4 / signet ----------------

pub fn bitcoin(kind: SpendKind) {
    if !enabled() {
        return;
    }
    let net = std::env::var("TESTNET_BTC").unwrap_or_else(|_| "signet".into());
    let (genesis, fund_net) = match net.as_str() {
        "testnet4" => (BTC_TESTNET4_GENESIS, "btc-testnet4"),
        "signet" => (BTC_SIGNET_GENESIS, "btc-signet"),
        other => panic!("TESTNET_BTC must be testnet4 or signet, not {other}"),
    };
    let api = format!("https://mempool.space/{net}/api");
    assert_eq!(get(&format!("{api}/block-height/0")).trim(), genesis);
    let mut rng = fresh();
    let (label, scheme, path) = match kind {
        SpendKind::P2wpkh => ("btc-p2wpkh", "P2WPKH ECDSA", "split envelope"),
        SpendKind::P2tr => ("btc-p2tr", "P2TR BIP340 (BIP86 key path)", "split envelope"),
        _ => unreachable!(),
    };
    let seed = live_seed(label);
    let ecdsa = EcdsaCommittee::new(seed);
    let script = match kind {
        SpendKind::P2wpkh => p2wpkh_script(ecdsa.public_key()),
        _ => p2tr_script(Bip340Committee::new(seed, &mut rng).output_key()),
    };
    let address = btc_address("tb", &script);
    eprintln!("[{net}] committee {scheme} address {address}");
    let confirmed = |api: &str| -> Vec<Value> {
        get_json(&format!("{api}/address/{address}/utxo"))
            .as_array()
            .unwrap()
            .iter()
            .filter(|u| u["status"]["confirmed"].as_bool() == Some(true))
            .cloned()
            .collect()
    };
    let mut funding = "existing".to_string();
    if confirmed(&api).is_empty() {
        // Small by default: the spend returns all but the fee.
        let amount = std::env::var("TESTNET_BTC_FUND")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5_000u128);
        if let Some(id) = fund(fund_net, &address, amount) {
            funding = id;
        }
    }
    let utxos = poll("a confirmed UTXO", wait_secs(3600), 60, || {
        let u = confirmed(&api);
        (!u.is_empty()).then_some(u)
    });
    let best = utxos
        .iter()
        .max_by_key(|u| u["value"].as_u64().unwrap())
        .unwrap();
    if funding == "existing" {
        funding = best["txid"].as_str().unwrap().to_string();
    }
    let prev = utxo(
        best["txid"].as_str().unwrap(),
        best["vout"].as_u64().unwrap() as u32,
        best["value"].as_u64().unwrap(),
        script.clone(),
    );
    let back = script_for_address("tb", &return_address(fund_net));
    let rate = get_json(&format!("{api}/v1/fees/recommended"))["halfHourFee"]
        .as_u64()
        .unwrap_or(2)
        .max(2);
    let fee = rate * 115;
    assert!(prev.value > fee + 330, "UTXO too small for the fee");
    let tx = btc_spend(prev, back, fee, kind);
    let sighash = tx.sighashes().unwrap()[0];
    let signed = match kind {
        SpendKind::P2wpkh => {
            let sig = ecdsa.sign_p2wpkh(&tx, &mut rng).remove(0).signature;
            let pk = compressed(ecdsa.public_key());
            VerifyingKey::from_sec1_bytes(&pk)
                .unwrap()
                .verify_prehash(&sighash, &sig)
                .unwrap();
            let mut item = der(&sig.r().to_bytes().into(), &sig.s().to_bytes().into());
            item.push(1);
            btc_signed(&tx, &[vec![item, pk.to_vec()]])
        }
        _ => {
            let mut committee = Bip340Committee::new(seed, &mut rng);
            let (sig, message) =
                committee.sign_variant(SpendVariant::bitcoin(&tx).unwrap(), &mut rng);
            assert_eq!(message, sighash.to_vec());
            k256::schnorr::VerifyingKey::from_bytes(&script[2..])
                .unwrap()
                .verify_raw(
                    &sighash,
                    &k256::schnorr::Signature::try_from(&sig[..]).unwrap(),
                )
                .unwrap();
            btc_signed(&tx, &[vec![sig.to_vec()]])
        }
    };
    let txid = hex(&btc_txid(&tx));
    assert_eq!(get(&format!("{api}/block-height/0")).trim(), genesis);
    let sent = post(&format!("{api}/tx"), "text/plain", &hex(&signed));
    assert_eq!(sent.trim(), txid, "broadcast reply");
    poll("spend confirmation", wait_secs(3600), 60, || {
        (get_json(&format!("{api}/tx/{txid}/status"))["confirmed"].as_bool() == Some(true))
            .then_some(())
    });
    record(Row {
        network: &format!("Bitcoin {net}"),
        scheme,
        path,
        address: &address,
        funding: &funding,
        spend: &txid,
        explorer: format!("https://mempool.space/{net}/tx/{txid}"),
    });
}

// ---------------- Ethereum Sepolia ----------------

pub fn sepolia() {
    if !enabled() {
        return;
    }
    let chain = || hex_u128(&rpc(SEPOLIA_RPC, "eth_chainId", json!([]))) as u64;
    assert_eq!(chain(), SEPOLIA_CHAIN_ID);
    let committee = EcdsaCommittee::new(live_seed("sepolia"));
    let from = eth_address(committee.public_key());
    let address = eip55(&from);
    eprintln!("[sepolia] committee address {address}");
    let balance = || {
        hex_u128(&rpc(
            SEPOLIA_RPC,
            "eth_getBalance",
            json!([address, "latest"]),
        ))
    };
    let mut funding = "existing".to_string();
    if balance() == 0 {
        if let Some(id) = fund("sepolia", &address, 10_000_000_000_000_000) {
            funding = id;
        }
    }
    let have = poll("a Sepolia balance", wait_secs(1800), 15, || {
        let b = balance();
        (b > 0).then_some(b)
    });
    let nonce = hex_u128(&rpc(
        SEPOLIA_RPC,
        "eth_getTransactionCount",
        json!([address, "pending"]),
    )) as u64;
    let block = rpc(
        SEPOLIA_RPC,
        "eth_getBlockByNumber",
        json!(["latest", false]),
    );
    let base = hex_u128(&block["baseFeePerGas"]);
    let tip = hex_u128(&rpc(SEPOLIA_RPC, "eth_maxPriorityFeePerGas", json!([]))).max(1_000_000);
    let max_fee = 2 * base + tip;
    let cost = 21_000 * max_fee;
    assert!(have > cost, "balance below gas cost");
    let to: [u8; 20] = unhex(&return_address("sepolia")).try_into().unwrap();
    let tx = Eip1559Transaction {
        chain_id: SEPOLIA_CHAIN_ID,
        nonce,
        to,
        value: have - cost,
        gas_limit: 21_000,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: tip,
        anchor_height: 0,
    };
    let mut rng = fresh();
    let sig = committee.sign_hash(tx.sighash(), &mut rng);
    let parity = sig.recovery_id.is_y_odd();
    let key = VerifyingKey::recover_from_prehash(
        &tx.sighash(),
        &sig.signature,
        RecoveryId::new(parity, false),
    )
    .unwrap();
    assert_eq!(
        eth_address(k256::ProjectivePoint::from(*key.as_affine())),
        from
    );
    let raw = eth_signed(
        &tx,
        parity,
        &sig.signature.r().to_bytes().into(),
        &sig.signature.s().to_bytes().into(),
    );
    let hash = format!("0x{}", hex(&keccak(&raw)));
    assert_eq!(chain(), SEPOLIA_CHAIN_ID);
    let sent = rpc(
        SEPOLIA_RPC,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex(&raw))]),
    );
    assert_eq!(sent.as_str().unwrap(), hash);
    let receipt = poll("the Sepolia receipt", wait_secs(900), 10, || {
        let r = rpc(SEPOLIA_RPC, "eth_getTransactionReceipt", json!([hash]));
        (!r.is_null()).then_some(r)
    });
    assert_eq!(receipt["status"].as_str(), Some("0x1"));
    record(Row {
        network: "Ethereum Sepolia",
        scheme: "EIP-1559 ECDSA",
        path: "split ECDSA slots, no envelope",
        address: &address,
        funding: &funding,
        spend: &hash,
        explorer: format!("https://sepolia.etherscan.io/tx/{hash}"),
    });
}

// ---------------- Cardano preprod ----------------

pub fn cardano() {
    if !enabled() {
        return;
    }
    let magic = || {
        get_json(&format!("{KOIOS}/genesis"))[0]["networkmagic"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(magic(), "1", "preprod network magic");
    let seed = live_seed("preprod");
    let mut rng = fresh();
    let vk: [u8; 32] =
        Edwards::signature_point(Ed25519Committee::new(seed, &mut rng).output_key()).unwrap();
    let addr = ada_enterprise(&vk);
    let address = ada_bech32(&addr);
    eprintln!("[preprod] committee address {address}");
    let utxos = || -> Vec<Value> {
        post_json(
            &format!("{KOIOS}/address_utxos"),
            &json!({"_addresses": [address], "_extended": true}),
        )
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["asset_list"].as_array().is_none_or(|a| a.is_empty()))
        .cloned()
        .collect()
    };
    let mut funding = "existing".to_string();
    if utxos().is_empty() {
        if let Some(id) = fund("cardano-preprod", &address, 10_000_000) {
            funding = id;
        }
    }
    let inputs = poll("a preprod UTxO", wait_secs(1800), 20, || {
        let u = utxos();
        (!u.is_empty()).then_some(u)
    });
    if funding == "existing" {
        funding = inputs[0]["tx_hash"].as_str().unwrap().to_string();
    }
    let total: u64 = inputs
        .iter()
        .map(|u| u["value"].as_str().unwrap().parse::<u64>().unwrap())
        .sum();
    let params = get_json(&format!("{KOIOS}/cli_protocol_params"));
    let (a, b) = (
        params["txFeePerByte"].as_u64().unwrap(),
        params["txFeeFixed"].as_u64().unwrap(),
    );
    let slot = get_json(&format!("{KOIOS}/tip"))[0]["abs_slot"]
        .as_u64()
        .unwrap();
    let (hrp, back, _) = bech32_bytes_decode(&return_address("cardano-preprod")).unwrap();
    assert_eq!(hrp, "addr_test");
    assert_eq!(
        back[0] & 0x0f,
        0,
        "return address must be a testnet address"
    );
    let mut tx = AdaTx {
        inputs: inputs
            .iter()
            .map(|u| {
                (
                    unhex(u["tx_hash"].as_str().unwrap()).try_into().unwrap(),
                    u["tx_index"].as_u64().unwrap() as u32,
                )
            })
            .collect(),
        outputs: vec![(back.clone(), total)],
        fee: 0,
        ttl: slot + 3600,
    };
    // The signed size does not depend on the signature value.
    let size = tx.signed(&vk, &[0; 64]).len() as u64 + 8;
    tx.fee = a * size + b;
    tx.outputs[0].1 = total - tx.fee;
    assert!(tx.outputs[0].1 >= 1_000_000, "below min-UTxO");
    let id = tx.id();
    let mut committee = Ed25519Committee::new(seed, &mut rng);
    let (sig, message) = committee.sign_variant(
        SpendVariant {
            transaction: id.to_vec(),
            prevouts: vec![],
            destination: back,
        },
        &mut rng,
    );
    assert_eq!(message, id.to_vec());
    ed25519_dalek::VerifyingKey::from_bytes(&vk)
        .unwrap()
        .verify_strict(&id, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
    let signed = tx.signed(&vk, &sig);
    let file = std::env::temp_dir().join(format!("preprod-{}.cbor", hex(&id)));
    std::fs::write(&file, &signed).unwrap();
    assert_eq!(magic(), "1");
    let sent = post(
        &format!("{KOIOS}/submittx"),
        "application/cbor",
        &format!("@{}", file.display()),
    );
    let txid = hex(&id);
    assert!(sent.contains(&txid), "submit reply: {sent}");
    poll("preprod confirmation", wait_secs(1800), 20, || {
        let s = post_json(
            &format!("{KOIOS}/tx_status"),
            &json!({"_tx_hashes": [txid]}),
        );
        (s[0]["num_confirmations"].as_u64().unwrap_or(0) >= 1).then_some(())
    });
    record(Row {
        network: "Cardano preprod",
        scheme: "Ed25519 enterprise address, Shelley-format tx",
        path: "split envelope",
        address: &address,
        funding: &funding,
        spend: &txid,
        explorer: format!("https://preprod.cardanoscan.io/transaction/{txid}"),
    });
}

// ---------------- Solana devnet ----------------

pub fn solana() {
    if !enabled() {
        return;
    }
    let genesis = || {
        rpc(SOLANA_RPC, "getGenesisHash", json!([]))
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(genesis(), SOLANA_DEVNET_GENESIS);
    let seed = live_seed("devnet");
    let mut rng = fresh();
    let from: [u8; 32] =
        Edwards::signature_point(Ed25519Committee::new(seed, &mut rng).output_key()).unwrap();
    let address = base58(&from);
    eprintln!("[devnet] committee address {address}");
    let balance = || {
        rpc(
            SOLANA_RPC,
            "getBalance",
            json!([address, {"commitment": "finalized"}]),
        )["value"]
            .as_u64()
            .unwrap()
    };
    let mut funding = "existing".to_string();
    if balance() == 0 {
        if let Some(id) = fund("solana-devnet", &address, 100_000_000) {
            funding = id;
        } else {
            let id = rpc(SOLANA_RPC, "requestAirdrop", json!([address, 100_000_000]));
            funding = id.as_str().unwrap().to_string();
            eprintln!("[devnet] airdrop {funding}");
        }
    }
    let have = poll("a devnet balance", wait_secs(1800), 10, || {
        let b = balance();
        (b > 0).then_some(b)
    });
    let to: [u8; 32] = unbase58(&return_address("solana-devnet"))
        .unwrap()
        .try_into()
        .unwrap();
    // A blockhash lives about a minute: fetch, sign and send in one step.
    let mut committee = Ed25519Committee::new(seed, &mut rng);
    let blockhash: [u8; 32] = unbase58(
        rpc(
            SOLANA_RPC,
            "getLatestBlockhash",
            json!([{"commitment": "finalized"}]),
        )["value"]["blockhash"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let probe = sol_transfer_message(&from, &to, &blockhash, have);
    let fee = rpc(
        SOLANA_RPC,
        "getFeeForMessage",
        json!([base64(&probe), {"commitment": "finalized"}]),
    )["value"]
        .as_u64()
        .unwrap();
    // Sweep to zero so no rent-exempt remainder is required.
    let message = sol_transfer_message(&from, &to, &blockhash, have - fee);
    let (sig, signed_message) = committee.sign_variant(
        SpendVariant {
            transaction: message.clone(),
            prevouts: vec![],
            destination: to.to_vec(),
        },
        &mut rng,
    );
    assert_eq!(signed_message, message);
    ed25519_dalek::VerifyingKey::from_bytes(&from)
        .unwrap()
        .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
    let wire = base64(&sol_signed(&sig, &message));
    let sim = rpc(
        SOLANA_RPC,
        "simulateTransaction",
        json!([wire, {"encoding": "base64", "sigVerify": true, "commitment": "confirmed"}]),
    );
    assert!(sim["value"]["err"].is_null(), "simulation: {sim}");
    assert_eq!(genesis(), SOLANA_DEVNET_GENESIS);
    let txid = base58(&sig);
    let sent = rpc(
        SOLANA_RPC,
        "sendTransaction",
        json!([wire, {"encoding": "base64"}]),
    );
    assert_eq!(sent.as_str().unwrap(), txid);
    poll("devnet finalization", wait_secs(600), 5, || {
        let s = rpc(
            SOLANA_RPC,
            "getSignatureStatuses",
            json!([[txid], {"searchTransactionHistory": true}]),
        );
        let st = &s["value"][0];
        if !st["err"].is_null() {
            panic!("transaction failed: {st}");
        }
        (st["confirmationStatus"].as_str() == Some("finalized")).then_some(())
    });
    record(Row {
        network: "Solana devnet",
        scheme: "Ed25519 system transfer",
        path: "split envelope",
        address: &address,
        funding: &funding,
        spend: &txid,
        explorer: format!("https://explorer.solana.com/tx/{txid}?cluster=devnet"),
    });
}

// ---------------- Midnight Preview ----------------

/// Run impl/testnet/midnight/mn.mjs with the installed Midnight SDK.
pub fn midnight_node(args: &[&str]) -> String {
    let script = impl_dir().join("testnet/midnight/mn.mjs");
    let out = Command::new("node")
        .arg(script)
        .args(args)
        .output()
        .expect("node");
    assert!(
        out.status.success(),
        "mn.mjs {:?}: {}",
        args.first(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

pub fn midnight() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;
    if !enabled() {
        return;
    }
    let seed = live_seed("midnight");
    let mut rng = fresh();
    let vk = x_only(Bip340Committee::new(seed, &mut rng).output_key());
    let info: Value = serde_json::from_str(&midnight_node(&["address", &hex(&vk)])).unwrap();
    let address = info["address"].as_str().unwrap().to_string();
    eprintln!("[midnight preview] committee address {address}");
    let to = return_address("midnight-preview");
    // DUST and shielded wallets: test-local fee wallet seed, never printed.
    let wallet_seed = [live_seed("midnight-fee-a"), live_seed("midnight-fee-b")].concat();
    let mut child = Command::new("node")
        .arg(impl_dir().join("testnet/midnight/mn.mjs"))
        .arg("session")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node");
    let mut stdin = child.stdin.take().unwrap();
    let init = json!({
        "vk": hex(&vk),
        "walletSeed": hex(&wallet_seed),
        "returnAddress": to,
        "waitSecs": wait_secs(7200).as_secs(),
    });
    writeln!(stdin, "{init}").unwrap();
    let mut funding = "existing".to_string();
    let (mut fund_tries, mut fund_after) = (0u32, None::<Instant>);
    let mut registration = String::new();
    let mut spend = String::new();
    let mut signatures = 0;
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let event: Value = serde_json::from_str(&line.unwrap()).unwrap();
        eprintln!("[midnight preview] {event}");
        match event["event"].as_str().unwrap() {
            "identity" => assert_eq!(event["address"].as_str(), Some(address.as_str())),
            "need-funds" if funding == "existing" => {
                // Raw NIGHT units (6 decimals). More NIGHT generates the fee
                // DUST sooner; every unit is spent back to the funding wallet.
                let amount = std::env::var("TESTNET_MIDNIGHT_FUND")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(500_000_000u128);
                // The funding wallet is shared. A send fails when another send
                // from it spent the same DUST first (ledger error 196,
                // DustDoubleSpend). Retry on a later need-funds event: mn.mjs
                // re-emits it only while the committee balance is still zero,
                // and 180 s is enough for a send that landed despite a script
                // error to show, so such a send is not repeated.
                let Some(script) = tool("fund-midnight-preview") else {
                    if fund_tries == 0 {
                        fund("midnight-preview", &address, amount);
                    }
                    fund_tries = 1;
                    continue;
                };
                if fund_tries >= 5 || fund_after.is_some_and(|t| Instant::now() < t) {
                    continue;
                }
                fund_tries += 1;
                match try_fund(&script, "midnight-preview", &address, amount) {
                    Ok(id) => funding = id,
                    Err(e) => {
                        eprintln!("[midnight preview] funding attempt {fund_tries}/5: {e}");
                        assert!(fund_tries < 5, "midnight funding failed 5 times");
                        fund_after = Some(Instant::now() + Duration::from_secs(180));
                    }
                }
            }
            "sign" => {
                // The committee signs SHA-256(data) with BIP340 (fresh slot).
                let data = unhex(event["data"].as_str().unwrap());
                let mut committee = Bip340Committee::new(seed, &mut rng);
                let sig = committee.sign_message(&sha256(&data), &mut rng);
                use k256::schnorr::signature::Verifier;
                k256::schnorr::VerifyingKey::from_bytes(&vk)
                    .unwrap()
                    .verify(
                        &data,
                        &k256::schnorr::Signature::try_from(&sig[..]).unwrap(),
                    )
                    .unwrap();
                signatures += 1;
                writeln!(stdin, "{}", json!({"sig": hex(&sig)})).unwrap();
            }
            "submitted" => {
                // Prefer the 64-hex hash the explorer uses; fall back to the
                // segment identifier when the indexer did not answer.
                let id = event["hash"]
                    .as_str()
                    .or(event["txId"].as_str())
                    .unwrap()
                    .to_string();
                match event["kind"].as_str().unwrap() {
                    "dust-registration" => registration = id,
                    _ => spend = id,
                }
            }
            "done" => break,
            _ => {}
        }
    }
    assert!(child.wait().unwrap().success(), "mn.mjs session failed");
    assert!(!spend.is_empty() && signatures > 0);
    if !registration.is_empty() {
        record(Row {
            network: "Midnight Preview",
            scheme: "DUST registration of the committee NIGHT, BIP340",
            path: "split Schnorr slots, no envelope",
            address: &address,
            funding: &funding,
            spend: &registration,
            explorer: format!("https://midnight-preview.subscan.io/tx/{registration}"),
        });
    }
    record(Row {
        network: "Midnight Preview",
        scheme: "unshielded NIGHT transfer, BIP340 over SHA-256(signatureData)",
        path: "split Schnorr slots, no envelope",
        address: &address,
        funding: &funding,
        spend: &spend,
        explorer: format!("https://midnight-preview.subscan.io/tx/{spend}"),
    });
}

/// Print every committee address (public data) so the owner can fund them.
pub fn addresses() {
    if !enabled() {
        return;
    }
    let mut rng = fresh();
    let p2wpkh = p2wpkh_script(EcdsaCommittee::new(live_seed("btc-p2wpkh")).public_key());
    let p2tr = p2tr_script(Bip340Committee::new(live_seed("btc-p2tr"), &mut rng).output_key());
    let eth = eip55(&eth_address(
        EcdsaCommittee::new(live_seed("sepolia")).public_key(),
    ));
    let ada: [u8; 32] = Edwards::signature_point(
        Ed25519Committee::new(live_seed("preprod"), &mut rng).output_key(),
    )
    .unwrap();
    let sol: [u8; 32] =
        Edwards::signature_point(Ed25519Committee::new(live_seed("devnet"), &mut rng).output_key())
            .unwrap();
    let mn = x_only(Bip340Committee::new(live_seed("midnight"), &mut rng).output_key());
    // Create the Midnight fee-wallet seeds too, so keys.local is complete.
    live_seed("midnight-fee-a");
    live_seed("midnight-fee-b");
    let mn: Value = serde_json::from_str(&midnight_node(&["address", &hex(&mn)])).unwrap();
    println!("bitcoin P2WPKH:   {}", btc_address("tb", &p2wpkh));
    println!("bitcoin P2TR:     {}", btc_address("tb", &p2tr));
    println!("sepolia:          {eth}");
    println!("cardano preprod:  {}", ada_bech32(&ada_enterprise(&ada)));
    println!("solana devnet:    {}", base58(&sol));
    println!("midnight preview: {}", mn["address"].as_str().unwrap());
}
