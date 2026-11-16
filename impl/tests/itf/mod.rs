//! Minimal loader for the ITF traces that `quint run --mbt --out-itf` writes for
//! `formal/quint/conformance/linedealing_mbt.qnt`. It decodes the model state
//! variables and the lagged projection `proj` into plain Rust values.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub type Int = i64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Post {
    pub kind: String,
    pub epoch: Int,
    pub node: Int,
    pub mid: Int,
    pub mode: String,
    pub t_profile: String,
    pub rot_policy: String,
    pub nb: Int,
    pub exp: Int,
    pub bad_nodes: BTreeSet<Int>,
    pub g: Int,
    pub a: Int,
    pub h: Int,
    pub dg: Int,
    pub variant: Int,
    pub dealers: BTreeSet<Int>,
    pub gens: BTreeSet<Int>,
    pub target_dealer: Int,
    pub bheight: Int,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub height: Int,
    pub trigger_ok: bool,
    pub market_fee: Int,
    pub tx_kind: String,
    pub tx_gen: Int,
    pub tx_val: Int,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelNode {
    pub chain_tip: Int,
    pub ledger: BTreeMap<Int, Int>,
    pub abstained: BTreeSet<Int>,
    pub erased: BTreeSet<Int>,
    pub builder_impl: Int,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttProj {
    pub done: bool,
    pub h: Int,
    pub failed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenProj {
    pub active: Int,
    pub in_flight: bool,
    pub lock_or_rel: bool,
    pub lock_dg: Int,
    pub lock_a: Int,
    pub att: BTreeMap<(Int, Int), AttProj>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proj {
    pub valid: bool,
    pub bound: bool,
    pub status: String,
    pub armed: bool,
    pub rotated: bool,
    pub handover: bool,
    pub q: BTreeSet<Int>,
    pub gens: BTreeMap<Int, GenProj>,
}

#[derive(Clone, Debug)]
pub struct State {
    pub byz1: BTreeSet<Int>,
    pub byz2: BTreeSet<Int>,
    pub board_height: Int,
    pub board: Vec<Post>,
    pub chain: Vec<Block>,
    pub nodes1: BTreeMap<Int, ModelNode>,
    pub nodes2: BTreeMap<Int, ModelNode>,
    pub action: String,
    pub proj: Option<Proj>,
}

#[derive(Clone, Debug)]
pub struct Trace {
    pub states: Vec<State>,
}

fn int(v: &Value) -> Int {
    match v {
        Value::Object(o) if o.contains_key("#bigint") => o["#bigint"]
            .as_str()
            .expect("bigint string")
            .parse()
            .expect("bigint value"),
        Value::Number(n) => n.as_i64().expect("integer"),
        other => panic!("not an ITF integer: {other}"),
    }
}

fn boolean(v: &Value) -> bool {
    v.as_bool().expect("ITF boolean")
}

fn tag(v: &Value) -> String {
    v["tag"].as_str().expect("ITF variant tag").to_string()
}

fn set(v: &Value) -> Vec<&Value> {
    v["#set"].as_array().expect("ITF set").iter().collect()
}

fn int_set(v: &Value) -> BTreeSet<Int> {
    set(v).into_iter().map(int).collect()
}

fn map(v: &Value) -> Vec<(&Value, &Value)> {
    v["#map"]
        .as_array()
        .expect("ITF map")
        .iter()
        .map(|kv| {
            let kv = kv.as_array().expect("ITF map entry");
            (&kv[0], &kv[1])
        })
        .collect()
}

fn tuple(v: &Value) -> Vec<&Value> {
    v["#tup"].as_array().expect("ITF tuple").iter().collect()
}

fn post(v: &Value) -> Post {
    Post {
        kind: tag(&v["kind"]),
        epoch: int(&v["epoch"]),
        node: int(&v["node"]),
        mid: int(&v["mid"]),
        mode: tag(&v["mode"]),
        t_profile: tag(&v["tProfile"]),
        rot_policy: tag(&v["rotPolicy"]),
        nb: int(&v["nb"]),
        exp: int(&v["exp"]),
        bad_nodes: int_set(&v["badNodes"]),
        g: int(&v["g"]),
        a: int(&v["a"]),
        h: int(&v["h"]),
        dg: int(&v["dg"]),
        variant: int(&v["variant"]),
        dealers: int_set(&v["dealers"]),
        gens: int_set(&v["gens"]),
        target_dealer: int(&v["targetDealer"]),
        bheight: int(&v["bheight"]),
    }
}

fn block(v: &Value) -> Block {
    Block {
        height: int(&v["height"]),
        trigger_ok: boolean(&v["triggerOk"]),
        market_fee: int(&v["marketFee"]),
        tx_kind: tag(&v["txKind"]),
        tx_gen: int(&v["txGen"]),
        tx_val: int(&v["txVal"]),
    }
}

fn node(v: &Value) -> ModelNode {
    ModelNode {
        chain_tip: int(&v["chainTip"]),
        ledger: map(&v["ledger"])
            .into_iter()
            .map(|(k, x)| (int(k), int(x)))
            .collect(),
        abstained: int_set(&v["abstained"]),
        erased: int_set(&v["erased"]),
        builder_impl: int(&v["builderImpl"]),
    }
}

fn nodes(v: &Value) -> BTreeMap<Int, ModelNode> {
    map(v).into_iter().map(|(k, x)| (int(k), node(x))).collect()
}

fn att(v: &Value) -> AttProj {
    AttProj {
        done: boolean(&v["done"]),
        h: int(&v["h"]),
        failed: boolean(&v["failed"]),
    }
}

fn gen_proj(v: &Value) -> GenProj {
    GenProj {
        active: int(&v["active"]),
        in_flight: boolean(&v["inFlight"]),
        lock_or_rel: boolean(&v["lockOrRel"]),
        lock_dg: int(&v["lockDg"]),
        lock_a: int(&v["lockA"]),
        att: map(&v["att"])
            .into_iter()
            .map(|(k, x)| {
                let t = tuple(k);
                ((int(t[0]), int(t[1])), att(x))
            })
            .collect(),
    }
}

fn proj(v: &Value) -> Proj {
    Proj {
        valid: boolean(&v["valid"]),
        bound: boolean(&v["bound"]),
        status: tag(&v["status"]),
        armed: boolean(&v["armed"]),
        rotated: boolean(&v["rotated"]),
        handover: boolean(&v["handover"]),
        q: int_set(&v["q"]),
        gens: map(&v["gens"])
            .into_iter()
            .map(|(k, x)| (int(k), gen_proj(x)))
            .collect(),
    }
}

/// Finds a state field by the last `::` segment of its qualified name.
fn field<'a>(state: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a Value> {
    state
        .iter()
        .find(|(k, _)| k.rsplit("::").next() == Some(name) && !k.starts_with("mbt::"))
        .map(|(_, v)| v)
}

pub fn load(path: &Path) -> Trace {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let states = doc["states"]
        .as_array()
        .expect("ITF states")
        .iter()
        .map(|s| {
            let s = s.as_object().expect("ITF state");
            let get = |n: &str| field(s, n).unwrap_or_else(|| panic!("missing {n}"));
            let p = field(s, "proj").map(proj).filter(|p| p.valid);
            State {
                byz1: int_set(get("byz1")),
                byz2: int_set(get("byz2")),
                board_height: int(get("boardHeight")),
                board: get("board")
                    .as_array()
                    .expect("board")
                    .iter()
                    .map(post)
                    .collect(),
                chain: get("chainBlocks")
                    .as_array()
                    .expect("chain")
                    .iter()
                    .map(block)
                    .collect(),
                nodes1: nodes(get("nodes1")),
                nodes2: nodes(get("nodes2")),
                action: s
                    .get("mbt::actionTaken")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                proj: p,
            }
        })
        .collect();
    Trace { states }
}
