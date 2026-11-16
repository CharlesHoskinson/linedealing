//! Deterministic payment builders for SCHEME.md section 4.
//! The supplied state is a finalized snapshot, not an RPC client or chain validator.

use crate::wire::{Intent, Output};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::BTreeSet;

pub const ALL: u128 = u128::MAX;
pub const RBF_SEQUENCE: u32 = 0xffff_fffd;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    InvalidIntent,
    Unsupported,
    PinSpent,
    NoncePending,
    Unconfirmed,
    InsufficientFunds,
    FeeCeiling,
    TooManyInputs,
    TooEarly,
    InvalidPrevious,
    Overflow,
    NoVariant,
}
pub type BuildResult<T> = Result<T, BuildError>;

/// Exact base units per virtual byte (or account tip per gas).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRate {
    pub numerator: u64,
    pub denominator: u64,
}
impl FeeRate {
    pub const fn integer(value: u64) -> Self {
        Self {
            numerator: value,
            denominator: 1,
        }
    }
}

/// txid bytes use display order; Bitcoin serialization reverses them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub confirmations: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendKind {
    P2pkhCompressed,
    P2pkhUncompressed,
    P2wpkh,
    P2tr,
}
#[derive(Clone, Debug)]
pub struct UtxoPolicy {
    pub owner_script: Vec<u8>,
    pub spend_kind: SpendKind,
    pub max_inputs: u16,
    pub late_inputs: bool,
    pub dust_threshold: u64,
    pub replacement_increment: FeeRate,
}
#[derive(Clone, Debug)]
pub struct UtxoState {
    pub height: u64,
    pub utxos: Vec<Utxo>,
    pub block_median_rates: [FeeRate; 6],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoTransaction {
    pub inputs: Vec<Utxo>,
    pub outputs: Vec<Output>,
    pub fee: u64,
    /// Conservative signed size; ECDSA uses a maximum-length low-s signature.
    pub vsize: u64,
    /// Exact size recomputed from the authenticated reconstructed signature.
    /// Without it, replacements use the smallest possible signed size.
    pub signed_vsize: Option<u64>,
    pub anchor_height: u64,
    pub lock_time: u32,
    pub spend_kind: SpendKind,
}
#[derive(Clone, Debug)]
pub struct AccountState {
    pub height: u64,
    pub nonce: u64,
    pub balance: u128,
    pub base_fee: u128,
    pub block_median_tips: [FeeRate; 6],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub anchor_height: u64,
}

fn add(a: u128, b: u128) -> BuildResult<u128> {
    a.checked_add(b).ok_or(BuildError::Overflow)
}
fn mul(a: u128, b: u128) -> BuildResult<u128> {
    a.checked_mul(b).ok_or(BuildError::Overflow)
}
fn ceil_div(a: u128, b: u128) -> BuildResult<u128> {
    if b == 0 {
        return Err(BuildError::InvalidIntent);
    }
    add(a / b, u128::from(!a.is_multiple_of(b)))
}
fn u64_checked(n: u128) -> BuildResult<u64> {
    n.try_into().map_err(|_| BuildError::Overflow)
}
impl FeeRate {
    pub fn fee(self, size: u64) -> BuildResult<u64> {
        u64_checked(ceil_div(
            mul(self.numerator as u128, size as u128)?,
            self.denominator as u128,
        )?)
    }
}

/// Fee-rule id 0: arithmetic mean of the middle two of six block medians.
/// Rates are supplied in base units; this fixes the even-median convention.
pub fn fee_rule(mut rates: [FeeRate; 6]) -> BuildResult<FeeRate> {
    if rates.iter().any(|r| r.denominator == 0) {
        return Err(BuildError::InvalidIntent);
    }
    rates.sort_by(|a, b| {
        ((a.numerator as u128) * (b.denominator as u128))
            .cmp(&((b.numerator as u128) * (a.denominator as u128)))
    });
    let (a, b) = (rates[2], rates[3]);
    let mut n = add(
        mul(a.numerator as u128, b.denominator as u128)?,
        mul(b.numerator as u128, a.denominator as u128)?,
    )?;
    let mut d = mul(2, mul(a.denominator as u128, b.denominator as u128)?)?;
    let (mut x, mut y) = (n, d);
    while y != 0 {
        (x, y) = (y, x % y);
    }
    n /= x;
    d /= x;
    Ok(FeeRate {
        numerator: u64_checked(n)?,
        denominator: u64_checked(d)?,
    })
}
fn validate_intent(i: &Intent) -> BuildResult<()> {
    if !(1..=2).contains(&i.outputs.len())
        || i.outputs
            .iter()
            .any(|o| o.script.is_empty() || o.script.len() > 35)
        || i.outputs.iter().filter(|o| o.amount == ALL).count() > 1
        || i.allowed.len() > 7
        || i.change_to.len() > 35
        || i.grid_ratio[1] == 0
    {
        return Err(BuildError::InvalidIntent);
    }
    if i.fee_rule != 0 {
        return Err(BuildError::Unsupported);
    }
    Ok(())
}
fn outpoint(bytes: &[u8]) -> OutPoint {
    OutPoint {
        txid: bytes[..32].try_into().expect("fixed outpoint"),
        vout: u32::from_be_bytes(bytes[32..36].try_into().expect("fixed outpoint")),
    }
}
fn utxo_pin(i: &Intent) -> BuildResult<(OutPoint, u64)> {
    if i.pin[0] != 1 || i.pin[45..].iter().any(|b| *b != 0) {
        return Err(BuildError::InvalidIntent);
    }
    Ok((
        outpoint(&i.pin[1..37]),
        u64::from_be_bytes(i.pin[37..45].try_into().expect("fixed pin")),
    ))
}
fn account_pin(i: &Intent) -> BuildResult<u64> {
    if i.pin[0] != 2
        || i.pin[9..].iter().any(|b| *b != 0)
        || !i.allowed.is_empty()
        || i.outputs.len() != 1
        || i.outputs[0].script.len() != 20
    {
        return Err(BuildError::InvalidIntent);
    }
    Ok(u64::from_be_bytes(
        i.pin[1..9].try_into().expect("fixed pin"),
    ))
}
fn generation(
    g: u16,
    count: usize,
    height: u64,
    previous: Option<u64>,
    delay: u16,
) -> BuildResult<()> {
    if g == 0 || count != usize::from(g - 1) {
        return Err(BuildError::InvalidPrevious);
    }
    if let Some(h) = previous {
        if height < h.checked_add(delay as u64).ok_or(BuildError::Overflow)? {
            return Err(BuildError::TooEarly);
        }
    }
    Ok(())
}
fn script_matches(script: &[u8], kind: SpendKind) -> bool {
    match kind {
        SpendKind::P2wpkh => script.len() == 22 && script[..2] == [0, 20],
        SpendKind::P2tr => script.len() == 34 && script[..2] == [0x51, 32],
        SpendKind::P2pkhCompressed | SpendKind::P2pkhUncompressed => {
            script.len() == 25 && script[..3] == [0x76, 0xa9, 20] && script[23..] == [0x88, 0xac]
        }
    }
}
fn eligible_coins(i: &Intent, s: &UtxoState, p: &UtxoPolicy) -> BuildResult<Vec<Utxo>> {
    validate_intent(i)?;
    if p.max_inputs == 0
        || !script_matches(&p.owner_script, p.spend_kind)
        || p.replacement_increment.denominator == 0
    {
        return Err(BuildError::InvalidIntent);
    }
    let (pin, value) = utxo_pin(i)?;
    let mut seen = BTreeSet::new();
    if s.utxos.iter().any(|u| !seen.insert(u.outpoint)) {
        return Err(BuildError::InvalidIntent);
    }
    let coin = s
        .utxos
        .iter()
        .find(|u| u.outpoint == pin)
        .ok_or(BuildError::PinSpent)?;
    if coin.value != value || coin.script_pubkey != p.owner_script {
        return Err(BuildError::InvalidIntent);
    }
    if coin.confirmations < u32::from(i.min_conf) {
        return Err(BuildError::Unconfirmed);
    }
    let allowed: BTreeSet<_> = i.allowed.iter().map(|o| outpoint(o)).collect();
    if allowed.len() != i.allowed.len() || allowed.contains(&pin) {
        return Err(BuildError::InvalidIntent);
    }
    let mut other: Vec<_> = s
        .utxos
        .iter()
        .filter(|u| {
            u.outpoint != pin
                && u.script_pubkey == p.owner_script
                && u.confirmations >= u32::from(i.min_conf)
                && (p.late_inputs || allowed.contains(&u.outpoint))
        })
        .cloned()
        .collect();
    other.sort_by(|a, b| b.value.cmp(&a.value).then(a.outpoint.cmp(&b.outpoint)));
    let mut coins = vec![coin.clone()];
    coins.extend(other);
    Ok(coins)
}
fn compact_size(n: usize) -> u64 {
    match n {
        0..=252 => 1,
        253..=65535 => 3,
        65536..=0xffff_ffff => 5,
        _ => 9,
    }
}
fn vsize(kind: SpendKind, inputs: usize, outputs: &[Output]) -> BuildResult<u64> {
    signed_size_bound(kind, inputs, outputs, false)
}
fn signed_size_bound(
    kind: SpendKind,
    inputs: usize,
    outputs: &[Output],
    minimum: bool,
) -> BuildResult<u64> {
    let output_bytes = outputs.iter().try_fold(0u64, |n, o| {
        n.checked_add(8 + compact_size(o.script.len()) + o.script.len() as u64)
            .ok_or(BuildError::Overflow)
    })?;
    let base = 4 + compact_size(inputs) + compact_size(outputs.len()) + output_bytes + 4;
    let n = inputs as u64;
    // Strict DER has at least eight bytes (one-byte nonzero r and s), plus
    // one sighash byte. Maximum low-s DER plus sighash has 72 bytes.
    match kind {
        SpendKind::P2pkhCompressed => Ok(base + if minimum { 85 } else { 148 } * n),
        SpendKind::P2pkhUncompressed => Ok(base + if minimum { 117 } else { 180 } * n),
        SpendKind::P2wpkh => u64_checked(ceil_div(
            (base + 41 * n) as u128 * 4 + 2 + if minimum { 45 } else { 108 } * n as u128,
            4,
        )?),
        SpendKind::P2tr => u64_checked(ceil_div(
            (base + 41 * n) as u128 * 4 + 2 + 66 * n as u128,
            4,
        )?),
    }
}
fn required_fee(
    rate: FeeRate,
    size: u64,
    increment: FeeRate,
    prev: &[UtxoTransaction],
) -> BuildResult<u64> {
    let mut fee = rate.fee(size)?;
    for old in prev {
        let lower = signed_size_bound(old.spend_kind, old.inputs.len(), &old.outputs, true)?;
        let upper = vsize(old.spend_kind, old.inputs.len(), &old.outputs)?;
        if old.inputs.is_empty() || old.vsize != upper {
            return Err(BuildError::InvalidPrevious);
        }
        let previous_size = old.signed_vsize.unwrap_or(lower);
        if !(lower..=upper).contains(&previous_size) {
            return Err(BuildError::InvalidPrevious);
        }
        fee = fee.max(
            old.fee
                .checked_add(increment.fee(size)?)
                .ok_or(BuildError::Overflow)?,
        );
        fee = fee.max(u64_checked(add(
            mul(old.fee as u128, size as u128)? / previous_size as u128,
            1,
        )?)?);
    }
    Ok(fee)
}
fn resolve_utxo(
    i: &Intent,
    p: &UtxoPolicy,
    mut inputs: Vec<Utxo>,
    height: u64,
    rate: FeeRate,
    prev: &[UtxoTransaction],
    exact_fee: Option<u64>,
) -> BuildResult<UtxoTransaction> {
    let total = inputs.iter().try_fold(0u64, |sum, u| {
        sum.checked_add(u.value).ok_or(BuildError::Overflow)
    })?;
    let fixed = u64_checked(
        i.outputs
            .iter()
            .filter(|o| o.amount != ALL)
            .try_fold(0u128, |sum, o| add(sum, o.amount))?,
    )?;
    let mut outputs = i.outputs.clone();
    let sweep = outputs.iter().position(|o| o.amount == ALL);
    if sweep.is_none() {
        if i.change_to.is_empty() {
            return Err(BuildError::InvalidIntent);
        }
        outputs.push(Output {
            script: i.change_to.clone(),
            amount: 0,
        });
    }
    let mut size = vsize(p.spend_kind, inputs.len(), &outputs)?;
    let fee = exact_fee.unwrap_or(required_fee(rate, size, p.replacement_increment, prev)?);
    let available = total
        .checked_sub(fixed)
        .ok_or(BuildError::InsufficientFunds)?;
    if let Some(index) = sweep {
        let amount = available
            .checked_sub(fee)
            .ok_or(BuildError::InsufficientFunds)?;
        if amount < p.dust_threshold {
            return Err(BuildError::InsufficientFunds);
        }
        outputs[index].amount = amount as u128;
    } else if available >= fee && available - fee >= p.dust_threshold && available != fee {
        outputs.last_mut().expect("change").amount = (available - fee) as u128;
    } else {
        outputs.pop();
        size = vsize(p.spend_kind, inputs.len(), &outputs)?;
        if available < exact_fee.unwrap_or(required_fee(rate, size, p.replacement_increment, prev)?)
        {
            return Err(BuildError::InsufficientFunds);
        }
    }
    let paid = u64_checked(
        outputs
            .iter()
            .try_fold(0u128, |sum, o| add(sum, o.amount))?,
    )?;
    let fee = total
        .checked_sub(paid)
        .ok_or(BuildError::InsufficientFunds)?;
    if fee as u128 > i.fee_ceiling {
        return Err(BuildError::FeeCeiling);
    }
    if exact_fee.is_some_and(|f| f != fee) {
        return Err(BuildError::InvalidIntent);
    }
    // Block-height locktimes must remain below the timestamp interpretation threshold.
    if height >= 500_000_000 {
        return Err(BuildError::Unsupported);
    }
    inputs.sort_by_key(|u| u.outpoint);
    Ok(UtxoTransaction {
        inputs,
        outputs,
        fee,
        vsize: size,
        signed_vsize: None,
        anchor_height: height,
        lock_time: height as u32,
        spend_kind: p.spend_kind,
    })
}

/// Recompute `prev` locally from the board-cut anchors; do not accept peer-supplied history.
pub fn build_utxo(
    i: &Intent,
    s: &UtxoState,
    p: &UtxoPolicy,
    g: u16,
    prev: &[UtxoTransaction],
) -> BuildResult<UtxoTransaction> {
    generation(
        g,
        prev.len(),
        s.height,
        prev.last().map(|t| t.anchor_height),
        i.bump_delay,
    )?;
    let coins = eligible_coins(i, s, p)?;
    let (pin, _) = utxo_pin(i)?;
    if prev
        .iter()
        .any(|t| !t.inputs.iter().any(|u| u.outpoint == pin) || t.spend_kind != p.spend_kind)
    {
        return Err(BuildError::InvalidPrevious);
    }
    let rate = fee_rule(s.block_median_rates)?;
    if i.outputs.iter().any(|o| o.amount == ALL) {
        if coins.len() > p.max_inputs as usize {
            return Err(BuildError::TooManyInputs);
        }
        return resolve_utxo(i, p, coins, s.height, rate, prev, None);
    }
    let mut selected = Vec::new();
    for coin in coins {
        if selected.len() == p.max_inputs as usize {
            return Err(BuildError::TooManyInputs);
        }
        selected.push(coin);
        match resolve_utxo(i, p, selected.clone(), s.height, rate, prev, None) {
            Err(BuildError::InsufficientFunds) => continue,
            result => return result,
        }
    }
    Err(BuildError::InsufficientFunds)
}

fn bump(value: u128) -> BuildResult<u128> {
    ceil_div(mul(value, 9)?, 8)
}
/// Native EOA payment only: fixed 21,000 gas, empty data, empty access list.
/// The caller must establish that the recipient does not require contract execution.
pub fn build_eip1559(
    i: &Intent,
    s: &AccountState,
    chain_id: u64,
    g: u16,
    prev: &[Eip1559Transaction],
) -> BuildResult<Eip1559Transaction> {
    validate_intent(i)?;
    let nonce = account_pin(i)?;
    if s.nonce < nonce {
        return Err(BuildError::NoncePending);
    }
    if s.nonce > nonce {
        return Err(BuildError::PinSpent);
    }
    generation(
        g,
        prev.len(),
        s.height,
        prev.last().map(|t| t.anchor_height),
        i.bump_delay,
    )?;
    if prev.iter().any(|t| {
        t.nonce != nonce || t.chain_id != chain_id || t.to.as_slice() != i.outputs[0].script
    }) {
        return Err(BuildError::InvalidPrevious);
    }
    let mut tip = fee_rule(s.block_median_tips)?.fee(1)? as u128;
    let mut max_fee = add(mul(2, s.base_fee)?, tip)?;
    for t in prev {
        tip = tip.max(bump(t.max_priority_fee_per_gas)?);
        max_fee = max_fee.max(bump(t.max_fee_per_gas)?);
    }
    max_fee = max_fee.max(tip);
    account_transaction(i, nonce, chain_id, s.balance, s.height, max_fee, tip)
}
fn account_transaction(
    i: &Intent,
    nonce: u64,
    chain_id: u64,
    balance: u128,
    height: u64,
    max_fee: u128,
    tip: u128,
) -> BuildResult<Eip1559Transaction> {
    let cost = mul(21_000, max_fee)?;
    if cost > i.fee_ceiling {
        return Err(BuildError::FeeCeiling);
    }
    let value = if i.outputs[0].amount == ALL {
        balance
            .checked_sub(cost)
            .ok_or(BuildError::InsufficientFunds)?
    } else {
        i.outputs[0].amount
    };
    if add(value, cost)? > balance {
        return Err(BuildError::InsufficientFunds);
    }
    Ok(Eip1559Transaction {
        chain_id,
        nonce,
        to: i.outputs[0]
            .script
            .as_slice()
            .try_into()
            .map_err(|_| BuildError::InvalidIntent)?,
        value,
        gas_limit: 21_000,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: tip,
        anchor_height: height,
    })
}

/// Immutable outpoint metadata resolved by the owner when sealing. Values and
/// scripts for `allowed` outpoints are not carried in the wire intent; verify
/// this metadata against the target chain before accepting a sealed dealing.
#[derive(Clone, Debug)]
pub struct SealedUtxoIntent {
    pub intent: Intent,
    pub inputs: Vec<Utxo>,
    pub policy: UtxoPolicy,
}
fn sealed_variants(s: &SealedUtxoIntent, k: u16) -> BuildResult<Vec<UtxoTransaction>> {
    let i = &s.intent;
    if k == 0 || (k > 1 && i.grid_ratio[0] <= i.grid_ratio[1]) {
        return Err(BuildError::InvalidIntent);
    }
    let mut policy = s.policy.clone();
    policy.late_inputs = false;
    let snapshot = UtxoState {
        height: 0,
        utxos: s.inputs.clone(),
        block_median_rates: [FeeRate::integer(0); 6],
    };
    let inputs = eligible_coins(i, &snapshot, &policy)?;
    if inputs.len() != 1 + i.allowed.len() || inputs.len() != s.inputs.len() {
        return Err(BuildError::InvalidIntent);
    }
    if inputs.len() > policy.max_inputs as usize {
        return Err(BuildError::TooManyInputs);
    }
    let mut fees = vec![0; k as usize];
    fees[k as usize - 1] = u64_checked(i.fee_ceiling)?;
    for j in (0..k as usize - 1).rev() {
        fees[j] = u64_checked(
            mul(fees[j + 1] as u128, i.grid_ratio[1] as u128)? / i.grid_ratio[0] as u128,
        )?;
    }
    let mut variants: Vec<UtxoTransaction> = Vec::with_capacity(k as usize);
    for fee in fees {
        let tx = resolve_utxo(
            i,
            &policy,
            inputs.clone(),
            0,
            FeeRate::integer(0),
            &[],
            Some(fee),
        )?;
        if let Some(previous) = variants.last() {
            if tx.fee
                < required_fee(
                    FeeRate::integer(0),
                    tx.vsize,
                    policy.replacement_increment,
                    std::slice::from_ref(previous),
                )?
            {
                return Err(BuildError::InvalidIntent);
            }
        }
        variants.push(tx);
    }
    Ok(variants)
}
/// One-based variant index; locktime is fixed at zero before the owner signs.
pub fn variant_utxo(s: &SealedUtxoIntent, j: u16, k: u16) -> BuildResult<UtxoTransaction> {
    if j == 0 || j > k {
        return Err(BuildError::NoVariant);
    }
    Ok(sealed_variants(s, k)?.remove(j as usize - 1))
}
/// Select the least eligible one-based index above `previous` (zero initially).
/// The board does not check generation eligibility (trigger, the delay Δ, pin
/// unspent): each node checks it at its OBS target height before it posts OBS.
pub fn select_utxo(
    sealed: &SealedUtxoIntent,
    s: &UtxoState,
    k: u16,
    previous: u16,
) -> BuildResult<(u16, UtxoTransaction)> {
    let variants = sealed_variants(sealed, k)?;
    let mut policy = sealed.policy.clone();
    policy.late_inputs = false;
    let current = eligible_coins(&sealed.intent, s, &policy)?;
    for fixed in &sealed.inputs {
        let live = current
            .iter()
            .find(|u| u.outpoint == fixed.outpoint)
            .ok_or(BuildError::Unconfirmed)?;
        if live.value != fixed.value || live.script_pubkey != fixed.script_pubkey {
            return Err(BuildError::InvalidIntent);
        }
    }
    let rate = fee_rule(s.block_median_rates)?;
    for (j, tx) in variants.into_iter().enumerate().skip(previous as usize) {
        if tx.fee >= rate.fee(tx.vsize)? {
            return Ok((j as u16 + 1, tx));
        }
    }
    Err(BuildError::NoVariant)
}
/// The sealed account profile has K=1. Both caps use floor(ceiling / 21,000).
/// `balance_at_seal` fixes the value of an ALL payment before signing.
pub fn variant_eip1559(
    i: &Intent,
    chain_id: u64,
    balance_at_seal: u128,
) -> BuildResult<Eip1559Transaction> {
    validate_intent(i)?;
    let nonce = account_pin(i)?;
    let cap = i.fee_ceiling / 21_000;
    account_transaction(i, nonce, chain_id, balance_at_seal, 0, cap, cap)
}
pub fn select_eip1559(
    i: &Intent,
    s: &AccountState,
    t: &Eip1559Transaction,
    previous: u16,
) -> BuildResult<u16> {
    validate_intent(i)?;
    let nonce = account_pin(i)?;
    if s.nonce < nonce {
        return Err(BuildError::NoncePending);
    }
    if s.nonce > nonce {
        return Err(BuildError::PinSpent);
    }
    if previous != 0 {
        return Err(BuildError::NoVariant);
    }
    let fee = mul(t.gas_limit as u128, t.max_fee_per_gas)?;
    if t.nonce != nonce
        || t.to.as_slice() != i.outputs[0].script
        || t.gas_limit != 21_000
        || t.max_fee_per_gas != i.fee_ceiling / 21_000
        || t.max_priority_fee_per_gas != t.max_fee_per_gas
        || (i.outputs[0].amount != ALL && t.value != i.outputs[0].amount)
    {
        return Err(BuildError::InvalidIntent);
    }
    let tip = fee_rule(s.block_median_tips)?.fee(1)? as u128;
    if add(s.base_fee, tip)? > t.max_fee_per_gas || tip > t.max_priority_fee_per_gas {
        return Err(BuildError::NoVariant);
    }
    if add(t.value, fee)? > s.balance {
        return Err(BuildError::InsufficientFunds);
    }
    Ok(1)
}

fn compact(n: usize, out: &mut Vec<u8>) {
    match n {
        0..=252 => out.push(n as u8),
        253..=65535 => {
            out.push(253);
            out.extend((n as u16).to_le_bytes());
        }
        65536..=0xffff_ffff => {
            out.push(254);
            out.extend((n as u32).to_le_bytes());
        }
        _ => {
            out.push(255);
            out.extend((n as u64).to_le_bytes());
        }
    }
}
fn script_bytes(script: &[u8], out: &mut Vec<u8>) {
    compact(script.len(), out);
    out.extend(script);
}
fn outpoint_bytes(o: OutPoint, out: &mut Vec<u8>) {
    out.extend(o.txid.iter().rev());
    out.extend(o.vout.to_le_bytes());
}
fn output_bytes(outputs: &[Output]) -> BuildResult<Vec<u8>> {
    let mut out = Vec::new();
    for o in outputs {
        out.extend(u64_checked(o.amount)?.to_le_bytes());
        script_bytes(&o.script, &mut out);
    }
    Ok(out)
}
fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

impl UtxoTransaction {
    // Shared production implementation; explicit version/sequences also permit
    // exact reference vectors without expanding the builder's version-2/RBF policy.
    fn segwit_sighash(
        &self,
        version: u32,
        input_sequences: &[u32],
        index: usize,
    ) -> BuildResult<[u8; 32]> {
        let input = self.inputs.get(index).ok_or(BuildError::InvalidIntent)?;
        if input_sequences.len() != self.inputs.len()
            || !script_matches(&input.script_pubkey, self.spend_kind)
        {
            return Err(BuildError::InvalidIntent);
        }
        let outputs = output_bytes(&self.outputs)?;
        let mut prevouts = Vec::new();
        let mut sequences = Vec::new();
        let mut amounts = Vec::new();
        let mut scripts = Vec::new();
        for (u, sequence) in self.inputs.iter().zip(input_sequences) {
            outpoint_bytes(u.outpoint, &mut prevouts);
            sequences.extend(sequence.to_le_bytes());
            amounts.extend(u.value.to_le_bytes());
            script_bytes(&u.script_pubkey, &mut scripts);
        }
        match self.spend_kind {
            SpendKind::P2wpkh => {
                let mut preimage = version.to_le_bytes().to_vec();
                preimage.extend(sha256d(&prevouts));
                preimage.extend(sha256d(&sequences));
                outpoint_bytes(input.outpoint, &mut preimage);
                preimage.extend([25, 0x76, 0xa9, 20]);
                preimage.extend(&input.script_pubkey[2..]);
                preimage.extend([0x88, 0xac]);
                preimage.extend(input.value.to_le_bytes());
                preimage.extend(input_sequences[index].to_le_bytes());
                preimage.extend(sha256d(&outputs));
                preimage.extend(self.lock_time.to_le_bytes());
                preimage.extend(1u32.to_le_bytes());
                Ok(sha256d(&preimage))
            }
            SpendKind::P2tr => {
                let tag = sha256(b"TapSighash");
                let mut preimage = Vec::new();
                preimage.extend(tag);
                preimage.extend(tag);
                preimage.extend([0, 0]); // epoch, DEFAULT hash type
                preimage.extend(version.to_le_bytes());
                preimage.extend(self.lock_time.to_le_bytes());
                for part in [&prevouts, &amounts, &scripts, &sequences, &outputs] {
                    preimage.extend(sha256(part));
                }
                preimage.push(0); // key path, no annex
                preimage.extend(
                    u32::try_from(index)
                        .map_err(|_| BuildError::Overflow)?
                        .to_le_bytes(),
                );
                Ok(sha256(&preimage))
            }
            _ => Err(BuildError::Unsupported),
        }
    }
    fn serialize(&self, script_index: Option<usize>) -> BuildResult<Vec<u8>> {
        let mut out = 2u32.to_le_bytes().to_vec();
        compact(self.inputs.len(), &mut out);
        for (index, u) in self.inputs.iter().enumerate() {
            outpoint_bytes(u.outpoint, &mut out);
            script_bytes(
                if script_index == Some(index) {
                    &u.script_pubkey
                } else {
                    &[]
                },
                &mut out,
            );
            out.extend(RBF_SEQUENCE.to_le_bytes());
        }
        compact(self.outputs.len(), &mut out);
        out.extend(output_bytes(&self.outputs)?);
        out.extend(self.lock_time.to_le_bytes());
        Ok(out)
    }
    /// Non-witness serialization with empty scriptSigs; not a broadcastable transaction.
    pub fn unsigned_bytes(&self) -> BuildResult<Vec<u8>> {
        self.serialize(None)
    }
    /// Legacy SIGHASH_ALL, BIP143 ALL, or BIP341 key-path DEFAULT, without annex.
    /// References: bitcoin/bips bip-0143.mediawiki and bip-0341.mediawiki.
    pub fn sighashes(&self) -> BuildResult<Vec<[u8; 32]>> {
        if self.inputs.is_empty()
            || self
                .inputs
                .iter()
                .any(|u| !script_matches(&u.script_pubkey, self.spend_kind))
        {
            return Err(BuildError::InvalidIntent);
        }
        let sequences = vec![RBF_SEQUENCE; self.inputs.len()];
        let mut hashes = Vec::with_capacity(self.inputs.len());
        for index in 0..self.inputs.len() {
            let hash = match self.spend_kind {
                SpendKind::P2pkhCompressed | SpendKind::P2pkhUncompressed => {
                    let mut preimage = self.serialize(Some(index))?;
                    preimage.extend(1u32.to_le_bytes());
                    sha256d(&preimage)
                }
                SpendKind::P2wpkh | SpendKind::P2tr => self.segwit_sighash(2, &sequences, index)?,
            };
            hashes.push(hash);
        }
        Ok(hashes)
    }
}

#[cfg(test)]
mod bitcoin_vectors {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn take<const N: usize>(bytes: &mut &[u8]) -> [u8; N] {
        let (first, rest) = bytes.split_at(N);
        *bytes = rest;
        first.try_into().unwrap()
    }
    fn script(bytes: &mut &[u8]) -> Vec<u8> {
        let length = take::<1>(bytes)[0] as usize;
        assert!(length < 253); // These exact fixtures use one-byte CompactSize lengths.
        let (first, rest) = bytes.split_at(length);
        *bytes = rest;
        first.to_vec()
    }
    fn transaction(
        raw: &str,
        spent: &[(u64, &str)],
        kind: SpendKind,
    ) -> (UtxoTransaction, u32, Vec<u32>) {
        let encoded = hex(raw);
        let mut bytes = encoded.as_slice();
        let version = u32::from_le_bytes(take(&mut bytes));
        assert_eq!(take::<1>(&mut bytes)[0] as usize, spent.len());
        let mut inputs = Vec::new();
        let mut sequences = Vec::new();
        for (value, script_pubkey) in spent {
            let mut txid = take::<32>(&mut bytes);
            txid.reverse();
            let vout = u32::from_le_bytes(take(&mut bytes));
            assert!(script(&mut bytes).is_empty());
            sequences.push(u32::from_le_bytes(take(&mut bytes)));
            inputs.push(Utxo {
                outpoint: OutPoint { txid, vout },
                value: *value,
                script_pubkey: hex(script_pubkey),
                confirmations: 0,
            });
        }
        let count = take::<1>(&mut bytes)[0];
        let mut outputs = Vec::new();
        for _ in 0..count {
            let amount = u64::from_le_bytes(take(&mut bytes)) as u128;
            outputs.push(Output {
                amount,
                script: script(&mut bytes),
            });
        }
        let lock_time = u32::from_le_bytes(take(&mut bytes));
        assert!(bytes.is_empty());
        (
            UtxoTransaction {
                inputs,
                outputs,
                fee: 0,
                vsize: 0,
                signed_vsize: None,
                anchor_height: 0,
                lock_time,
                spend_kind: kind,
            },
            version,
            sequences,
        )
    }

    #[test]
    fn bip143_published_native_p2wpkh_sighash_all() {
        // Exact "Native P2WPKH" unsigned transaction and previous outputs:
        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
        let raw="0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
        let spent = [
            (
                625_000_000,
                "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
            ),
            (600_000_000, "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"),
        ];
        let (tx, version, sequences) = transaction(raw, &spent, SpendKind::P2wpkh);
        assert_eq!(
            tx.segwit_sighash(version, &sequences, 1)
                .unwrap()
                .as_slice(),
            hex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
        );
    }

    #[test]
    fn bip341_published_keypath_sighash_default() {
        // keyPathSpending[0], inputSpending[3], txinIndex=4, hashType=DEFAULT:
        // https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
        let raw="02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d";
        let spent = [
            (
                420_000_000,
                "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
            ),
            (
                462_000_000,
                "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
            ),
            (
                294_000_000,
                "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
            ),
            (
                504_000_000,
                "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
            ),
            (
                630_000_000,
                "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
            ),
            (378_000_000, "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc"),
            (
                672_000_000,
                "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
            ),
            (
                546_000_000,
                "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
            ),
            (
                588_000_000,
                "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
            ),
        ];
        let (tx, version, sequences) = transaction(raw, &spent, SpendKind::P2tr);
        assert_eq!(
            tx.segwit_sighash(version, &sequences, 4)
                .unwrap()
                .as_slice(),
            hex("4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef")
        );
    }
}

fn rlp_prefix(len: usize, short: u8, long: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(short + len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let offset = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        out.push(long + (bytes.len() - offset) as u8);
        out.extend(&bytes[offset..]);
    }
}
fn rlp_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        rlp_prefix(bytes.len(), 0x80, 0xb7, out);
        out.extend(bytes);
    }
}
fn rlp_integer(value: u128, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes();
    let offset = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    rlp_bytes(&bytes[offset..], out);
}
impl Eip1559Transaction {
    /// EIP-1559 signing envelope: type byte followed by the nine unsigned RLP fields.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for n in [
            self.chain_id as u128,
            self.nonce as u128,
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.gas_limit as u128,
        ] {
            rlp_integer(n, &mut body);
        }
        rlp_bytes(&self.to, &mut body);
        rlp_integer(self.value, &mut body);
        body.extend([0x80, 0xc0]);
        let mut out = vec![2];
        rlp_prefix(body.len(), 0xc0, 0xf7, &mut out);
        out.extend(body);
        out
    }
    pub fn sighash(&self) -> [u8; 32] {
        Keccak256::digest(self.signing_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(value: u64) -> (Intent, UtxoState, UtxoPolicy) {
        let script = [vec![0, 20], vec![7; 20]].concat();
        let mut pin = [0; 72];
        pin[0] = 1;
        pin[1..33].fill(1);
        pin[37..45].copy_from_slice(&value.to_be_bytes());
        let intent = Intent {
            outputs: vec![Output {
                script: script.clone(),
                amount: 10_000,
            }],
            change_to: script.clone(),
            pin,
            allowed: vec![],
            fee_ceiling: 3_000,
            fee_rule: 0,
            bump_delay: 1,
            grid_ratio: [2, 1],
            min_conf: 1,
        };
        let state = UtxoState {
            height: 100,
            utxos: vec![Utxo {
                outpoint: OutPoint {
                    txid: [1; 32],
                    vout: 0,
                },
                value,
                script_pubkey: script.clone(),
                confirmations: 10,
            }],
            block_median_rates: [FeeRate::integer(10); 6],
        };
        let policy = UtxoPolicy {
            owner_script: script,
            spend_kind: SpendKind::P2wpkh,
            max_inputs: 8,
            late_inputs: false,
            dust_threshold: 294,
            replacement_increment: FeeRate::integer(1),
        };
        (intent, state, policy)
    }
    fn account() -> (Intent, AccountState) {
        let (mut i, _, _) = fixture(20_000);
        i.pin = [0; 72];
        i.pin[0] = 2;
        i.pin[8] = 7;
        i.outputs[0].script = vec![9; 20];
        i.outputs[0].amount = 100;
        i.fee_ceiling = 2_000_000;
        (
            i,
            AccountState {
                height: 100,
                nonce: 7,
                balance: 5_000_000,
                base_fee: 30,
                block_median_tips: [FeeRate::integer(2); 6],
            },
        )
    }
    #[test]
    fn d12_flat_bitcoin_market_still_bumps() {
        let (i, mut s, p) = fixture(20_000);
        let mut a = build_utxo(&i, &s, &p, 1, &[]).unwrap();
        assert_eq!((a.vsize, a.fee), (141, 1410));
        a.signed_vsize = Some(141); // D12 specifies the actual previous vsize.
        s.height += 1;
        let b = build_utxo(&i, &s, &p, 2, &[a]).unwrap();
        assert_eq!(b.fee, 1551);
    }
    #[test]
    fn d12_flat_account_market_uses_scheme_125_percent_bump() {
        let (i, mut s) = account();
        let a = build_eip1559(&i, &s, 1, 1, &[]).unwrap();
        assert_eq!((a.max_fee_per_gas, a.max_priority_fee_per_gas), (62, 2));
        s.height += 1;
        let b = build_eip1559(&i, &s, 1, 2, &[a]).unwrap();
        assert_eq!((b.max_fee_per_gas, b.max_priority_fee_per_gas), (70, 3));
    }
    #[test]
    fn d13_dust_is_charged_to_the_real_fee() {
        let (mut i, mut s, p) = fixture(10_762);
        i.fee_ceiling = 700;
        s.block_median_rates = [FeeRate {
            numerator: 562,
            denominator: 141,
        }; 6];
        assert_eq!(build_utxo(&i, &s, &p, 1, &[]), Err(BuildError::FeeCeiling));
        i.fee_ceiling = 762;
        let t = build_utxo(&i, &s, &p, 1, &[]).unwrap();
        assert_eq!((t.fee, t.outputs.len()), (762, 1));
    }
    #[test]
    fn pin_is_required_even_when_another_coin_covers_payment() {
        let (i, mut s, mut p) = fixture(20_000);
        p.late_inputs = true;
        s.utxos[0].outpoint.txid = [2; 32];
        assert_eq!(build_utxo(&i, &s, &p, 1, &[]), Err(BuildError::PinSpent));
    }
    #[test]
    fn generation_and_nonce_gates() {
        let (i, mut s) = account();
        s.nonce = 6;
        assert_eq!(
            build_eip1559(&i, &s, 1, 1, &[]),
            Err(BuildError::NoncePending)
        );
        s.nonce = 8;
        assert_eq!(build_eip1559(&i, &s, 1, 1, &[]), Err(BuildError::PinSpent));
        s.nonce = 7;
        assert_eq!(
            build_eip1559(&i, &s, 1, 2, &[]),
            Err(BuildError::InvalidPrevious)
        );
        let a = build_eip1559(&i, &s, 1, 1, &[]).unwrap();
        assert_eq!(build_eip1559(&i, &s, 1, 2, &[a]), Err(BuildError::TooEarly));
    }
    #[test]
    fn account_all_reserves_maximum_fee_and_rejects_ceiling() {
        let (mut i, s) = account();
        i.outputs[0].amount = ALL;
        let a = build_eip1559(&i, &s, 1, 1, &[]).unwrap();
        assert_eq!(a.value, s.balance - 21_000 * 62);
        i.fee_ceiling = 21_000 * 62 - 1;
        assert_eq!(
            build_eip1559(&i, &s, 1, 1, &[]),
            Err(BuildError::FeeCeiling)
        );
    }
    #[test]
    fn largest_first_and_serialization_order_ignore_snapshot_order() {
        let (i, mut s, mut p) = fixture(1_000);
        p.late_inputs = true;
        for (id, value) in [(3, 6_000), (2, 20_000), (4, 500)] {
            let mut u = s.utxos[0].clone();
            u.outpoint.txid = [id; 32];
            u.value = value;
            s.utxos.push(u);
        }
        let a = build_utxo(&i, &s, &p, 1, &[]).unwrap();
        assert_eq!(
            a.inputs
                .iter()
                .map(|u| u.outpoint.txid[0])
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        s.utxos.reverse();
        assert_eq!(build_utxo(&i, &s, &p, 1, &[]).unwrap(), a);
        p.max_inputs = 1;
        assert_eq!(
            build_utxo(&i, &s, &p, 1, &[]),
            Err(BuildError::TooManyInputs)
        );
    }
    #[test]
    fn all_takes_every_eligible_input_and_no_change() {
        let (mut i, mut s, mut p) = fixture(20_000);
        i.outputs[0].amount = ALL;
        p.late_inputs = true;
        let mut u = s.utxos[0].clone();
        u.outpoint.txid = [2; 32];
        u.value = 5_000;
        s.utxos.push(u);
        let a = build_utxo(&i, &s, &p, 1, &[]).unwrap();
        assert_eq!((a.inputs.len(), a.outputs.len()), (2, 1));
        assert_eq!(a.outputs[0].amount + a.fee as u128, 25_000);
    }
    #[test]
    fn malformed_state_and_overflow_fail_closed() {
        let (i, mut s, p) = fixture(20_000);
        s.utxos.push(s.utxos[0].clone());
        assert_eq!(
            build_utxo(&i, &s, &p, 1, &[]),
            Err(BuildError::InvalidIntent)
        );
        let (i, s) = account();
        let mut bad = s.clone();
        bad.base_fee = u128::MAX;
        assert_eq!(
            build_eip1559(&i, &bad, 1, 1, &[]),
            Err(BuildError::Overflow)
        );
        bad = s;
        bad.block_median_tips[0].denominator = 0;
        assert_eq!(
            build_eip1559(&i, &bad, 1, 1, &[]),
            Err(BuildError::InvalidIntent)
        );
    }
    #[test]
    fn sealed_grid_uses_frozen_allowed_inputs_and_selects_least_sufficient_fee() {
        let (mut i, mut s, p) = fixture(20_000);
        let mut extra = s.utxos[0].clone();
        extra.outpoint.txid = [2; 32];
        extra.value = 5_000;
        let mut allowed = [0; 36];
        allowed[..32].fill(2);
        i.allowed.push(allowed);
        s.utxos.push(extra);
        i.fee_ceiling = 4_000;
        let sealed = SealedUtxoIntent {
            intent: i,
            inputs: s.utxos.clone(),
            policy: p,
        };
        let a = variant_utxo(&sealed, 1, 3).unwrap();
        let b = variant_utxo(&sealed, 2, 3).unwrap();
        let c = variant_utxo(&sealed, 3, 3).unwrap();
        assert_eq!((a.fee, b.fee, c.fee), (1000, 2000, 4000));
        assert_eq!(a.inputs, b.inputs);
        assert_eq!(b.inputs, c.inputs);
        assert_eq!(a.inputs.len(), 2);
        assert_eq!(a.lock_time, 0);
        s.block_median_rates = [FeeRate::integer(6); 6];
        assert_eq!(select_utxo(&sealed, &s, 3, 0).unwrap().0, 2);
        assert_eq!(select_utxo(&sealed, &s, 3, 2).unwrap().0, 3);
        assert_eq!(select_utxo(&sealed, &s, 3, 3), Err(BuildError::NoVariant));
        s.utxos[1].value += 1;
        assert_eq!(
            select_utxo(&sealed, &s, 3, 0),
            Err(BuildError::InvalidIntent)
        );
    }
    #[test]
    fn sealed_grid_rejects_dust_and_too_small_replacement_steps() {
        let (mut i, s, p) = fixture(20_000);
        i.grid_ratio = [101, 100];
        let mut sealed = SealedUtxoIntent {
            intent: i,
            inputs: s.utxos,
            policy: p,
        };
        assert_eq!(variant_utxo(&sealed, 1, 2), Err(BuildError::InvalidIntent));
        sealed.intent.grid_ratio = [2, 1];
        sealed.intent.fee_ceiling = 9_900;
        assert_eq!(variant_utxo(&sealed, 1, 2), Err(BuildError::FeeCeiling));
    }
    #[test]
    fn sealed_account_is_one_frozen_ceiling_variant() {
        let (i, mut s) = account();
        let t = variant_eip1559(&i, 1, s.balance).unwrap();
        assert_eq!(t.max_fee_per_gas, i.fee_ceiling / 21_000);
        assert_eq!(select_eip1559(&i, &s, &t, 0), Ok(1));
        assert_eq!(select_eip1559(&i, &s, &t, 1), Err(BuildError::NoVariant));
        s.base_fee = t.max_fee_per_gas + 1;
        assert_eq!(select_eip1559(&i, &s, &t, 0), Err(BuildError::NoVariant));
    }
    #[test]
    fn bitcoin_encoding_and_sighashes_bind_inputs_outputs_and_locktime() {
        let (i, s, p) = fixture(20_000);
        let t = build_utxo(&i, &s, &p, 1, &[]).unwrap();
        let bytes = t.unsigned_bytes().unwrap();
        assert_eq!(bytes.len(), 113);
        assert_eq!(&bytes[..5], &[2, 0, 0, 0, 1]);
        assert_eq!(&bytes[42..46], &RBF_SEQUENCE.to_le_bytes());
        assert_eq!(&bytes[109..], &100u32.to_le_bytes());
        let h = t.sighashes().unwrap();
        let mut changed = t.clone();
        changed.inputs[0].value += 1;
        assert_ne!(changed.sighashes().unwrap(), h);
        changed = t.clone();
        changed.outputs[0].amount += 1;
        assert_ne!(changed.sighashes().unwrap(), h);
        changed = t;
        changed.lock_time += 1;
        assert_ne!(changed.sighashes().unwrap(), h);
    }
    #[test]
    fn account_type2_encoding_has_empty_data_and_access_list() {
        let (i, s) = account();
        let t = build_eip1559(&i, &s, 1, 1, &[]).unwrap();
        let mut expected = vec![2, 0xdf, 1, 7, 2, 62, 0x82, 0x52, 0x08, 0x94];
        expected.extend([9; 20]);
        expected.extend([100, 0x80, 0xc0]);
        assert_eq!(t.signing_bytes(), expected);
        assert_eq!(t.sighash(), <[u8; 32]>::from(Keccak256::digest(&expected)));
    }
    #[test]
    fn replacement_with_more_inputs_exceeds_all_prior_fee_rates() {
        let (i, mut s, mut p) = fixture(11_400);
        p.late_inputs = true;
        let mut first = build_utxo(&i, &s, &p, 1, &[]).unwrap();
        first.signed_vsize = Some(first.vsize);
        assert_eq!((first.fee, first.vsize), (1400, 110));
        let mut extra = s.utxos[0].clone();
        extra.outpoint.txid = [2; 32];
        extra.value = 20_000;
        s.utxos.push(extra);
        s.height += 1;
        let next = build_utxo(&i, &s, &p, 2, std::slice::from_ref(&first)).unwrap();
        assert_eq!((next.fee, next.vsize), (2661, 209));
        assert!(
            (next.fee as u128) * (first.vsize as u128) > (first.fee as u128) * (next.vsize as u128)
        );
    }
    #[test]
    fn legacy_and_taproot_profiles_have_distinct_sighash_rules() {
        for kind in [
            SpendKind::P2pkhCompressed,
            SpendKind::P2pkhUncompressed,
            SpendKind::P2tr,
        ] {
            let (i, mut s, mut p) = fixture(20_000);
            p.spend_kind = kind;
            p.owner_script = if kind == SpendKind::P2tr {
                [vec![0x51, 32], vec![7; 32]].concat()
            } else {
                [vec![0x76, 0xa9, 20], vec![7; 20], vec![0x88, 0xac]].concat()
            };
            s.utxos[0].script_pubkey = p.owner_script.clone();
            let t = build_utxo(&i, &s, &p, 1, &[]).unwrap();
            let hash = t.sighashes().unwrap();
            let mut changed = t.clone();
            changed.inputs[0].value += 1;
            if kind == SpendKind::P2tr {
                assert_ne!(hash, changed.sighashes().unwrap());
            } else {
                assert_eq!(hash, changed.sighashes().unwrap());
            }
            changed = t;
            changed.outputs[0].amount += 1;
            assert_ne!(hash, changed.sighashes().unwrap());
        }
    }
    #[test]
    fn median_averages_middle_values_without_floating_point() {
        let rate = fee_rule([9, 1, 8, 2, 5, 4].map(FeeRate::integer)).unwrap();
        assert_eq!(
            rate,
            FeeRate {
                numerator: 9,
                denominator: 2
            }
        );
        assert_eq!(rate.fee(3), Ok(14));
        let (i, mut s, p) = fixture(20_000);
        s.utxos[0].confirmations = 0;
        assert_eq!(build_utxo(&i, &s, &p, 1, &[]), Err(BuildError::Unconfirmed));
    }
    #[test]
    fn high_rate_replacement_accounts_for_shorter_previous_der_signature() {
        let (mut i, mut s, p) = fixture(2_000_000);
        i.fee_ceiling = 500_000;
        s.block_median_rates = [FeeRate::integer(1000); 6];
        let mut first = build_utxo(&i, &s, &p, 1, &[]).unwrap();
        first.signed_vsize = Some(140);
        s.height += 1;
        let next = build_utxo(&i, &s, &p, 2, std::slice::from_ref(&first)).unwrap();
        assert_eq!(next.fee, 142_008);
        assert!((next.fee as u128) * 140 > (first.fee as u128) * (next.vsize as u128));
        first.signed_vsize = None;
        let worst = build_utxo(&i, &s, &p, 2, std::slice::from_ref(&first)).unwrap();
        assert_eq!(worst.fee, 159_049);
        for impossible in [0, 124, 142] {
            first.signed_vsize = Some(impossible);
            assert_eq!(
                build_utxo(&i, &s, &p, 2, std::slice::from_ref(&first)),
                Err(BuildError::InvalidPrevious)
            );
        }
    }
    #[test]
    fn single_sealed_variant_does_not_require_a_fee_grid_increase() {
        let (mut intent, state, policy) = fixture(20_000);
        intent.grid_ratio = [1, 1];
        let sealed = SealedUtxoIntent {
            intent,
            inputs: state.utxos,
            policy,
        };
        assert_eq!(variant_utxo(&sealed, 1, 1).unwrap().fee, 3_000);
    }
}
