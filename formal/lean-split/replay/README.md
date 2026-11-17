# Replay of the Quint model through the oracles

`replay.py` replays the ITF traces of the Quint model of LOOP item 14
(`formal/quint-spec/`, written from the specs only) through the `--step` mode of
five oracles: request (`../request`), authorization (`../authorization`), slots
(`../slots`), envelope (`../envelope`) and shard-holders (`../shard-holders`).
It checks each oracle against the spec through an independent reading of the
same sentences.

```sh
for c in request authorization slots envelope shard-holders; do (cd ../$c && lake build oracle); done
python3 -I replay.py --oracle ../request/.lake/build/bin/oracle \
  --auth-oracle ../authorization/.lake/build/bin/oracle \
  --slots-oracle ../slots/.lake/build/bin/oracle \
  --envelope-oracle ../envelope/.lake/build/bin/oracle \
  --shard-oracle ../shard-holders/.lake/build/bin/oracle \
  --traces ../../quint-spec/traces-sample/tee_p2_initArmed ... \
  --expect-disagree "DIR@EVENT@TEXT" ... [--json OUT]
```

Each oracle is one lane. A lane has its own oracle process per trace directory
and its own threaded state, and it compares its own projection of the model
state. The lanes do not share state: a disagreement in one lane does not stop
the others. The negative controls run the request lane only. `--auth-oracle`,
`--slots-oracle`, `--envelope-oracle` and `--shard-oracle` are optional;
without them the lane does not run.

`formal/drwatt/gate.sh replay` (SLG-026) runs it on the committed traces of
`formal/quint-spec/traces-sample/`. The full sets that `run_gate.sh traces
testtraces` regenerates (not committed) go through the same command.

## How a trace is replayed: request lane

- The driver starts the oracle once per trace directory with
  `LEAN_ABORT_ON_PANIC=1`. Each answer must come within `--timeout` seconds. An
  `error` answer, stderr output or a nonzero exit is a protocol error (exit 2).
- The oracle state starts at `init` with the model's constants: `n = 4`,
  `f = 1`, `Δ_c = 4`, `Δ_hold = 1`, the mode of the directory name, and epoch 1.
  For `initArmed` the oracle gets `post` of request 1. After that the oracle
  state is threaded from the oracle's own answers. The driver never writes the
  model state into it.
- Each step maps `lastOp` to oracle operations (event map below) and then
  compares the request projection of the model state with the oracle state.
  The first disagreement ends that trace. The other traces go on.
- A refused model event (`code` set) must leave the model state unchanged. The
  oracle must refuse the mapped operation with the model's code among its
  codes. The driver sends the refusal as a probe from the threaded state and
  keeps that state.

## Compared fields and inputs

Compared on every request after every step: `phase`, `reason`, `outcome`,
`any_release`, `restart_end`, `anchor[1..2]`, `released[1..2]`, `exp_c`,
`end_height`, `order_pos`, `exp`, the complaint record (`early` against
`early_complaint`, `late` against `dealer_fault`), `filled` (position 0 of a
collecting request) and the FINAL and VOID posts (member `m` of the model is
node `m − 1`). The set of request ids, the board height and the registered
epochs are compared too.

Values that the driver takes from the model to build an operation are inputs.
They are not evidence for the step that uses them:

| Event | Inputs taken from the model |
|---|---|
| `post` | `exp`, `epoch`, type, profile |
| `order` | the position `b = height + 1` |
| `open` | `K`, `L`, `collecting` (rates `[1..K]`, one actor position) |
| `admit`, `anchor2` | the variant `j`: the host fee median is `j`, so RQ-027 selects `j`; `anchor[g] = j` is not evidence, the phase and the guards are |
| `record_release` | `j = anchor[g]` |
| `post_void` | the reason of the new post |
| `restart` | the requests whose `restart_end` the model sets |

The node queries (RQ-030, RQ-037, RQ-069) build the node's view from the model
guards: authorization in force, no revocation read, release check passed, the
RQ-033 hold age from the model's Midnight heights, `w` acks in TEE mode.

## Event map

| `lastOp.kind` | Oracle operations |
|---|---|
| `post` | `post` |
| `order` | `tick(h + 1)`, `order(qc, p = h + 1)` |
| `tick` | `tick(h)` |
| `checkpoint` | `land_checkpoint(h)`, `tick(h + 1)` (the model raises the height after the checkpoint) |
| `complain` | `complaint` |
| `open` (arg 1) | `open`; arg 0 (malformed, RQ-014) maps to no operation |
| `opened_vote` | `q` `vote_opened` with one hash |
| `frame`, `frame_complaint` | `frame` (position 0), `detach` |
| `admit` | `host_fee(H, j)`, `q` `vote_admit` at host height `H` |
| `anchor2` | `host_fee(H, j)`, `obs2(missed, f + 1 heights H)` |
| `send_release` | TEE: `release(g, j)`; NON_TEE: node query only (RQ-069: `release` act after the RELEASE committed) |
| `record_release` | node query (`release_record` act), then `release(g, j)` |
| `host_confirm` | `confirm` |
| `post_final`, `post_void` | `post_final` (one `ct`), `post_void` |
| `rotate` | `rotate(2, 4, 1)` |
| `restart` | `restart_burn` for each request the restart re-ends |
| `reissue` | `carry` of the stalled request |
| `expire` | none (see RQ-046 below) |
| `authorize`, `finalize_auth`, `revoke`, `tick_midnight`, `ecdsa_prec` | none; the compared fields must not change |
| `register_addr`, `holder_ack`, `creator_ack`, `ack_ok`, `acknowledge`, `pay_addr` | none (declared stutter steps; the shard-holders lane drives them); the compared fields must not change |
| refusals `admit/unknown_request`, `admit/terminal` | `vote_admit` probe |
| `order/no_qc`, `order/exp_c_not_below_exp` | `tick(h + 1)`, `order` probe |
| `frame/position_filled`, `frame/late_contribution` | `frame` probe |
| `post_void/unknown_epoch` | `post_void` in epoch 2 |
| `admit/not_in_force`, `admit/above_window`, `admit/settled` | node query |
| `authorize/nf_used`, `revoke/not_revocable`, `reissue/bad_carry`, `checkpoint/*` (`pending_min_lowered` included) | none in this lane; the census counts them as "other package" (the authorization lane replays the first three) |
| `ack_ok/ack_refused`, `acknowledge/no_ack_certificate` | none in this lane; "other package" (the shard-holders lane replays them) |

## RQ-046: expiry

The oracle reads RQ-046 ("When the board height passes `exp` ...") as part of
the board block: `tick` expires every live request with `exp < h`. The model
has a separate `expire` event that stays enabled. When the oracle has expired a
request and the model has not, the driver holds the request until the model's
`expire` and then compares it in full, `end_height` included. This accepts only
stuttering. Any other model event on that request, or a later expiry height, is
a disagreement of class `RQ-046 timing`. `--relax-expiry-height` accepts a
later expiry height. It is a diagnostic to look past the first class, not a
gate mode.

## Authorization lane

The model's one asset record and its authorizations against
`../authorization`. The lane starts with `charter(cid 1, profile)` and
`record(rid 1, cm_addr 1, nf fresh 1, hold_tag 1, slr_own 1, slr_G 1 in P2)`.
For `initArmed` it adds `authorize` and `finalize` of request 1.

Model nullifiers are integers. The lane maps each one to the oracle's
nullifier: `fresh n` for the nullifier of a new coin, `(auth, outcome)` for
the successor that a settlement leaf names. The map is built from the model
steps that create a nullifier. An unknown model nullifier is a protocol error.

| `lastOp.kind` | Authorization oracle operations |
|---|---|
| `authorize` | `authorize` (record = model coin, current nullifier, auth = the request, pin = `arg`, source of the request) |
| `finalize_auth` | `finalize(auth, height = arg)` |
| `revoke` | `revoke(auth, tag 1)` |
| `checkpoint` | `settle_root` with the model's settle leaves; on a new coin, `record` of that coin |
| `reissue` | `authorize` of the new request with the carry `{auth_0, VOID, q signatures}` |
| refusal `authorize/nf_used` | `authorize` probe with the record's current nullifier |
| refusal `revoke/not_revocable` | `revoke` probe |
| refusal `reissue/bad_carry` | `authorize` probe with a FINAL carry |
| any other event | none |

Inputs taken from the model: the pin and the source of each authorization, the
finalization height, and the settle leaves of each checkpoint. Compared after
every step: the number of coins, and for the current record `rstate`, `pin`,
the nullifier, whether it is used and whether a hold is set; for every
authorization its coin, `status`, `final_height`, `settled`, `pin` and
nullifier, and the set of authorization ids.

## Slots lane

The model's committee pool of four indices against `../slots`, as one BIP340
pool of epoch 1 (`deal_c BIP340 1 4`). The ECDSA pools (`eslots`) are not
compared.

| `lastOp.kind` | Slots oracle operations |
|---|---|
| `finalize_auth` (and request 1 of `initArmed`) | `in_force(e, OWN or G)`; a refusal is accepted only when the model request has lapsed or has ended (the model finalizes an authorization after the end too) |
| `open` (arg 1), SCHNORR | `open_c(e, pos = order_pos, names = cslot[1..G])` |
| `opened_vote`, SCHNORR | `reserve` |
| `admit`, SCHNORR | `reserve` (from OPENED), `claim` |
| `restart` | `burn_range(lo = pending_min, hi = cp.h + 2)` when `lo <= hi` |
| any step that ends a request | `end` |
| any step that sets `lapsed` | `lapse` |

Inputs taken from the model: the slot names of each open, the order position,
the restart burn range and the lapse of a request. Compared after every step:
`bstat`, `prec` and the set of namers of every committee slot.

## Envelope lane

EN-023 against `../envelope`. At every `post` and every accepted `order` the
lane sends `order_check{exp, height = h + 1}` and expects it accepted. At every
`order/exp_c_not_below_exp` refusal it sends the same probe and expects that
refusal code. The probes do not change the threaded state; the lane compares
no state fields.

## Shard-holders lane

The model's `addr` (revision 6, DECISIONS 67: the asset record of one address
with a network-created shard) against `../shard-holders`, SH-030 to SH-037.
The address is `cm_addr 1`. Member `m` of the model is node `m − 1`. The lane
starts with `fix_charter(1, user OR 3-of-5 guardians)`; the oracle's `q` is 3
at `n = 4`, `f = 1`, equal to the model's `Q`.

| `lastOp.kind` | Shard-holders oracle operations |
|---|---|
| `register_addr` | `birth_check` by nodes `0 .. q − 1` (every check passes; the actor's shard is network-created), then `submit_record` with `network_created` true, `q` signers and the escrow and guardian ACKs; each must be accepted |
| `holder_ack` | `holder_open(x_match = ec_ok)`; the answer must be `ack_envelope` (SH-030). The model takes `holder_ack` only when `ec_ok` |
| `creator_ack` | none: it sets the `pop_u` input of the later `ack_check` steps to false |
| `ack_ok` (arg = member) | `ack_check(node m − 1)`; the answer must be `ack_ok` (SH-031) |
| `acknowledge` (arg = signature count) | `acknowledge` with the model's `ack_ok` members as signers (their count must equal `arg`); the answer must be `ok` (SH-037) |
| `pay_addr` | `pay`; the answer must be `paid` (SH-035) |
| refusal `ack_ok/ack_refused` (eid = member) | `ack_check` probe of that member on the creator's envelope |
| refusal `acknowledge/no_ack_certificate` | `acknowledge` probe with the model's `ack_ok` members as signers |
| any other event | none (declared stutter step) |

A refusal agrees only when the oracle refuses with exactly the mapped code
(the list of codes equals `[code]`, so an extra `outside-capability` or
`no-rule` is a disagreement) and the oracle state is unchanged: a probe is
never threaded, and the compare after the step checks the state.

Inputs taken from the model: `ec_ok` (the holder wallet's check `x_u·G = X_u`),
the envelope that opened (the holder's carries a valid `pop_u`, the creator's
does not) and the corrupt member. The model's corrupt member 1 signs ACK_OK on
any envelope. The oracle's `ack_check` is the check of a node, with the three
SH-031 checks as input flags, and an ACK_OK verifies exactly when the node gave
it in the run. The lane drives the corrupt member's ACK_OK as an `ack_check`
with every flag true: an adversarial input, not evidence. SH-031 and SH-032
bind the honest members, and their steps are the evidence. The charter, the
birth data and the escrow and guardian ACKs of the record are fixed inputs.

Compared after every step: whether the record of `cm_addr 1` is registered,
its `acked` flag and `network_created`, no other record, and the set of
members with an ACK_OK on it. At every state with a registered record the lane
also sends a `pay` probe: the payer wallet must pay exactly when the model has
`acked` (SH-035). `ec_ok`, `ack_env` and `paid` are wallet facts with no oracle
state; the lane keeps them from the observations (`ack_envelope`, `paid`) and
compares them with the model.

The other lanes take the six events as declared stutter steps: the request
lane maps them to no operation and checks that no compared request field
changes; the authorization, slots and envelope lanes send nothing for them.
The model has no refused `holder_ack` or `pay_addr` event, so SH-036 has no
replay evidence; the `pay` probe gives SH-035 refusals (`pin_holder_wrong_ec`
and `pin_pay` carry them in the oracle too).

## Negative controls

- `traces-sample/mutant_stalled_after_release_tee_p1/`: the kill schedule of the
  model mutant `stalled_after_release` (the RQ-045 reason rule of revision 3).
  It must disagree at its tombstone: model STALLED, oracle MIXED (RQ-073,
  RQ-074). It is exported from the model unchanged, in `formal/quint-spec/`:
  `quint test splitspec_test.qnt --main test_m_stalled_after_release --match 'Test$'
  --max-samples 1 --out-itf RAW/{test}_{seq}.itf.json`, then
  `python3 -I tools/flatten_itf.py RAW traces-sample/mutant_stalled_after_release_tee_p1`.
- `traces-sample/f6_nontee_p1_rev3/` holds the two revision 3 F6 traces of
  the model lane. They disagree by design (from step 46: the RELEASE record at
  height 18 of a request with `exp = 16`, which the oracle expired at the tick
  to 17, RQ-046), and `gate.sh replay` leaves them out.

## Not replayed

The checkpoint (CP) is a model field that no lane compares, and the census of
the request lane counts the checkpoint refusals (`pending_min_lowered` among
them) as "other package". The shard holders are compared only for the address
record of revision 6 (SH-030 to SH-037); the birth, pools, contributions and
slot sessions (SH-001 to SH-026) have no model event. The slots lane does not compare the ECDSA pools, and the
envelope lane drives only `order_check`, not `submit`.

## Results at spec revision 4 (04a3c4f)

The full regenerated sets (`run_gate.sh traces testtraces`, 518 traces), with
the lead rulings on ledger entries 8, 12, 27 and 28 in the request oracle:

| Lane | Traces that agree | Transitions that agree |
|---|---|---|
| request | 110 / 518 | 19971 |
| authorization | 518 / 518 | 28040 |
| slots | 518 / 518 | 28040 |
| envelope | 518 / 518 | 28040 |

The committed samples (`gate.sh replay`, 47 traces):

| Lane | Traces that agree | Transitions that agree |
|---|---|---|
| request | 29 / 47 | 710 |
| authorization | 47 / 47 | 1005 |
| slots | 47 / 47 | 1005 |
| envelope | 47 / 47 | 1005 |

In the request lane about 4100 of the agreeing transitions are events with no
request-oracle operation (`tick_midnight`, `authorize`, `finalize_auth`,
`revoke`, `ecdsa_prec`, `expire`), where only "no compared field changed" is
checked, and about 1100 are refusal probes. Every first disagreement of the
request lane falls in one of four classes. All four are model findings: the
oracle follows the lead rulings, and the Quint model is fixed from the spec in
a separate lane. Eight scripted schedules of item 14 (F1, F5 and SL-010 among
them) and both revision 3 F6 seeds reach their states only through a late
`expire` (class A).

| Class | Traces | Verdict |
|---|---|---|
| A. RQ-046 timing: the model acts on a request, or expires it, after the board passed `exp` | 282 | Model. Lead ruling: the expiry is urgent at the tick (ledger 27, reading (a)). The model's `expire` stays enabled and is not taken at the tick, so posts, opens and releases land on a request that the spec has already expired. |
| B. A frame that the model holds and the oracle refuses `late_contribution`: ordered above `exp_c` while the target is ORDERED (67), or for a target in OPENED or later (36) | 103 | Model. Lead rulings: RQ-020 applies in every live phase, and a frame for a request in OPENED or later is refused `late_contribution` (ledger 8; `pin_rq020_ordered`, `pin_rq021_opened`, `pin_rq021_admitted`, two mutants). The model's `frame` hold branch has neither guard. |
| C. A restart that loses the release evidence (`restartWith(lose)`): the model clears `any_release` and `released` | 22 | Model. Lead ruling: `any_release` and `released` survive the loss of the board tail (ledger 28). DECISIONS 53 settles the outcome (RELEASED) and both sides agree on it. |
| D. A restart burn of a request whose VOID leaf a reissue carried: the model re-ends it, the oracle refuses `settled` | 1 | Model. Lead ruling: the oracle's refusal is right under D-058, "the restart gives it no second outcome" (ledger 12). |

The authorization, slots and envelope lanes agree on every transition of
every trace. Replay evidence for revision 4 rules (compared transitions, full
sets): AU-029 VOID of a pinned record 3, SL-005 late open burns 79, EN-023
`order_check` at post 1200, at order 1122, at the `exp_c_not_below_exp`
refusal 51, RQ-072 MIXED tombstone 149, RQ-069 record before send 37 and send
after record 17, RQ-073/RQ-074 STALLED post after release 4, RQ-071 carry of a
STALLED leaf 2.

The negative control disagrees where expected. The first oracle run on the
replay also showed RQ-020 before COLLECTING (20 refused model frames answered
`no-rule` or accepted): that was an oracle defect, fixed with ledger 8. The
first run of the slots lane refused `in_force` for 6 authorizations that the
model finalized after their request ended; the lane now accepts that refusal
for an ended request, and the compared slots stay equal.

## Results against the revision 5 model

The model-fix lane (DECISIONS 70: RQ-046 expiry inside `tick`, `order` and
`landCheckpoint`, RQ-075 for ruling C, RQ-076 for ruling D, no `expire` op,
`restart` with `lose` changes no state) regenerated `traces-sample/`. Its six
sample sets (55 traces, the F6 seeds left out) through the same oracles:

| Lane | Traces that agree | Transitions that agree |
|---|---|---|
| request | 55 / 55 | 1011 |
| authorization | 55 / 55 | 1043 |
| slots | 55 / 55 | 1043 |
| envelope | 55 / 55 | 1043 |

Every class A to D is gone. The driver needs no change for that format: with
no `expire` event the RQ-046 hold never starts, and the ghost field
`g_rel_seen` is not a compared field. `gate.sh replay` (SLG-026) holds on these
samples (main at b8d6a4d) with the oracles at the 237-requirement revision
(DECISIONS 65 to 70), and the negative control disagrees where expected. The
replay drives the node view with `auth` `IN_FORCE` or `NOT_IN_FORCE` only and
compares no slots observation, so RQ-025 (`IN_FORCE_MISMATCH`) and SL-016
(SLOT_TAKEN once in force) have no replay evidence; their pins and mutants
carry them.

## Results against the revision 7 model

Revision 7 (LOOP item 36, DECISIONS 71) changes only the CP-014 pending list and
replaces `cp040PendingMinLoweredBlocked1Test` with `f7SpamPrecedenceLandsTest`
and `cp040OldIndexRefusedTest`. The committed samples are 67 traces (49 scripted
traces of `test_tee_p2`). Every lane agrees on every trace: request 1089
transitions, authorization, slots, envelope and shard-holders 1151 each, and the
negative control disagrees where expected (`replay: every set as expected`). No
lane runs the checkpoint oracle, so this replay carries no CP-014 evidence; the
checkpoint pins, theorems and Spec mutants carry it.

## Results against the revision 6 model

Revision 6 (item 14c, DECISIONS 67 to 69) adds `addr`, the ghost `g_adm_posts`,
six events and three refusal codes. The ghost is not a compared field. The
committed samples (`gate.sh replay`, 66 traces) with the shard-holders lane:

| Lane | Traces that agree | Transitions that agree |
|---|---|---|
| request | 66 / 66 | 1086 |
| authorization | 66 / 66 | 1148 |
| slots | 66 / 66 | 1148 |
| envelope | 66 / 66 | 1148 |
| shard-holders | 66 / 66 | 1148 |

The request lane counts the refusals of other packages as "other package", not
as transitions. Shard-holders evidence (compared transitions): `register_addr`
14 (SH-034), `holder_ack` 7 (SH-030), `ack_ok` 30 (19 by honest members,
SH-031; 11 by the corrupt member, inputs), `ack_ok/ack_refused` 19 (SH-032),
`acknowledge` 6 (SH-037), `acknowledge/no_ack_certificate` 25 (SH-033),
`pay_addr` 6 and the `pay` probe 121 paid and 358 refused (SH-035).
`creator_ack` (5) has no oracle operation. No disagreement: the model and the
oracle agree on every SH-030 to SH-037 transition, so no ledger entry is new.
The negative control disagrees where expected. A lane with the member offset
off by one, or with `pop_u` true on the creator's envelope, goes red on
`tee_p2_refusals` (checked by hand, not committed).
