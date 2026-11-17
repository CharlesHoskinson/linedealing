# split-request reference suite

The KRS port of the request machine of `../../lean-split/request` (`Spec.lean`,
`reqStep` and the board events of `step`), checked against that oracle through
`../scripts/oracle_adapter.py` and `schema.json`.

## What the definition holds

`src/lib.rs` is one KRS definition, `split-request-reference`. Its configuration has the
cells `params`, `height`, `cpheight`, `epochs`, `hostmed`, `requests`, `ops` and `obs`. Each
operation of the oracle's `Op` is one rule pair: the event applies (`x`) or is refused
(`x_refused`), and the observation that the oracle records is appended to `obs`.

* Board events: `post`, `tick` (RQ-046 expiry), `rotate` (RQ-001, ledger 5),
  `land_checkpoint` (RQ-054, ledger 4) and `host_fee` (RQ-027, ledger 7).
* Events that name a request: `order`, `open_header`, `complaint`, `frame`, `detach`,
  `vote_opened`, `vote_admit`, `obs2`, `post_final`, `post_void`, `restart_burn`,
  `confirm`, `carry` and `release`. Each runs through `T<Op>`: an eid the board does
  not hold is refused with `unknown_request` (RQ-004).
* Each step is a chain of single-condition functions, one per check of the oracle, in the
  oracle's order: `terminal` first, then the capability domain, then the phase, then the
  repeat checks. One condition per function gives every MC/DC obligation a reachable
  case.
* `Option Nat` is a list of at most one integer (`[]` or `[x]`); `anchor`, `released` and
  the actor slot table are lists of such options.

The node rules of the oracle (`nodeAct`, `combinerCount`, the checks of RQ-031 to RQ-041
that a node evaluates) are not board steps. `gaps.toml` lists each with the
Lean theorem or pin that covers it.

## The RELEASE record and the VOID reason

The revision of DECISIONS 59 to 70 (item 13) is in the oracle and in this port:

* The board records a RELEASE of generation `g` with variant `j` when it commits in a board
  vote (`release`, RQ-037); a request with a recorded RELEASE settles RELEASED, never VOID
  (RQ-050, RQ-051). The oracle's board `release` step did not change: the revision moved the
  send record to the node, which in NON_TEE mode posts the RELEASE (`release_record`) and
  sends partials only once it committed (RQ-069, a node rule in gaps.toml).
* A VOID end takes the reason that `f_e + 1` reason posts of the completing epoch carry, else
  MIXED (`TombReason`, RQ-045, RQ-072); once `any_release` holds, STALLED posts are no reason
  posts (RQ-073, RQ-074). MIXED is no post reason (RQ-065), and `carry` takes only a VOID
  leaf whose reason reads as STALLED (`ReadsAs`, RQ-060, RQ-071).
* `order` refuses `exp_c_not_below_exp` when `b + Δ_c ≥ exp` (EN-023 at the ordering block).
* A frame is `late_contribution` above `exp_c` in every live phase that is not COLLECTING
  (RQ-020) and for a target in OPENED or ADMITTED (RQ-075).
* `restart_burn` keeps `any_release` and `released` (RQ-076).

## Argued coverage and survivors

* `syntax:crate::ModeC::Tee`, `syntax:crate::ModeC::NonTee`: only the node rules read
  the mode; no board step takes it as an operand.
* `flip--admit_count_1+admit_count_2--QOf`: the negated count guard reads the anchor
  height from fewer than f + 1 heights, an undefined step of the mutant, so the flip has
  no comparable run. The count misreadings are killed by `events/admit-any-hash` and
  `events/admit-all-heights`.
* Survivor `events/obs2-g1`: G = 1 only when K = 1, and then generation 2 cannot select
  above anchor[1] = 1, so the G check and the selection check refuse the same events.
* Survivor `events/held-any-height`: since RQ-020 holds in every live phase (ledger 8), a
  frame is held only at or below `exp_c` (a POSTED frame's height is at most the later order
  height), so the attach-time height check of `attachHeld` never decides.
* Survivor `helpers/h-find-1`: `find` returns its default record only for an eid the
  board does not hold, and `targeted` then answers `unknown_request` without reading it.

## Files

| Path | What |
|---|---|
| `src/lib.rs` | the definition |
| `schema.json` | the adapter schema: the oracle's JSON names and the KRS constructors |
| `kink/FLOW.toml` | programs, MC/DC, the lean-oracle implementation, argued items |
| `kink/cases/` | the corpus (typed cases; `../scripts/mkcase.py` writes them from oracle-form inputs) |
| `kink/mutations/` | `board`, `events`, `helpers`, `release`, `void` |
| `gaps.toml` | the EARS IDs the board steps do not hold, with their Lean checks |
| `golden/vectors.json` | the corpus with the oracle's ends |
