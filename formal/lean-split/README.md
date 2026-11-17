# Lean oracle for split-line dealing (LOOP item 13)

The Lean oracle stage of the software-factory formal pipeline (spec and EARS,
Lean oracle, Quint check, k-rust reference suite) for the OpenSpec change
`openspec/changes/add-split-line-dealing`. Each capability is one Lake package
with an executable `oracle` (`kink-implementation/1` and `--step` JSON Lines)
and theorems for the invariants of `specs/refinement/baseline.yaml`, named by
claim ID. The oracle comes from the spec sentences
(`openspec/changes/add-split-line-dealing/specs/`) and the refinement baseline
only. No Quint model was read.

Lean 4.35.0, no Mathlib. Only the axioms `propext`, `Classical.choice` and
`Quot.sound` occur. No module holds `sorry`.

| Package | Capability | IDs | Namespace |
|---|---|---|---|
| `codec/` | the shared JSON codec (strict integers, exact keys, duplicate keys, 8 MiB lines), the oracle main loop, `#audit_ns` | | `SplitCodec` |
| `envelope/` | split-envelope | EN-001 to EN-023 | `SplitEnvelope` |
| `request/` | split-request | RQ-001 to RQ-076 (no RQ-070) | `SplitRequest` |
| `slots/` | split-slots | SL-001 to SL-030 | `SplitSlots` |
| `authorization/` | split-authorization | AU-001 to AU-029 | `SplitAuthorization` |
| `checkpoint/` | split-checkpoint | CP-001 to CP-043 | `SplitCheckpoint` |
| `shard-holders/` | split-shard-holders | SH-001 to SH-038 | `SplitShardHolders` |
| `handoff/` | split-handoff | HO-001 to HO-068 | `SplitHandoff` |

Each package README has the modes, the refusal codes, the interpretation
rows, the requirement table (every ID, its sentence word for word, the Lean
names, the state) and the claims. Each package has an ambiguity ledger; every
entry is `held` (a reading applied until a ruling replaces it) or `ruled`.

## Gates

Run from this directory under `heavy-run` (each mutant builds a copy of a
package):

    heavy-run --mem 16G -- sh gates.sh oracle CAP   # build --wfail, words, cases, mutants, ledger
    sh gates.sh trace CAP                           # the README table equals the spec sentences
    heavy-run --mem 16G -- sh gates.sh all          # every package, then every EARS ID once

`scripts/`: `gen_audit.py` (writes each `Audit.lean`), `req_table.py` (the
requirement tables), `oracle_checks.py` (words, cases, mutants, ledger),
`count_ids.py` (every EARS ID of the specs, once, over the six tables).

## Claims

The state parts of the claims. The cryptographic parts (DLEQ and
Chaum-Pedersen soundness, AEAD hiding, PRF independence, threshold signature
unforgeability) are outside the oracles and are named as exceptions.

| Claim | Rule (baseline) | Theorems |
|---|---|---|
| C1 | address binding | `SplitShardHolders.C1_run_records_certified` (SH-009, SH-011); `SplitShardHolders.sh037_run_acked_certified` (SH-033, SH-037: a network-created shard is acked only with `q` ACK_OK, DECISIONS 67) |
| C2 | birth proof of possession | `SplitShardHolders.C2_birthOk_from_check` (SH-009) |
| C3 | sealed user half | exception: SH-027 (signature scheme) |
| C4 | no spend without an admitted signing set | `SplitShardHolders.C17_admitted_satisfies` (state part); exception: SH-027 (signature scheme) |
| C5 | no spend without the committee | exception: SH-028 |
| C6 | authorization enforcement | `SplitRequest.C6_release_in_force` (RQ-024, RQ-030), `SplitAuthorization.C6_no_force_without_finalize` (AU-010), `SplitSlots.C13_ecdsa_prec_in_force` (ECDSA reservations in force) |
| C7 | hold enforcement (P2) | `SplitRequest.C7_no_release_after_revocation` (RQ-032, RQ-059), `SplitRequest.C7_hold_p2` (RQ-033) |
| C8 | sealed until order | `SplitRequest.C8_sealed_until_order` (RQ-008) |
| C9 | unselected variants stay sealed | `SplitEnvelope.C9_run_dd_unique` (EN-008), `SplitRequest.C9_release_only_anchor` (RQ-030, RQ-058) |
| C10 | blindness | `SplitEnvelope.C10_public_checks_blind` (EN-002, EN-022) |
| C11 | one spend per record state | `SplitAuthorization.C11_one_final`, `C11_nf_once`, `C11_released_never_fresh`, `C11_bf_first_only`, `C11_pinned_never_unspent` (AU-008, AU-015, AU-016, AU-024, AU-025, AU-029); `SplitRequest.C11_released_never_void`, `C11_held_leaf_stable` (RQ-051, RQ-052, RQ-054) |
| C12 | one nonce use | `SplitSlots.C12_run_one_ticket` (SL-021, SL-027 seat part) |
| C13 | liveness | exception: RQ-063 (not a state property; Quint, item 14); witness `SplitRequest.witness_C13_final`; state part `SplitSlots.C13_ecdsa_burn_only_if_reserved` (SL-028: an ECDSA slot burns only at the end of its reserver), `SplitSlots.C13_run_lapsed_burned` (SL-005, SL-010: a slot under a lapsed precedence is BURNED, also when its header opened after the lapse) |
| C16 | cold start | `SplitCheckpoint.C16_run_window_burned`, `C16_restart_burns_range`, `C16_acct_burned`, `C16_session_burned`, `C16_bounded_loss` (CP-020, CP-021, CP-023, CP-024, CP-038, CP-039) |
| C17 | unadmitted coalitions cannot sign | `SplitShardHolders.C17_run_charters_valid`, `C17_admitted_satisfies`, `C17_contribution_admitted` (SH-002, SH-003, SH-022) |
| C18 | sealed confinement per actor | exception: SH-029 |
| C19 | no concurrent-session forgery | exception: SH-029; state part `SplitShardHolders.sh038_cl_fixes_weight` (SH-038: one commitment list fixes every weight, DECISIONS 72) |
| C20 | reissue safety | `SplitRequest.C20_no_release_before_admission` (RQ-057), `SplitRequest.C20_stalled_releases_nothing` (RQ-047), `SplitRequest.rq073_no_stalled_after_release` (RQ-073) |
| C21 | actor identity hiding before release | `SplitEnvelope.C21_run_blind` (EN-002, EN-018, EN-022) |

## Findings for the spec owner

* **AU-023 against D-047** (split-authorization ledger 11, ruled by AU-029 at
  spec revision 4). A record locked to a pin stays LOCKED after a VOID
  settlement of the pinned re-post, so a later authorization spends only that
  input (`SplitAuthorization.pin_au029_locked_void`,
  `C11_pinned_never_unspent`).
