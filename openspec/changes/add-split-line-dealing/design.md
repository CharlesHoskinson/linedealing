# Design: add split-line dealing

The architecture of this change is in [specs/refinement/architecture.md](../../../specs/refinement/architecture.md). The model is in [baseline.yaml](../../../specs/refinement/baseline.yaml) (BASE-001 revision 1) and the trace is in [traceability.yaml](../../../specs/refinement/traceability.yaml) (TRACE-001 revision 1). The decision records are the entries of [DECISIONS.md](../../../design/enhancement/DECISIONS.md), and D-NNN is entry NNN.

## Context

The design of record is [DESIGN.md](../../../design/enhancement/DESIGN.md) at main 4a20ccc. DECISIONS 53 and 54 and their DESIGN hunks come from branch `quint-split` (aa038fa) and are not merged yet. Where `impl/` and DESIGN disagree, DESIGN wins.

## Goals and non-goals

Goals: requirements that a Lean oracle and a Quint model can each take without reading the other, with one bounded context per capability, every refusal as an If-then requirement with a code and an unchanged state, and every security claim as an invariant with its claim id.

Non-goals: the cryptographic instantiation of `F_presig` and `F_mul` (O1, O2, O19), rotation (O5), the ticket proof circuit and the seald store. The specs name the interface that each one gives.

## Decisions

1. **One capability per bounded context.** Six contexts (request, slots, authorization, checkpoint, envelope, shard holders) each have their own vocabulary and their own consistency boundary. The seventh, seald Sessions, is external and is consumed through CON-004. Reason: the oracle and the model can then build one module per capability, and every cross-context rule becomes a contract with named requirements.
2. **D identity is the DECISIONS number.** The repository already keeps one MADR entry per numbered DECISIONS item. A separate D-001 series would add a second numbering. The consumed set is derived from the requirement text, and `check.py` fails when a D item is missing or extra.
3. **Entries 1 to 41 get MADR fields in place.** These entries predate the MADR convention. The fields go as indented bullets under each consumed entry and the entry text stays as it was, so record links stay stable.
4. **Provisional names for silent DESIGN text.** DESIGN names some VOID cases without a code and is silent on two ordering details. The specs use explicit values (MALFORMED, DEALER_FAULT, PIN_SPENT, RESTART; the completing post's reason; the wait for earlier headers) and mark them Q-001 to Q-003. The models need distinct values. No outcome depends on the choice.
5. **Symbols for unmeasured constants.** `B`, `B_slot` and `S_max` stay symbolic (Q-005). DESIGN §11 has no measured value for them.
6. **The actor's MAY is a free policy input.** DESIGN §4.2 lets an actor refuse a request. SH-023 states the refusal as a SHALL conditioned on the actor's own policy, and the models take that policy as a free input. That is the formal pipeline's MAY cell.
7. **Midnight writes are per checkpoint.** Every committee write is per checkpoint, epoch or boot (CP-005, DECISIONS 52, owner ruling). Item data lives on the board under per-checkpoint roots.

## Risks and trade-offs

- quint-split not merged: the specs are ahead of DESIGN on main for ECDSA precedence and restart settlement. Q-004 keeps D-053 and D-054 provisional until the merge.
- `impl/` lags the specs on restart, recovery, seat logs and batched roots. The gaps are listed in the architecture note, and the oracle, not `impl/`, is the reference for item 14.

## Checks

Run from the repository root:

```bash
python3 -I ~/.claude/skills/ears/scripts/ears_lint.py --require-ids --strict -q openspec/changes/add-split-line-dealing/specs/*/spec.md
openspec validate add-split-line-dealing --strict
python3 -I specs/refinement/tools/gen.py . && python3 -I specs/refinement/tools/check.py .
```
