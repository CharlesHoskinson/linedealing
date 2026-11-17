# Tasks

## 1. Specification (LOOP item 12)

- [x] 1.1 Write the six capability specs with EARS requirements and stable IDs.
- [x] 1.2 Lint every spec with `ears_lint.py --require-ids --strict` and validate the change with `openspec validate --strict`.
- [x] 1.3 Add MADR fields under the consumed DECISIONS entries 8 to 40.
- [x] 1.4 Generate the baseline and the traceability map, and pass `specs/refinement/tools/check.py`.
- [ ] 1.5 Merge branch quint-split (DECISIONS 53, 54 and their DESIGN hunks) into main and close Q-004.
- [ ] 1.6 Settle Q-001 to Q-003 in DESIGN §4.1, §5.1 and §5.4. Q-007 is resolved (SH-023 form kept).
- [x] 1.7 Close Q-008 (re-end of a terminal request at a whole-committee restart) before item 13 freezes the transitions: RQ-068.

## 2. Lean oracle (LOOP item 13)

- [ ] 2.1 One Lean module per capability with the state, the domains and the transitions.
- [ ] 2.2 Every If-then requirement is a refusal that leaves the state unchanged and returns its code.
- [ ] 2.3 Theorems for the state invariants among C6, C9, C11, C12, C13, C16 and C20.

## 3. Quint model (LOOP item 14)

- [ ] 3.1 Model from the specs, not from the oracle, with one invariant per claim id.
- [ ] 3.2 Replay the ITF traces through the oracle's step mode.

## 4. impl/ (LOOP item 11 and later)

- [ ] 4.1 Close GAP-01 to GAP-09 of `specs/refinement/architecture.md`.
