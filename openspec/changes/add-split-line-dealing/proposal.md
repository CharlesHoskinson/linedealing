# Add split-line dealing

## Why

Split-line dealing (design/enhancement/DESIGN.md with DECISIONS 1 to 57) adds Fenrir co-custody to line dealing. The Fenrir committee holds one share of an address key, outside actors hold the other shards, and a Midnight authorization ledger decides when a spend may happen. The design is long prose. The Lean oracle (LOOP item 13) and the Quint model (LOOP item 14) need requirements that each can model on its own: state machines, value domains, refusals with codes, and invariants named by claim. This change states the design as EARS requirements, one capability per bounded context.

## What Changes

- New capability `split-request` (RQ-001 to RQ-068): the request state machine from post to settlement. It covers order, share check, open, contribution collection, admit, anchors, release, FINAL and VOID tombstones, expiry, stall, restart end and re-end, outcomes and settlement leaves.
- New capability `split-slots` (SL-001 to SL-030): committee Schnorr slot pools and per-address ECDSA account pools, with precedence by board order, ECDSA precedence from the authorization (DECISIONS 54), the reservation window, batched binds through seald Sessions, burns and `slot_anchor`.
- New capability `split-authorization` (AU-001 to AU-028): asset records and authorizations on Midnight. It covers sources per profile, Midnight-first and board-first in force, holds, revocation, settlement by root, carried VOIDs and the seizure destination.
- New capability `split-checkpoint` (CP-001 to CP-039): checkpoint fields and contract rules, one Midnight write per checkpoint (DECISIONS 52), seat logs, whole-committee restart classification and burns, restart settlement (DECISIONS 53), cold start, recovery and the replay floor.
- New capability `split-envelope` (EN-001 to EN-022): the one 16,384-byte frame, public checks before order, the layout block, threshold-PRF keys, contribution frames and fixed-size actor capsules.
- New capability `split-shard-holders` (SH-001 to SH-029): the access structure, address birth and its certificates, actor nonce pools, ECDSA leaf sets, the actor and initiator rules, and claims C1 to C5, C17 and C18.
- Architecture and Technical Decisions baseline under `specs/refinement/`: bounded contexts, aggregates, contracts, invariants for the 19 claims the specs cite (C1 to C13 and C16 to C21), questions Q-001 to Q-008, one D item per consumed DECISIONS entry, and a traceability map with every check planned.
- MADR fields (drivers, options, outcome and authority, consequences, confirmation, revisit) added under DECISIONS entries 8, 19 to 22, 27 to 29, 34 to 36, 38 and 40, which the requirements consume. The entry text stays as it was.

## Impact

- Specs: six new capabilities, 215 requirements. Nothing existing is modified.
- Decisions: DECISIONS 53 and 54 live only on branch `quint-split` (aa038fa). The specs follow them, and Q-004 asks for the merge.
- Code: none in this change. `impl/` is evidence only. Nine gaps between `impl/` and the specs are listed in `specs/refinement/architecture.md`. Item 11 adopts DECISIONS 54 in `impl/`.
- Formal work: item 13 (Lean oracle) and item 14 (Quint model) take these requirements as their source.
