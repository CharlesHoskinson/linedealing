# Work plan (owner AFK, 2026-11-14)

| # | Item | State |
|---|---|---|
| 1 | Protocol lanes (Fable, Astra, Carbon) | DONE: astra/, carbon/, fable/PROPOSAL.md |
| 2 | Veritee hardening lanes | DONE: hardening/*/HARDENING.md |
| 3 | Merged spec DESIGN.md (profiles P0/P1/P2, seizure optional) | DONE (55e23f1) |
| 3b | Multi-shard extension (DECISIONS 21-25): outside actors hold shards, Fenrir runs the MPC | RUNNING |
| 3c | Speed: lanes DONE; merged as DECISIONS 26-32; fold into DESIGN.md after 3b releases it | IN PROGRESS |
| 4 | Cross-family review of DESIGN.md (Astra, Carbon), fixes; §7.2 evidence classes fixed in 613b330 (0x02 NodeKeys, 0x03 BootClaim) | TODO after 3b, 3c |
| 5 | Veritee code: attest, verify, seald, os worktrees; OS integration lane DONE; integration merge in wt-merge RUNNING | RUNNING |
| 6 | Merge into veritee branch committee-signing-mode; docs/committee-signing-mode.md with recommendations; PR.md | TODO |
| 7 | Quint: impl/ conformance (worktree mpcexperiments-wt-quint) | RUNNING |
| 8 | Quint: Veritee committee mode model (boot tickets, peer witness, group seal, share repair, clone/rollback operator) + ITF conformance against seald/attest; every fixed finding gets a regression test in veritee-vm tests/quint-regressions/ (shrunk ITF trace replayed on the code + model run) | TODO after 6 |
| 9 | Quint: split-line dealing model, written from the OpenSpec + EARS (factory rule: never from the oracle); merged into 16 | TODO after 14 |
| 10 | Lean: split-line theorems + Natural Lean port + cleanup of the 103 | TODO after 4 |
| 11 | Paper draft paper-split/ | TODO after 4, 10 |
| 12 | Cross-family review of Veritee PR diff and paper; commit; no push | TODO |

## Software factory pipeline (owner 2026-11-14), ~/Projects/software-factory plugins/formal

| # | Item | State |
|---|---|---|
| 13 | Discovery prototype of split-line dealing (multi-shard, envelope, state machine, profiles) by extending impl/ | TODO after 4 |
| 14 | Extract OpenSpec capabilities + EARS from DESIGN.md and the prototype (skills/specs suite: architect, split, reconcile, assemble) into specs/ | TODO after 13 |
| 15 | Lean oracle per formal-oracle: one Lake package per capability, no Mathlib, St/init/valid/refusals/step/run, pins, theorems, Audit, `oracle` exe with kink-implementation/1 and --step | TODO after 14 |
| 16 | Quint check per formal-quint-check from spec only; quint_replay.py through the oracle | TODO after 14 |
| 17 | k-rust reference suite (KRUST_DIR=~/formal-kits/k-rust at UPSTREAM.md revision); kink compare, mutations, golden vectors | TODO after 15 |
| 18 | drwatt gates (requirements.json, checks.json), `dw verify` green | TODO after 15-17 |
| 19 | EARS skill: vet (Codex, Carbon), fix, upstream into drwatt on a local software-factory branch (EARS requirement + failing test first), no push | RUNNING |
