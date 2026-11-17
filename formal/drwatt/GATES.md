# Split-line pipeline gates

The stage gates of the formal pipeline for the OpenSpec change
`add-split-line-dealing`. Each gate is a drwatt requirement in the repo-root
`requirements.json` (IDs SLG-001 to SLG-026) whose check runs
`sh formal/drwatt/gate.sh GATE [ARG]` from the repo root. `checks.json` declares
the inputs of each check, so an edit to one stage leaves the gates of the other
stages fresh.

drwatt runs each check in a private copy of the repo without `.git`. Every gate
reads only files inside the repo. The tools come from `PATH`: `python3` with
PyYAML, `openspec`, `lake` (elan, Lean 4.35.0), `quint` 0.32.0 and `cargo`
(offline, from the local registry cache). Two helpers are vendored for this:
`scripts/ears_lint.py` (the EARS skill's lint) and `scripts/quint_replay.py`
(the formal plugin's replay driver). `specs/refinement/sources/quint-split-aa038fa/`
holds the two files of branch `quint-split` at aa038fa that the refinement check
reads; the check pins their git blob IDs.

The gates run cold in a copy: the Lean packages and the Rust crate build from
nothing. The timeouts come from a cold run of each gate in a fresh copy, with
margin. Run `dw verify` under `heavy-run` or `heavy-slot`; the gates do not call
`heavy-run` themselves.

## Specs

`gate.sh ears` lints the six capability specs with the EARS lint
(`--require-ids --strict`): 238 requirements, no defect and no warning.
`gate.sh openspec` runs `openspec validate add-split-line-dealing --strict`.
`gate.sh refinement` runs `specs/refinement/tools/check.py`, which checks the
baseline, the traceability and the DECISIONS entries that the specs consume
against the specs.

## Lean oracle

One Lake package per capability in `formal/lean-split/`: envelope, request,
slots, authorization, checkpoint, shard-holders, each depending on `codec/`.
`gate.sh oracle CAP` runs `formal/lean-split/gates.sh oracle CAP`. It builds
`codec/` and the package with `lake build --wfail`, which checks the theorems,
the pins and the axiom audit. Then it runs the word search for escape hatches,
the codec and refusal cases, the Spec mutants and the ambiguity ledger check.
Each Spec mutant builds in a copy of the package, and a pin or a theorem must
kill it.

`gate.sh trace CAP` checks that the requirement table of the package README
quotes each EARS sentence of its capability spec word for word.
`gate.sh ids` checks that the six tables hold every EARS ID of the specs, one row each.

## Quint spec model

`formal/quint-spec/splitspec.qnt` is the Quint model written from the specs.
`gate.sh quint-typecheck` typechecks the model and `splitspec_test.qnt`.
`gate.sh quint-test MODULE` runs the scripted schedules of one design test
module (test_tee_p2, test_nontee_p2, test_tee_p1) with `quint test`. It holds
only when every `run ...Test` of the module passes, so an empty match fails.
`gate.sh quint-kills` checks that every mutant instance `m_*` has a kill module
`test_m_*` and that each kill module passes. Each kill module runs a scripted
schedule that violates the mutated rule.

The long design runs of `formal/quint-spec/run_gate.sh` (tiers design, c11,
c20, mutants at random, traces) are not gates. They take hours of bounded
random simulation, with 10000 samples per instance and seed. Two of their tiers
report the expected findings F1, F2 and F5 as violations. Their record is
`formal/quint-spec/logs/ledger.tsv` and the README of the model.

## Prototype

The discovery prototype in `impl/`. `gate.sh impl-test` runs
`cargo test --offline --release -j 4`; the tests replay the ITF traces of
`tests/quint-regressions/` and `formal/quint/conformance/traces/`.
`gate.sh impl-clippy` runs `cargo clippy --offline --all-targets -j 4 -- -D warnings`.
`gate.sh impl-fmt` runs `cargo fmt --check`.

## Reference suite

`gate.sh reference-suite` runs, for each of the six capabilities (envelope,
authorization, shard-holders, checkpoint, slots, request),
`formal/krs-split/gates.sh oracle-equal CAP` and `formal/krs-split/gates.sh golden CAP`.
The first builds the Lean oracle of the capability and runs
`krs kink compare --only lean-oracle --locked`: every program of the locked corpus is
`equal`. The second checks that `golden/vectors.json` is current for the corpus.
Coverage and mutation runs (`gates.sh coverage` and `gates.sh mutations`) take hours and
stay outside `dw verify`; the lead reruns them when a definition or corpus changes.

## Replay

`gate.sh replay` builds the request, authorization, slots, envelope and
shard-holders oracles and runs `formal/lean-split/replay/replay.py` on the
committed traces of the Quint model (`formal/quint-spec/traces-sample/`). The
driver maps each model event to the operations of each oracle, threads each
oracle's own state in its own lane and compares that lane's projection after
every step: the requests, the asset record and its authorizations, the
committee slots, the EN-023 `order_check`, and the address record with a
network-created shard of SH-030 to SH-037 (`formal/lean-split/replay/README.md`).
The negative control must disagree at the named step: the kill schedule of
the mutant `stalled_after_release` at its tombstone (reason STALLED against
MIXED). The revision 3 F6 traces disagree by design and the gate leaves them
out. The gate holds only when every other trace agrees on every transition. It
reads no git state and does not call `heavy-run`. The regenerated full trace
sets (`run_gate.sh traces testtraces`, not committed) run through the same
driver by hand. With the oracles built the gate takes 22 s; the timeout is
300 s. The build of the five oracles in a fresh worktree took 4 min 26 s under
`heavy-run` (item 13c, queue time included). At the revision 6 model the gate holds; the
replay README lists the results and the disagreement classes of earlier
revisions.
