# k-rust reference suite for split-line dealing (LOOP items 15 and 15b)

The reference-suite stage of the software-factory formal pipeline (spec and EARS,
Lean oracle, Quint check, k-rust reference suite) for the six capabilities of
`openspec/changes/add-split-line-dealing`. Each Lean oracle package of
`../lean-split/` is ported to one KRS definition here. kink grows a corpus of typed
cases until coverage has no open obligation and every mutation is killed or argued,
and `krs kink compare` checks the definition against the oracle on every case. Golden
vectors come from the oracle only after that comparison is `equal` on every case.

k-rust at `8aaaac1c1cfd88a50fa58115030b3f28f43f67bf` (the software-factory
`plugins/formal/UPSTREAM.md` pin), `krs` built from `$KRUST_DIR` (default
`~/formal-kits/k-rust`).

| Directory | Capability | Lean oracle | KRS package |
|---|---|---|---|
| `envelope/` | split-envelope (EN) | `../lean-split/envelope` | `split-envelope-reference` |
| `request/` | split-request (RQ) | `../lean-split/request` | `split-request-reference` |
| `slots/` | split-slots (SL) | `../lean-split/slots` | `split-slots-reference` |
| `authorization/` | split-authorization (AU) | `../lean-split/authorization` | `split-authorization-reference` |
| `checkpoint/` | split-checkpoint (CP) | `../lean-split/checkpoint` | `split-checkpoint-reference` |
| `shard-holders/` | split-shard-holders (SH) | `../lean-split/shard-holders` | `split-shard-holders-reference` |

Each capability directory holds:

* `src/lib.rs`: the KRS definition. Cells are the oracle's `St` fields by name, plus
  `obs` (the oracle's observation list), `ops` (the operations still to run, empty at
  every end) and `k`. The `#[k::init]` parameters are the oracle's inputs by name.
  One rule per behaviour of the oracle's `apply`: each operation passes its refusal
  check and runs, or is refused with the codes in code order and leaves the state
  unchanged. Refusals are observable answers, so they are rules with cases and
  mutations, not `could-not-apply`.
* `schema.json`: the type schema the adapter translates by.
* `kink/FLOW.toml`, `kink/cases/`, `kink/mutations/`,
  `kink/definition.k` (emitted), `kink/kink.lock`.
* `gaps.toml`: the EARS IDs no rule stands for (wallet rules, cryptographic
  exceptions, proved theorems), each with the check that covers it.
* `golden/vectors.json`: the exportable cases with the oracle's end.

## The adapter

kink sends a case's inputs in the KRS typed encoding (`{"Submit": {"e": {"Env":
{...}}}}`) and reads the end's cells by Rust path. The Lean oracles read and write
their own JSON (`{"op": "submit", "envelope": {...}}`, an answer `{"state": {...},
"obs": [...]}`). `scripts/oracle_adapter.py` translates between the two by the
capability's `schema.json` alone: it holds no spec logic and no default, refuses
every key and constructor the schema does not name (exit 2), and flattens the answer's
`state` into one cell per state field. The `[[implementation]]` of each flow runs the
oracle through it. It declares no `identity`, because the answers depend on the
adapter, the schema and the oracle binary together, so kink caches no answer.

## Oracle revision

The suites follow the oracles of `../lean-split/` at the 237-requirement spec (DECISIONS
59 to 71). The areas that item 15 held apart for the revision of DECISIONS 59 to 63 are
settled and ported, and nothing is held:

* request: the RELEASE record (RQ-030, RQ-050, RQ-051; the send record is the node rule
  RQ-069) and the MIXED reason by f + 1 VOID posts (RQ-045, RQ-072 to RQ-074);
* authorization: a VOID settlement on a LOCKED record keeps the lock (AU-029, DECISIONS 60);
* envelope: the refusal `exp_c_not_below_exp` (EN-023) at acceptance and for the ordering
  block (`order_check`);
* slots: the state-driven lapse (SL-005, SL-010, DECISIONS 63).

Every case is under `kink/cases/` and is exported as a golden vector.

| Capability | Programs equal | Mutations killed / argued | Coverage open | Golden vectors |
|---|---|---|---|---|
| envelope | 87 | 128 / 2 | 0 | 87 |
| request | 169 | 323 / 3 | 0 | 169 |
| slots | 39 | 251 / 16 | 0 | 39 |
| authorization | 59 | 267 / 0 | 0 | 59 |
| checkpoint | 79 | 335 / 6 | 0 | 79 |
| shard-holders | 89 | 323 / 0 | 0 | 89 |

## Gates

Run from the repository root under `heavy-run`:

    heavy-run --mem 16G -- sh formal/krs-split/gates.sh all CAP

| Gate | Holds when |
|---|---|
| `emit CAP` | `kink/definition.k` is the K the definition emits |
| `coverage CAP` | the lock is current and the coverage JSON says 0 open (MC/DC on) |
| `mutations CAP` | the lock is current; every mutation has `expect`; every survivor has `expect = "survive"` and its argument; no rule is untargeted; every EARS ID is named by a mutation or listed in `gaps.toml` (`scripts/check_mutations.py`) |
| `oracle-equal CAP` | `compare --only lean-oracle --locked`: every row `equal` |
| `golden CAP` | `golden/vectors.json` is current (`GOLDEN_WRITE=1` writes it) |

`scripts/krs-in.sh CAP KRS-ARGS` runs one `krs` command in a capability directory
under `heavy-run`, after writing the facade patch `.cargo/config.toml` (not
committed). `scripts/mkcase.py` writes case documents from oracle-form inputs.
