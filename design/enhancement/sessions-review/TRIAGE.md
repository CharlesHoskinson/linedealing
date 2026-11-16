# Sessions review triage

Inputs: `reviewer-a.md` (A, 23 findings) and `reviewer-b.md` (B, 17 findings, 25 rows after the split). B-F10, B-F15 and B-F17 are compound and get one verdict per part. The counting unit below is one row of the tables.

Verdicts: **admitted** (fixed in `design.md` and `spec.md` of `add-seald-sessions`), **admitted, claim** (the claim changes, not the protocol), **admitted, no spec change** (an implementation item, no requirement changes), **rejected**. "Owner decision, not changed" marks an argument against one of the four confirmed decisions. Severity is the reviewer's, then the triage severity where it differs.

Each verdict was checked against the bundle text and, for code claims, against `server/seald` at 8c8981b: `peer.rs` `check_requester` (no app-image check, `BootClaim` has no image field), `witness.rs` `refetch` (own seat only, aborts on one conflicting digest), `ledger_file.rs` `read` (a read error returns `None`, as an empty ledger does), `api.rs` (one thread per connection), `tpm.rs` (`cap` right after unseal), `docs/committee-mode.md` (unit `ReadWritePaths`, Phase 2 opens `/mnt/persist` after `seald` starts).

## Reviewer A

| ID | Severity | Verdict | Reason | Fix in spec |
|---|---|---|---|---|
| A-F1 | blocking → major | admitted, claim; owner decision 4 not changed | A rollback of every disk is outside the witness bound. It reopens erased entries inside the enclaves. Slot reuse stays blocked by the window burn, `slot_stale` and the monotone `h` of SS-103. G4 now states its bound. The argument against decision 4: a tier-0 `σ_i` lets a full-disk snapshot open old records after the epoch closed. | design G4, "Limits" |
| A-F2 | blocking | admitted | A blank-disk peer loses the entries it held for other seats. Sequential replacements erase the fence with no collusion. | SS-102 |
| A-F3 | blocking | admitted | A session with no record skips SS-068. All disks rolled back to a state before the session existed reuse a window slot. | SS-041, SS-068 |
| A-F4 | blocking | admitted | The checkpoint rule lived only in design prose. `h` had no retired-range meaning, and the anchored profile contradicted the rule. | SS-005, SS-103, SS-104, SS-105, SS-117 |
| A-F5 | blocking | admitted | A retried `slot_burn` after `no_quorum` returned success with no checkpoint. | SS-002 `dirty`, SS-058, SS-086, SS-118 |
| A-F6 | blocking | admitted | `close_epoch` looked only at the node's own sessions. Three nodes can strand a fourth seat. | SS-080 |
| A-F7 | blocking | admitted | Local records not yet witnessed were outside the epoch accounting and the rekey list. | SS-078, SS-080 |
| A-F8 | blocking | admitted | Restore re-witnessed `v_max` and could not pass a peer that held another digest of that version. | SS-027, SS-030 to SS-036 |
| A-F9 | blocking | admitted | An uncommitted highest version with no replica blocked restore of the committed version. | SS-031, SS-034 |
| A-F10 | blocking | admitted | A ledger read error looked like "no checkpoint" and skipped the burn. | SS-098, SS-106 |
| A-F11 | blocking | admitted | An anchored slot restored as `bound` never passed SS-055, which read only the witness log. | SS-055, SS-073, SS-119 |
| A-F12 | major | admitted | SS-070 returned success but left the index in `unsealed`. | SS-070 |
| A-F13 | blocking | admitted | One thread per connection. A checkpoint of one call cleared `unsealed` for a binding that its record did not hold. | SS-023, SS-107 |
| A-F14 | blocking → major | admitted, claim; owner decision 3 not changed | The requesting enclave holds `K_sess` for one operation. G5 now says what holds: `t` share holders must take part, and the key leaves RAM after the operation. The argument against decision 3: a symmetric key that one enclave rebuilds gives no threshold decryption. | design G5 |
| A-F15 | major | admitted | A re-ack did not restore a lost replica, and SS-038 and SS-039 both applied to a peer with `pv > 0` and no replica. | SS-026, SS-038, SS-039 |
| A-F16 | major | admitted | `slot` witness entries grow with no bound in tier 0. | SS-108, design "Sizing" |
| A-F17 | major | admitted | A legal session record can exceed the 1 MiB peer line. | SS-004, SS-109 |
| A-F18 | major | admitted, claim | `seald` caps PCR14 after unseal, so a restarted process cannot unseal `K_tpm`. G1 now says that a `seald` crash recovers through a VM reboot. | design G1, proposal |
| A-F19 | major | admitted, claim; owner decision 2 not changed | A request may name any unclaimed slot, so skipped indices below `h` are lost. The design now states that the app reserves in index order and that a skipped index is lost. The argument against decision 2: the loss bound is false for sparse reservations. | design "Reservation window" |
| A-F20 | major | admitted | Bind and mandatory burns grow `work` past `S_max`. | SS-002, SS-088 |
| A-F21 | blocking | admitted | SS-041 and SS-042 both applied to an open session with `v_max = 0`. | SS-041 |
| A-F22 | minor | admitted | Two design sentences disagreed with SS-009 and SS-021. | design "Keys" |
| A-F23 | major | admitted | Nothing told the app which requests a restart burn voided. | SS-036, SS-041 return `burned` |

## Reviewer B

| ID | Severity | Verdict | Reason | Fix in spec |
|---|---|---|---|---|
| B-F1 | blocking | admitted; owner decision 3 not changed | Without `K_tpm` in `K_sess`, the app image is the only gate on `session_get`. The peer policy does not pin PCR15, so one operator with a custom app disk reads every secret of its seat. Peers must check the app image before they serve a partial or a replica. This depends on guide recommendation 5 (TLS evidence out of PCR15). | SS-110 |
| B-F2 | blocking | admitted | One faulty peer reported a false high version. Restore witnessed the record before it authenticated it and overwrote the replicas on honest peers. | SS-030, SS-035, SS-036, SS-111 |
| B-F3 | blocking → major | admitted, claim | The bound of DESIGN §7.7 counts the restoring seat among the `c`. An honest seat with a blank disk is forgetful too, so it counts. The design now defines `c` that way. No formula changes. | design G2 |
| B-F4 | blocking | duplicate of A-F5 | Same retry defect, also for `session_destroy`. | SS-002, SS-058, SS-086, SS-118 |
| B-F5 | blocking | admitted (part A duplicates A-F11) | Part B: after a full rollback, a node with a stale `bound(d)` and a ledger anchor for `d'` released for `d`. | SS-055, SS-073, SS-092, SS-105, SS-119 |
| B-F6 | blocking | admitted | Path A: a checkpoint recorded the boot counter of a rolled-back seat before that seat synced, so later boots counted it continuous. Path B: `h` could go down. | SS-005, SS-103, SS-112, SS-117 |
| B-F7 | blocking → major | admitted | Part A: continuous nodes did not burn and stalled the pool. Part B: nodes latched different checkpoints. Safety holds through SS-103 and SS-064. The loss can pass one window, and G3 now says so. | SS-113, design G3 |
| B-F8 | blocking | duplicate of A-F8 | Also: `stale_version` returned `pv` and no requirement used it. | SS-027 |
| B-F9 | blocking | admitted in part | ECDSA slots are per address. A checkpoint `h` for them shows the account on Midnight, against DESIGN §4.1, and the window bricks old addresses. The window now applies to sequential pools only, and a bind in any pool needs a checkpoint. A node that classifies a whole-committee restart burns every account-pool slot once per boot. Open: a node that boots after the first checkpoint that follows the restart has no account-pool guard. The design Limits names the gap, and the board and DESIGN §7.11 must cover it. | SS-004, SS-005, SS-063 to SS-065, SS-114 |
| B-F10.1 | blocking | duplicate of A-F6 | | SS-080 |
| B-F10.2 | blocking | duplicate of A-F7 | | SS-078, SS-080 |
| B-F10.3 | major | admitted | `rekey` restored closed sessions with no `purpose` and overwrote an open working copy. | SS-078, SS-008 body holds `purpose` |
| B-F10.4 | major | admitted | `close_epoch` ran before the witness sync and on a fenced node. | SS-079, SS-080 |
| B-F11 | blocking → major | duplicate of A-F1; owner decision 4 not changed | Closed-epoch shares in a full-disk snapshot open old records. | design G4 |
| B-F12 | blocking → major | admitted | The unit makes `/mnt/persist` read-only for `seald`, and Phase 2 mounts it after `seald` starts. | SS-115, proposal "Impact" |
| B-F13 | major | duplicate of A-F16 | Byte counts in the report were not measured, so the design states no number. | SS-108 |
| B-F14 | major | duplicate of A-F15 | | SS-026, SS-038 |
| B-F15.1 | major | duplicate of A-F17 | | SS-109 |
| B-F15.2 | minor | admitted, no spec change | `PeerResponse` has no `pv` and maps `unavailable` to a refusal. SS-027, SS-095 and SS-101 already require the fields. This is a code task. | none |
| B-F15.3 | major | admitted | `refetch` stops at the first conflicting digest, so one faulty peer keeps the node `not_ready`. | SS-116 |
| B-F15.4 | major | duplicate of A-F18 | | design G1 |
| B-F16 | major | duplicate of A-F20 | | SS-088 |
| B-F17.1 | minor | admitted, no spec change | HKDF salt, HPKE context and signature labels belong to the golden vectors of the reference suite. | none |
| B-F17.2 | minor | admitted | SS-081 refused the existing tier-1 operations. | SS-081 |
| B-F17.3 | minor | admitted in part | Fixed: SS-020 lists every checkpoint caller, SS-041/SS-042/SS-093 take "no refusal applies", SS-057 removes the burned index from `unsealed`. Rejected: moving `bad_evidence` before `not_current` in SS-091, because the ticket check reads only the ledger and is cheaper. | SS-020, SS-041, SS-042, SS-057, SS-093 |

## Counts

| Verdict | Rows |
|---|---|
| admitted, protocol fix | 31 |
| admitted, claim change only | 5 (A-F1, A-F14, A-F18, A-F19, B-F3) |
| admitted, no spec change | 2 (B-F15.2, B-F17.1) |
| duplicate, fixed with its pair | 10 (B-F4, B-F8, B-F10.1, B-F10.2, B-F11, B-F13, B-F14, B-F15.1, B-F15.4, B-F16) |
| rejected | 0 rows, one part of B-F17.3 |
| total | 48 rows: 23 from A, 25 from B |

Distinct issues after merging duplicates: 38. Blocking after triage: 17 distinct issues (A-F2, A-F3, A-F4, A-F5, A-F6, A-F7, A-F8, A-F9, A-F10, A-F11, A-F13, A-F21, B-F1, B-F2, B-F5, B-F6, B-F9). Sixteen are fixed. B-F9 is fixed in part: the late-boot gap for account pools stays open and is named in the design Limits. Major after triage: 16 distinct issues, all fixed or restated as claims. Minor: 3 rows fixed, 2 rows left to code tasks.

## Owner decisions challenged, not changed

- **Decision 2** (A-F19): the loss bound is false for sparse reservations. Kept. The design states the allocation order and the hole loss.
- **Decision 3** (A-F14, B-F1): a `K_tpm`-free key lets one enclave rebuild the whole key, and an app image that peers do not check reads every secret. Kept. G5 is restated, and SS-110 makes peers check the app image.
- **Decision 4** (A-F1, B-F11): `σ_i` in tier 0 lets a full-disk snapshot open records after the epoch closed. Kept. G4 states its bound.

## Notes for other items

- DESIGN.md §7.7 states the bound `c ≤ n − 1 − 2f` with the restoring seat among the colluders. Its owner should add that a seat with a lost tier 0 counts among the `c` (B-F3).
- `tasks.md` names "SS-001 to SS-101" in tasks 1.1, 2.2 and several section-5 tasks. The new IDs SS-102 to SS-119 need rows in the section-5 code tasks. Tasks 1.1 and 2.2 now name SS-001 to SS-119.

## Decisions for MADR (item 27)

| Choice | Options weighed | Driver IDs | Confirmation |
|---|---|---|---|
| A blank-tier-0 peer rebuilds the entries it held for other seats from `w` peers before it serves acks or partials. | (a) peer-state sync at boot; (b) count every replaced peer as forgetful and shrink `c`; (c) anchor every version on Midnight. (a) keeps the bound and needs no chain write. | SS-102 | Quint: sequential peer replacement with no collusion never lowers the fence (QI-02). |
| The checkpoint contract enforces a monotone `h` per sequential pool, the restart jump and one anchor per slot key. | (a) contract rules; (b) `seald` checks the chain of checkpoints itself. (b) cannot stop a checkpoint that the app writes. | SS-103, SS-104, SS-105, SS-117 | Quint: wave rollback and late boot (QI-05, QI-06); mock-ledger tests. |
| A checkpoint records a seat's boot counter only from a `RestoreDone` statement signed by that boot. | (a) signed restore statement; (b) contract compares counters across two checkpoints only. (b) is the rule that the wave rollback of B-F6 passes. | SS-112, SS-117, SS-067 | Quint: B-F6 path A trace (QI-05). |
| Restore authenticates the record before any peer state changes, tries candidates from the highest version down, and seals the result as a new version. | (a) re-witness `v_max` as before; (b) authenticate, then seal `v_max + 1`; (c) commit certificates. (b) needs no new message and the PRF fence keeps the fallback safe. | SS-030 to SS-036, SS-111 | Quint: fallback never opens a version below a committed one with `c` in bound (QI-03); split-version liveness (QI-04). |
| Two digests of one version: the fence does not separate them, so restore takes the digest with the most signed reports, then the lower digest bytes. | (a) plurality, then byte order; (b) refuse `conflict` (deadlock of A-F8); (c) commit certificates. | SS-031, SS-032 | Quint: the committed digest wins when `c` is in bound (QI-04). |
| Sync reports carry the seat-signed witness statement. | (a) signed statements; (b) trust `f + 1` matching reports. (a) needs no count and stops a forged version from one peer. | SS-111 | Quint: one faulty peer cannot raise `v_max` (QI-03); unit test on the code. |
| Account pools (per-address ECDSA slots) have no window. A node that classifies a whole restart burns them once per boot, and the recovery group reprovisions unused slots under new indices. The late-boot gap stays open. This widens the restart loss beyond the two sets that decision 2 names, for account pools only. | (a) burn and reprovision through DESIGN §7.11; (b) per-address `h` on Midnight (shows the account); (c) board reconciliation in `seald`; (d) a `whole_restart` flag in `RestoreDone` that late nodes read. (d) would close the late-boot gap. | SS-004, SS-065, SS-114 | Quint: QI-07 and its late-boot counterexample. |
| Peers check the app image before they serve a session partial or a replica. | (a) pin PCR15 after recommendation 5; (b) add `K_tpm` back (against decision 3); (c) approved `app_root` list on the ledger checked against the ticket. | SS-110 | Test: evidence with another PCR15 value gets `bad_evidence`. |
| Session operations run one at a time per session. | (a) one lock per session; (b) per-binding version tags. (a) is simpler and the operations are short. | SS-107, SS-023 | Quint: interleaved bind and checkpoint never release an unsealed binding (QI-08). |
| A running node burns too when the ledger shows a whole-committee restart. | (a) every node evaluates the rule at each new checkpoint; (b) only booting nodes burn and the contract forces the jump. (b) stalls the pool. | SS-113 | Quint: three-node reboot liveness (QI-06). |
| `slot` witness entries below `cp.h` and not pending may be pruned. | (a) prune covered entries; (b) move the log off tier 0. (a) keeps tier 0 small with no new storage. | SS-108 | Quint: pruning never lets a second digest bind (QI-09). |
| Epoch close waits for every session that any seat holds in that epoch. | (a) refuse while any own or peer entry has the epoch; (b) committee barrier on the ledger. (a) uses state the node has. | SS-080 | Quint: no share erased while a session needs it (QI-10). |
