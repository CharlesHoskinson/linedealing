# Adversarial Protocol & Cryptographic Review: `seald` Sessions

## Findings

### F1 — Single operator extracts all session secrets via an unpinned-PCR15 replacement VM
- **Severity:** blocking (decision challenge: Decision 3)
- **Location:** [design.md](bundle/change/design.md) §Keys, §Decisions (Decision 3); [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-007, SS-012, SS-013, SS-014, SS-015, SS-038; [committee-signing-mode.md](bundle/docs/committee-signing-mode.md) §`/run/veritee/peer-policy.json`, §Limits, Recommendation 5; [committee-mode.md](bundle/docs/committee-mode.md) §PCR14; [peer.rs](bundle/seald/src/peer.rs) (`check_requester`)
- **Claim affected:** G5, Decision 3, consistency with current code and docs (Check 9)
- **Failure scenario:**
  1. Seat `0` runs in epoch `1` with session `purpose = "keys"` at `v = 4`, holding Class S (`x_f` share, Schnorr/ECDSA slot shares) and Class L (`NodeKeys` private keys, provisioning key) secrets, replicated to peers `1..8` (`pv = 4`).
  2. Operator `0` alone (`c = 1` malicious operator, `0` broken enclaves) packages a custom app disk whose `metadata.json` keeps the exact same `{"committee":{"id":C,"n":9,"t":7,"f":2,"w":6}}` and replaces the app container with a script that calls `session_open`, `session_get`, and `slot_get` on `/run/veritee/seald.sock` and prints the outputs.
  3. Operator `0` boots a replacement VM for seat `0` with the approved base OS image and the custom app disk, and submits seat `0`'s new boot ticket (`boot_counter = 2`) with seat `0`'s operator key.
  4. In the replacement VM, `measured-setup` extends PCR14 with `role_digest` over `{"committee":C,"f":2,"n":9,"role":"committee-node","t":7,"version":1,"w":6}` and `seald` caps PCR14. Both PCR4 and runtime PCR14 match `/run/veritee/peer-policy.json` on peers `1..8` bit-for-bit; PCR15 is not in `peer-policy.json`, `BootClaim` carries no `app_root`, and peers do not check `BootTicket.app_root` ([committee-signing-mode.md](bundle/docs/committee-signing-mode.md#L658-L659)).
  5. Previously, tier 1 (`K_seal = HKDF(K_tpm ‖ K_grp ‖ ratchet)`) defeated this attack because `K_tpm` is vTPM-sealed under `PolicyPCR(4, 14, 15)`. Decision 3 (`SS-007`) removes `K_tpm` from `K_sess` and replicates ciphertext via `session_fetch` (`SS-038`). Honest peers `1..6` verify seat `0`'s class `0x03` evidence (`SS-013`), repair `σ_0`, return `replica` and `6` `session_partial` values (`SS-012`), and `seald` opens `v = 4` and serves all Class S and Class L secrets in cleartext to Operator `0`'s container—violating G5 ("No operator ... holds a key that opens a session alone") and decrypting historical wallet `SealedToNode` traffic.
- **Fix:** Do not ship `K_tpm`-free session keys until peer verification pins the approved app image (and new committee parameters):
  > **SS-013a** The PCR14 committee role descriptor and `/run/veritee/peer-policy.json` SHALL bind the approved `application_root_hash` (measured before per-node TLS extensions, which move to a separate PCR), `session_window`, and `anchor_before_release`, and `SS-013` SHALL refuse `bad_evidence` when the attested image root is not approved.

---

### F2 — One Byzantine peer (`1 ≤ f`) permanently destroys a rebooting node's session because `SS-035` witnesses before `SS-036` authenticates
- **Severity:** blocking
- **Location:** [design.md](bundle/change/design.md) §Versions and the witness fence; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-016, SS-025, SS-030, SS-031, SS-033, SS-034, SS-035, SS-036, SS-037
- **Claim affected:** G1, the witness fence (Check 2), replication (Check 6)
- **Failure scenario:**
  1. Committee `n = 9, f = 2, t = 7, w = 6`. Seat `0` has a valid session at `v = 7, epoch = 1` (`pd = D7`) stored on honest peers `2..8`. Peer `1` is faulty (`1 ≤ f = 2`).
  2. Seat `0` reboots (`boot_counter = 2`, with a blank or intact disk) and runs `sync_witness` (`SS-030`). Honest peers `2..6` report `(pv = 7, pe = 1, pd = D7)`, while faulty peer `1` returns a signed `WitnessLog` reporting `(pv = 999999, pe = 1, pd = SHA-256(R_bad))`, where `R_bad` is a clear header `(sid, 999999, 0, 1)` concatenated with 64 random bytes.
  3. By `SS-030`, seat `0` sets `v_max = 999999`. On `session_open`, `SS-031` selects `SHA-256(R_bad)` (the sole digest reported for `999999`), and `SS-033` fetches `R_bad` from peer `1` and accepts it because `SHA-256(R_bad)` matches.
  4. By `SS-035`—which runs *before* `SS-036` derives `K_sess` or checks AEAD authentication—seat `0` signs `session_witness(0, sid, 999999, 1, R_bad)` with its current boot key and sends it to peers `1..8`.
  5. Honest peers `2..8` verify seat `0`'s current boot signature and header (`SS-028`, `SS-029`), see `999999 > 7`, and execute `SS-025`: each overwrites `replica` on `/mnt/persist` with `R_bad` ("so the record of the earlier version is gone") and sets `pv = 999999` in tier 0.
  6. Seat `0` now reaches `SS-036` and `SS-037`: decryption of `R_bad` under `K_sess(1, 999999)` fails authentication, returning `corrupt`. Version `7` is now gone from peer replicas and fenced forever on every honest peer (`7 < pv = 999999` -> `stale_version` under `SS-016`), permanently destroying seat `0`'s keys and shares. (If peer `1` instead refuses `session_fetch` with `not_found`, `SS-034` permanently stalls `session_open` with `record_unavailable`.)
- **Fix:** Authenticate and decrypt the candidate record under `K_sess` *before* re-witnessing, and fall back to lower versions when an uncorroborated candidate (`≤ f` peers) is unavailable or corrupt:
  > **SS-035 (revised)** When the seald service restores a session with `v_max > 0`, it SHALL try candidate `(u, d)` pairs from the witness sync and local records in descending order of `u` (and descending peer count on ties): fetch the record matching `d` (`SS-033`), derive `K_sess` for `(u, epoch)` (`SS-009`), and verify and decrypt the record (`SS-036`). Only after decryption succeeds SHALL the seald service seal and witness `work` (at version `v_max + 1`, see F8) and require `w` acks before setting `open = true`. A candidate `(u, d)` reported by at most `f` peers that fails `SS-034` or `SS-037` SHALL be discarded in favor of the next candidate; only if `f + 1` or more peers reported `(u, d)` SHALL `SS-034` or `SS-037` abort `session_open`.

---

### F3 — Blank-disk replacement VM under `c = n − 1 − 2f` forgetful peers reopens burned state and allows nonce-slot reuse
- **Severity:** blocking
- **Location:** [design.md](bundle/change/design.md) §Goals (G1, G2, G4), §Versions and the witness fence; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-012, SS-016, SS-030, SS-035, SS-036, SS-050; [split-line/DESIGN.md](bundle/split-line/DESIGN.md#L854) §7.7
- **Claim affected:** G2, G4, the witness fence (Check 2), slot binding (Check 3), replication (Check 6)
- **Failure scenario:**
  1. Parameters `n = 9, f = 2, t = 7, w = 6`, stated witness collusion bound `c ≤ n − 1 − 2f = 4`. Colluding operators control seats `{1, 2, 3, 4}` (`c = 4`); seat `0` is honest.
  2. At `cp1` (`h = 1000`), seat `0` has `v = 7` (`1100` is `free(share)`, `"old_secret"` present). Seat `0` binds slot `1100` to `H(tk_1)` (`SS-050`, `SS-051`) and destroys `"old_secret"` (`SS-046`) in `v = 8`, receiving `w = 6` acks for both the `slot` entry and `v = 8` from peers `{1, 2, 3, 4, 5, 6}` while honest peers `{7, 8}` are slow (`pv = 7`, no `slot` entry for `1100`). Seat `0` releases its signature partial on `tk_1`.
  3. Colluding peer operators `{1, 2, 3, 4}` roll back their disks to `pv = 7` (wiping the `slot` entry for `1100` and `v = 8`) and reboot one pair at a time so `whole_restart = false`.
  4. Honest seat `0` undergoes a normal app-disk upgrade or host replacement onto a blank disk ([committee-signing-mode.md](bundle/docs/committee-signing-mode.md#L452)) while `{5, 6}` are slow.
  5. Seat `0` runs `sync_witness` (`SS-030`), receiving `w = 6` replies from `{1, 2, 3, 4, 7, 8}`: all 6 report `pv = 7` and no `slot` entry for `1100`. Seat `0` repairs `σ_0`, fetches `R7` from peer `7`, collects `6` partials for `v = 7` from `{1, 2, 3, 4, 7, 8}` plus its own (`1 + 6 = 7 = t`), and opens `v = 7`.
  6. `"old_secret"` is live again (breaking G4), and slot `1100` is `free(share)` with no witness entry; if `{1, 2, 3, 4}` also rolled back board state before `cp2`, `{0, 1, 2, 3, 7, 8}` (`q = 6` enclaves) have no record of `tk_1`'s request and admit a second request on `1100` for `tk_2 ≠ tk_1`, causing seat `0` to release a second partial on `1100` (breaking G2).
  - *Root cause:* [split-line/DESIGN.md](bundle/split-line/DESIGN.md#L854) §7.7 proved `c ≤ n − 1 − 2f` assuming the recovering node is *itself* one of the `c` colluders, leaving `≤ c − 1 = 3` forgetful peers among its `8` peers. A benign blank-disk VM replacement makes seat `0` forgetful *without* operator `0` colluding, allowing all `c = 4` colluders to sit in the `2w − (n − 1) = 4` peer intersection.
- **Fix:** Either change G2/G4's collusion bound in the presence of blank-disk seat replacements to `c ≤ n − 2 − 2f` (`3` at launch), or anchor planned/replacement seat handovers on Midnight:
  > **SS-030a** When a VM boots with no tier-0 state (a blank `seal` partition), the Midnight replacement ticket for that seat SHALL record the retiring enclave's `(sid, v, pd)` digest (or `w + 1` peer witness digests), or the committee collusion bound while blank-disk replacements are unanchored is `c ≤ n − 2 − 2f`.

---

### F4 — `slot_burn` and `session_destroy` silently skip checkpointing or fail `not_found` on retry after `no_quorum`, resurrecting erased shares on reboot
- **Severity:** blocking
- **Location:** [design.md](bundle/change/design.md) §Versions and the witness fence, §API; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-024, SS-046, SS-057, SS-058, SS-086
- **Claim affected:** G4, SS-046, SS-057, SS-058
- **Failure scenario:**
  1. Seat `0` has an open session at `v = 8` (replicated to all peers `1..8`), where slot `120` is `bound(share, d)` and `work.entries["k"]` holds a retired key share.
  2. *`slot_burn` path:* Request ends `FINAL` and the app calls `slot_burn(sid, 120)` (`SS-057`). `seald` sets `work.slots[120] = burned`, zeroizes `share` in RAM, seals `v = 9`, receives only `5 < w = 6` acks due to a transient blip, and returns `{"ok":false,"error":"no_quorum"}`. Per `SS-024`, `v` stays `8` (peers remain at `pv = 8`), and `work` keeps `work.slots[120] = burned`.
  3. The app retries `slot_burn(sid, 120)`. Because `work.slots[120]` is already `burned`, `SS-058` fires and returns `{"ok":true,"v":8}` *without* checkpointing! Thinking erasure succeeded durably, the app continues; when seat `0` later reboots, `SS-036` restores `v = 8` from peers, reopening slot `120` as `bound(share, d)` with its full `share` intact (violating G4 and [design.md](bundle/change/design.md#L98)).
  4. *`session_destroy` path:* Identically, if `session_destroy(sid, "k")` (`SS-046`) gets `no_quorum`, `SS-024` keeps `"k"` removed from `work.entries` with `v = 8`. Retrying `session_destroy(sid, "k")` returns `not_found` (`SS-086`) without advancing `v`, and a reboot restores `"k"` from `v = 8`.
- **Fix:** Track uncommitted erasures (comparable to `unsealed` for binds) or require `SS-058` / `SS-046` to confirm durability at `v`:
  > **SS-002 / SS-023 / SS-046 / SS-058 (revised)** Keep a boolean `uncheckpointed_erasure` on each open session, set to `true` whenever `session_destroy` (`SS-046`) or `slot_burn` (`SS-057`) mutates `work`, and cleared to `false` only when a version reaches `w` acks (`SS-023`). While `uncheckpointed_erasure` is `true`, `slot_burn` on a `burned` slot (`SS-058`) and `session_destroy` on an absent name (`SS-086`) SHALL return success only with `w` acks for a checkpoint of `work`.

---

### F5 — `anchor_before_release` breaks both liveness after rollback (`SS-073` vs `SS-055`/`SS-093`) and single-ticket safety under operator rollback (`SS-055`/`SS-073`/`SS-092`)
- **Severity:** blocking
- **Location:** [design.md](bundle/change/design.md) §Reservation window and whole-committee restart; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-055, SS-070, SS-071, SS-072, SS-073, SS-092, SS-093
- **Claim affected:** G1, G2, G3, slot binding (Check 3), window burn and restart (Checks 4 & 5)
- **Failure scenario:** Charter sets `anchor_before_release = true` (intended to keep slot binding safe against any number of colluding operators, [split-line/DESIGN.md](bundle/split-line/DESIGN.md#L860) §7.7).
  - *Scenario A (Honest liveness break after whole-committee rollback):* Seat `0` binds slot `1100` to `H(tk_1)` at `v = 8` and anchors `(C, 0, purpose, 1100, H(tk_1))` on Midnight. All 9 disks roll back to `v = 7` (where `1100` is `free(share)` and no tier-0 witness log has `1100`) and reboot (`whole_restart = true`). In `session_open`, `SS-036` sets `unsealed = ∅` and `SS-073` sets `work.slots[1100] = bound(share, H(tk_1))` *without* writing `(0, purpose, 1100) → H(tk_1)` to seat `0`'s witness log and *without* checkpointing. When the app calls `slot_release_ok(sid, 1100, H(tk_1))`, `SS-055` fails because `(0, purpose, 1100)` is missing from the witness log (`SS-056` returns `release = false`). If the app calls `slot_bind(sid, 1100, H(tk_1))`, `SS-093` sees `bound(share, H(tk_1))` and `1100 ∉ unsealed` and returns `ok: true` with no state change—so `slot_release_ok` returns `false` forever, contradicting [design.md](bundle/change/design.md#L79) ("voids nothing").
  - *Scenario B (Double signature partial release under `c = 9` operator rollback):*
    1. Seat `0` runs `slot_bind(sid, 120, H(tk_1))`: witnesses `slot` `120 → H(tk_1)`, checkpoints `v = 8` (`bound(share, H(tk_1))`), appends `(C, 0, purpose, 120, H(tk_1))` to `outbox.jsonl` (`SS-070`), and returns `anchor_pending` (`SS-071`). Operator `0` drops the outbox submission and snapshots all 9 disks as `SNAP_1`.
    2. All 9 operators roll back disks to `v = 7` (`120` is `free`), reboot, bind slot `120` to `H(tk_2) ≠ H(tk_1)`, let `(C, 0, purpose, 120, H(tk_2))` finalize on Midnight, and release seat `0`'s partial for `tk_2`.
    3. All 9 operators restore `SNAP_1` (`v = 8`, `work.slots[120] = bound(share, H(tk_1))`, witness logs hold `H(tk_1)`) and reboot. First, neither `design.md` nor `spec.md` states a Midnight contract rule forbidding a second anchor `(C, 0, purpose, 120, H(tk_1))` from `SNAP_1`'s outbox; second, even with one anchor per slot, `SS-073` touches `free` slots only (skipping `120`), `SS-092` ("whose anchor record is not in the ledger") does not specify digest matching or conflict refusal, `SS-093` lacks `"and no refusal applies"` (overriding `SS-072`), and `SS-055` (`slot_release_ok`) never checks the ledger anchor—returning `release = true` for `H(tk_1)` and leaking seat `0`'s key share!
- **Fix:**
  1. Add a contract rule to `design.md`: Midnight accepts at most one anchor record per `(committee, node_index, purpose, slot)`, signed by the current boot key of `node_index`.
  2. Strengthen `SS-055`, `SS-073`, and `SS-092`:
  > **SS-055 (addition)** Where the charter sets `anchor_before_release`, `slot_release_ok` SHALL also require the ledger to hold `(committee, node_index, purpose, slot, d)`.
  > **SS-073 (revised)** Where the charter sets `anchor_before_release`, when the seald service restores a session (whether `whole_restart` is `true` or `false`), for each anchor `(committee, node_index, purpose, slot, d)` in the ledger: if `work.slots[slot]` is `bound(_, d')` with `d' ≠ d`, `session_open` SHALL fail with `conflict`; if `work.slots[slot]` is `free(share)` or `bound(share, d)`, the seald service SHALL record `(node_index, purpose, slot) → d` in its own witness log and set `work.slots[slot] = bound(share, d)`, and if `work` changed, open only with `w` acks for a checkpoint.
  > **SS-092 (revised)** Where the charter sets `anchor_before_release`, when the seald service restores a session, it SHALL add to `unsealed` each `bound(share, d)` index for which the ledger holds no anchor record `(committee, node_index, purpose, index, d)` (refusing `session_open` with `conflict` if the ledger holds `d' ≠ d`).

---

### F6 — Staggered 2-seat rollbacks across checkpoints launder unsynced boot counters and bypass `SS-067` and the `cp2` contract rule; normal checkpoints also lack `cp2.h ≥ cp1.h`
- **Severity:** blocking
- **Location:** [design.md](bundle/change/design.md) §Reservation window and whole-committee restart; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-005, SS-064, SS-067, SS-068
- **Claim affected:** G3, window burn (Check 4), whole-committee restart from rolled-back disks (Check 5)
- **Failure scenario:** Two concrete nonce-reuse paths (`n = 9, f = 2, q = 6, t = 7, w = 6, B = 200`):
  - *Path A (Wave rollback with `f = 2` Byzantine nodes):* At `cp1`, `cp1.h = 1000, cp1.pending = ∅, cp1.boot_counters = [1..1]`, and disk snapshot `SNAP_0` is at `v = 5` (`1150` is `free(share)`). Seats `{7, 8}` are Byzantine (`|C| = f = 2`).
    1. Honest seats `{0, 1}` reboot from `SNAP_0`, post `boot_counter = 2` on Midnight, and their operators pause their peer sockets *before* `sync_witness` (`SS-067`).
    2. Live seats `{2..8}` post `cp_A` (`h = 1000`, `boot_counters = [2,2,1,1,1,1,1,1,1]`). Since `7 ≥ w + 1` seats (`{2..8}`) match `cp1`, Midnight accepts `cp_A` with `h = 1000`, stamping unsynced rolled-back `{0, 1}` as `2`.
    3. Seats `{2..8}` (`t = 7`) admit `Req_1`, bind slot `1150 → H(tk_1)`, and release a complete signature on `tk_1`.
    4. Operators roll back honest seats `{2, 3}` to `SNAP_0` (`boot_counter = 2` -> `[2,2,2,2,1,1,1,1,1]`) and unpause `{0, 1}`. Honest `{0, 1, 2, 3}` run `sync_witness` against `{0, 1, 2, 3, 7, 8}` (`w = 6`, with Byzantine `{7, 8}` reporting `pv = 5` and keeping `boot_counter = 1`): compared to `cp_A`, `{0, 1}` (`2=2`) and `{4..8}` (`1=1`) give `c = 7 ≥ w + 1`, so all four set `whole_restart = false`!
    5. `{0, 1, 2, 3, 7, 8}` (`q = 6` board/checkpoint quorum) post `cp_B` (`h = 1000`, `boot_counters = [2,2,2,2,1,1,1,1,1]`, `7` match `cp_A`). Repeating for `{4, 5}` (`c = 7`, post `cp_C`) and `{6}` (`c = 8`) rolls back all 7 honest nodes with `whole_restart = false` and `h = 1000`, signing a second ticket `tk_2 ≠ tk_1` on slot `1150` and leaking `x_f`.
  - *Path B (Non-monotone `cp3.h` after deep rollback with `0` Byzantine nodes):* All 9 disks roll back from `cp10` (`h = 1000`, where slots `601..800` were already used and burned) to an older snapshot `v = 2` (where `601..800` are `free(share)`). On reboot (`[6..6]`), `SS-068` burns `(1000, 1200]` only—leaving `601..800` `free(share)` in `work.slots`! `cp2` (`[6..6]`) sets `cp2.h = 1200` (passing `design.md` line 78). Next, `cp3` (`[6..6]`) has `c = 9 ≥ 7` matching `cp2`, where `design.md` line 78 imposes *no* `cp3.h ≥ cp2.h` check; if `cp3.h` regresses to `600` (from rolled-back app state), `SS-064` no longer rejects `601..800` and `slot_bind` reuses them.
- **Fix:**
  1. Contract rule (`design.md`): On *every* checkpoint `cp2` after `cp1`, require `cp2.h[p] ≥ cp1.h[p]` and `cp2.pending[p] ⊆ cp1.pending[p] ∪ (cp1.h[p], cp2.h[p]]`; advance `cp.boot_counters[j]` to `b` only with a signature by seat `j`'s boot key `b` attesting completion of `sync_witness` and `SS-068` at or after `cp1.seq`, and trigger the window-burn jump whenever `< w + 1` *checkpoint signers* held continuous synced seats since `cp1`.
  2. In `SS-068`, also burn stale lower slots:
  > **SS-068 (addition)** ... SHALL also set to `burned` each nonce slot index in `work.slots` at or below `cp_boot.h[purpose]` that is not in `cp_boot.pending[purpose]`.

---

### F7 — Rebooting 3 nodes (`c = 6`) or finalizing a checkpoint mid-restart causes a burn split-brain across honest nodes
- **Severity:** blocking
- **Location:** [design.md](bundle/change/design.md) §Reservation window and whole-committee restart; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-067, SS-068, SS-069
- **Claim affected:** G1, G3, window burn (Check 4), whole-committee restart (Check 5)
- **Failure scenario:** Two split-brain timelines (`n = 9, f = 2, q = 6, t = 7, w = 6, B = 200`):
  - *Scenario A (3-node reboot, `SS-067` Scenario 3):* At `cp1` (`h = 1000, pending = {990}, boot_counters = [1..1]`), seats `{0, 1, 2}` reboot (`boot_counter = 2`) while seats `{3..8}` (`6 = q` nodes) stay continuously up. Seats `{0, 1, 2}` see `c = 6 < 7`, set `whole_restart = true` (`SS-067`), and burn `{990} ∪ (1000, 1200]` (`SS-068`). Live seats `{3..8}` never run `SS-067`/`SS-068` (their sessions remain `open = true` and `whole_restart` is fixed per boot): as a full `q = 6` board quorum, `{3..8}` keep request `990` pending and keep admitting new spends on `1001..1200`—every one of which hangs at `6 < t = 7` signature partials—and when `{3..8}` submit `cp2` (`h = 1050 < 1200, pending = {990}`), Midnight's contract rule (`c = 6 < 7`) rejects every checkpoint!
  - *Scenario B (`cp_boot` disagreement when a checkpoint lands during restart):* Just before all 9 VMs reboot (`[2..2]`), the `[1..1]` committee submitted `cp2` (`h = 1060, pending = {990, 1060}, boot_counters = [1..1]`) to Midnight. Seats `{0..5}` finish `sync_witness` before `cp2` finalizes, latching `cp_boot = cp1` and burning `(1000, 1200]`; `cp2` then finalizes (`9 ≥ 7` match `cp1`), and seats `{6, 7, 8}` finish `sync_witness` latching `cp_boot = cp2` and burning `(1060, 1260]`. Now `260 > B = 200` slots are lost (breaking G3), `{0..5}` (`q = 6`) admit requests on `1201..1260` that stall at `6 < 7` partials, and `cp3` fails the contract check if `1201..1260` enter `cp3.pending`. Conversely, if `{0..5}` (`q = 6`) post `cp2` (`h = 1200, boot_counters = [2..2]`) after `{6, 7, 8}` posted `boot_counter = 2` on Midnight but before `{6, 7, 8}` ran `sync_witness`, `{6, 7, 8}` see `c = 9 ≥ 7` (`whole_restart = false`, `SS-069`) and never burn `bound` shares in `{990} ∪ (1000, 1200]` (breaking G4).
- **Fix:** Tie the burn to an explicit checkpoint transition on Midnight (or evaluate `c < w + 1` dynamically on live nodes too whenever the ledger's continuous-seat count against the latest checkpoint drops below `w + 1`), so *all* nodes—rebooted and continuous—burn `(cp1.h, cp1.h + B] ∪ cp1.pending` for the *same* checkpoint `cp1`, and late nodes booting after `cp2` burn all slots `≤ cp2.h` not in `cp2.pending` (per F6's `SS-068` addition, applied unconditionally on every restore!).

---

### F8 — Restore deadlocks on `SS-032` (`conflict`) and `SS-035` (`no_quorum`) when honest crashes produce two records for one version (`SS-027` `pv` is never applied)
- **Severity:** blocking
- **Location:** [design.md](bundle/change/design.md) §Versions and the witness fence, §Replication; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-020, SS-027, SS-030, SS-031, SS-032, SS-035, SS-095
- **Claim affected:** G1, replication (Check 6)
- **Failure scenario:** `n = 9, f = 2, t = 7, w = 6`, zero faulty enclaves and zero colluding operators:
  1. Seat `0` at `v = 7` checkpoints `v = 8` (`R8_A`, digest `A`); peers `{1, 2}` ack `R8_A`, then seat `0`'s VM fails before reaching `{3..8}`.
  2. Replacement VM of seat `0` (blank disk) boots; `sync_witness` (`SS-030`) gets `w = 6` answers from `{3..8}` (`pv = 7`). Seat `0` opens `v = 7`: in `SS-035`, `{3..8}` return 6 acks while `{1, 2}` refuse `stale_version` with `pv = 8` (`SS-027`), **which no requirement in `spec.md` uses to update `v_max`** (`v_max` remains `7`).
  3. Seat `0` checkpoints `v_max + 1 = 8` with a fresh 24-byte nonce (`SS-008`), producing `R8_B` (`B ≠ A`):
     - *Tie deadlock:* `R8_B` reaches `{3, 4}` before a reboot. On the next `sync_witness`, `{1, 2}` report `(8, A)`, `{3, 4}` report `(8, B)`, `{5..8}` report `7`. `SS-032` returns `conflict` (`open = false`) on every `session_open` forever!
     - *Majority deadlock (`SS-031` + `SS-035` + `SS-095`):* Even if `R8_B` reaches `{3, 4, 5, 6}` (4 peers—the exact scenario of `SS-031` lines 352–355!) and seat `0` reboots while `{7, 8}` are offline (`f = 2` tolerated crashes): `SS-031` selects `B` (`4 > 2`), and `SS-035` sends `session_witness(8, B)` requiring `w = 6` acks. Peers `{1, 2}` refuse `(8, B)` with `conflict` (`SS-095`) and `{7, 8}` are offline, leaving only `4 < 6` acks—`session_open` fails permanently with `no_quorum` while `7 = n − f` nodes are healthy!
- **Fix:** Update `v_max` on `stale_version`/`conflict`, break digest ties deterministically, and seal `v_max + 1` during restore instead of re-witnessing `v_max`:
  > **SS-027a** Whenever a current-ticket peer refuses `session_witness` with `stale_version` or `conflict` and `pv > v_max`, the seald service SHALL set `v_max` to `pv`.
  > **SS-032 (revised)** When two record digests of `v_max` have the same largest number of reporting peers, the seald service SHALL order them by digest bytes descending and select the first record that is available and passes `SS-037`.
  > **SS-035 (revised)** After `SS-036` decrypts the selected record into `work` (and runs `SS-068`/`SS-073`/`SS-092`), the seald service SHALL seal and witness `work` as version `v_max + 1` (`SS-020`–`SS-023`) and set `open = true` only with `w` acks.

---

### F9 — ECDSA per-address presignature slot shares are incompatible with the global `(h_cp, h_cp + B]` window (`SS-064`, `SS-065`, `SS-068`)
- **Severity:** blocking
- **Location:** [proposal.md](bundle/change/proposal.md) §Why; [design.md](bundle/change/design.md) §State classes, §Reservation window; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-005, SS-063, SS-064, SS-065, SS-068; [split-line/DESIGN.md](bundle/split-line/DESIGN.md) §3.6, §4.1, §4.4
- **Claim affected:** G1, G3, window burn (Check 4)
- **Failure scenario:** `design.md` §State classes seals ECDSA presignature slot shares `(w_{f,i}, μ_{f,i})` in sessions. Unlike fungible committee-wide Schnorr slots, `N_slot = 32` ECDSA slots are generated interactively *per address* at birth ([split-line/DESIGN.md](bundle/split-line/DESIGN.md#L212) §3.6) and spent asynchronously over months:
  1. *Shared pool (`purpose = "ecdsa-slots"`):* Address `A_1` is born at `t = 0` with slots `1..32`. Address `A_2` is born later with slots `33..64` and spends slot `40`, advancing `cp.h["ecdsa-slots"] = 40` (`cp.pending = ∅`). When `A_1` later tries to spend its unused slot `1`, `1 ≤ 40` and `1 ∉ cp.pending`, so `SS-064` refuses `slot_bind(sid, 1, H(tk))` with `slot_stale`—permanently bricking all 32 slots of `A_1`!
  2. *Per-address pool (`purpose = "ecdsa-<id>"`):* `SS-005` publishes every ECDSA account and its exact spend index `cp.h` and `cp.pending` on Midnight checkpoints (violating [split-line/DESIGN.md](bundle/split-line/DESIGN.md#L300) §4.1: "Slot ids never appear on Midnight, so an authorization record does not show ... for ECDSA, the account"), `SS-065` (`no_checkpoint`) blocks spending on a newly born address until a checkpoint lists it, and `SS-068` (`(h, h + B]` with `B ≥ 32`) burns the entire 32-slot pool of every listed address on a whole-committee restart.
- **Fix:** Restrict `SS-063`–`SS-068`'s sequential `cp.h` window to fungible committee-pool Schnorr sessions, and track non-fungible ECDSA presignature slots via `work.entries` plus board-root replay floor + recovery group `E` ([split-line/DESIGN.md](bundle/split-line/DESIGN.md#L886) §7.11) or an on-chain Merkle nullifier set rather than a scalar high-water mark `h`.

---

### F10 — `close_epoch` and `rekey` ignore peers' un-rekeyed sessions, own unwitnessed/closed sessions, `purpose` lookup, and pre-sync calls, permanently bricking sessions
- **Severity:** blocking
- **Location:** [design.md](bundle/change/design.md) §Epochs; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-001, SS-003, SS-006, SS-018, SS-020–SS-024, SS-078, SS-079, SS-080, SS-082, SS-083, SS-094; [api.rs](bundle/seald/src/api.rs) (`CloseEpoch`)
- **Claim affected:** G1, epochs (Check 7), spec consistency (Check 8)
- **Failure scenario:** Four concrete epoch-rotation failures (`epoch 5 → 6`, `t = 7, w = 6`):
  1. *Peers close epoch 5 while seat `0` lags:* Seat `0` crashes before or during `rekey(6)`, so its session `S` remains at `pv = 7, pe = 5` on peers `1..8` (or `< w` peers got `v = 8` in epoch `6` and crashed). Honest peers `1, 2, 3` (`f + 1 = 3`) finish `rekey(6)` on *their own* sessions and call `close_epoch(5)`. Because `SS-080` checks only whether "a session *of the node* has `epoch = e`" and ignores `pe = 5` in `SS-003`, peers `1, 2, 3` erase their epoch-5 PRF shares (`SS-079`). Only `6 < t = 7` shares of epoch `5` survive, so seat `0` gets `no_share` (`SS-018`) and `group_unavailable` (`SS-010`) forever.
  2. *Session with no witness-log entry (`SS-094` / `SS-023`):* Seat `0` opens a new session `S` in epoch `5`, seals `v = 1` locally (`SS-021`), and crashes before peer witness (`SS-094`)—or gets `w = 6` acks (`SS-023`, which never writes `session` entries into seat `0`'s *own* witness log!) and calls `session_close(S)`. Next, `rekey(6)` (`SS-078`, which restores only sessions "that [have] a version in the witness log of the node") skips `S`, and `close_epoch(5)` (`SS-080`, which "reads `epoch` of a closed session from the witness log") succeeds and erases epoch `5`'s share—bricking `S`.
  3. *`rekey` lacks `purpose` after reboot and corrupts open/closed RAM state:* After a whole-committee reboot (`whole_restart = true`), the app calls `rekey(6)` before `session_open`. `sync_witness` (`SS-030`) yields `sid = SHA-256(... ‖ purpose)` (`SS-006`) and never `purpose`, so `SS-078` → `SS-036` → `SS-068`/`SS-073`/`SS-092` cannot index `cp_boot.h[purpose]`. Moreover, if a session is already `open = true` with uncheckpointed `work`, `SS-078` ("SHALL restore each session") clobbers `work` in RAM; if it was `open = false`, `SS-036` leaves it `open = true` in RAM!
  4. *`close_epoch` before `sync_witness`:* `SS-082`/`SS-083` guard "session and nonce slot operation[s]" (`SS-040`), and `api.rs` line 201 runs `close_epoch` with neither fence nor `witness_synced` check; calling `close_epoch(5)` right after boot before `sync_witness` sees an empty witness log and erases epoch `5`.
- **Fix:**
  > **SS-001a** The seald service SHALL persist `(sid, purpose, v, v_max, epoch)` in tier 0 for each own session and include `purpose` inside the encrypted `work` body so a blank-disk restore recovers `purpose` upon decryption.
  > **SS-078 (revised)** `rekey(e)` (gated by `SS-082` and `SS-083`) SHALL rekey tier 1 and every own session with `open = true` or `v_max > 0` (from tier 0, witness sync, or `/mnt/persist`): an open session checkpoints its live `work` directly in epoch `e`; a closed session restores, checkpoints in epoch `e`, and zeroizes `work` (`open = false`).
  > **SS-080 (revised)** `close_epoch(e)` (gated by `SS-082` and `SS-083`) SHALL refuse `epoch_in_use` if tier 1 has epoch `e`, if any own session or local record on `/mnt/persist` has epoch `e`, or if any non-retired peer seat's `(node_index, sid)` entry in `SS-003` has `pe = e`.

---

### F11 — Whole-committee disk rollback reloads tier-0 PRF shares of closed epochs and reopens `session_destroy`ed entries and `≤ cp_boot.h` slot shares
- **Severity:** blocking (decision challenge: Decision 4)
- **Location:** [design.md](bundle/change/design.md) §Goals (G4), §Decisions (Decision 4); [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-046, SS-057, SS-068, SS-074, SS-075, SS-079; [committee-signing-mode.md](bundle/docs/committee-signing-mode.md#L656) §Limits, Recommendation 2
- **Claim affected:** G4, Decision 4, whole-committee restart from rolled-back disks (Check 5)
- **Failure scenario:**
  1. In epoch `5` at `v = 2`, operators snapshot all 9 disks (`seal` + `/mnt/persist`), where `work.entries["retired_key"]` exists and slots `500..989` are `free(share)`.
  2. In `v = 3..10`, the committee destroys `"retired_key"` via `session_destroy` (`SS-046`), consumes and burns slots `500..989` via `slot_burn` (`SS-057`), posts `cp10` (`h = 1000, pending = {990}`), rotates to epoch `6` (`rekey(6)`), and calls `close_epoch(5)` (`SS-079`) on all 9 nodes.
  3. Months later, all 9 VMs are booted from the epoch-5 `v = 2` snapshots (e.g., coerced operators or disaster backup restore). Previously (`σ_i` in RAM only), `close_epoch(5)` guaranteed snapshot erasure ([committee-signing-mode.md](bundle/docs/committee-signing-mode.md#L656)). Under Decision 4 (`SS-074`), the snapshot's tier 0 holds `σ^{(5)}_i` under `K_tpm` (which unseals because PCR 4/14/15 of the approved image are unchanged), and Midnight's historical `EpochKeySet` for epoch `5` still matches `σ^{(5)}_i`'s commitment, so `SS-075` loads `σ^{(5)}_i` on all 9 nodes!
  4. Rolled-back tier-0 witness logs hold `pv = 2`, so `t = 7` nodes serve partials for `(epoch = 5, v = 2)` (`SS-012`), `SS-036` decrypts `v = 2`, and `SS-068` burns `(1000, 1200] ∪ {990}` only—reopening `"retired_key"` (`session_get` returns it) and reopening all 490 consumed slot shares `500..989` as `free(share)` (`slot_get` returns them), directly breaking G4 ("a destroyed record or a consumed slot share does not open again from any old ciphertext").
- **Fix:** Pair Decision 4 with on-chain epoch-close and version-floor anchors in Midnight checkpoints:
  > **SS-075a / SS-018a** Each Midnight checkpoint SHALL record `min_open_epoch` and, for each `(node_index, sid)`, the witnessed version floor `v_cp`. `SS-075` SHALL delete from tier 0 (and `SS-018` SHALL refuse `no_share` for) any epoch `< min_open_epoch`, and `SS-016` SHALL refuse `stale_version` for any `v < max(pv, v_cp)`.

---

### F12 — `veritee-seald.service` systemd sandbox (`ProtectSystem=strict`) and two-phase boot race prevent `seald` from using `/mnt/persist`
- **Severity:** blocking
- **Location:** [proposal.md](bundle/change/proposal.md) §What changes, §Impact; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-003, SS-021, SS-025, SS-030, SS-100, SS-101; [committee-mode.md](bundle/docs/committee-mode.md#L92-L118) §Boot sequence, §Interfaces (`seald` line 266); [main.rs](bundle/seald/src/main.rs)
- **Claim affected:** G1, replication (Check 6), consistency with current code and docs (Check 9)
- **Failure scenario:**
  1. `veritee-seald.service` runs with `ProtectSystem=strict` and `ReadWritePaths=/var/lib/seald /run/veritee` ([committee-mode.md](bundle/docs/committee-mode.md#L266)), and `proposal.md` §Impact does not modify the unit or boot sequence. Every `SS-021` checkpoint write and `SS-025` peer replica write to `/mnt/persist` fails with `EROFS`, returning `internal` (`SS-100`) and `unavailable` (`SS-101`).
  2. Even with `/mnt/persist` writable, Phase 1 (`measured-setup.service`) unmounts `/mnt/persist` and starts `seald`, which immediately spawns `serve_peer` and `node.maintain()` (`sync_witness` → `SS-030`), while Phase 2 (`measured-setup-committee.service`) opens—and on first boot spends up to `900 s` formatting—`/mnt/persist` *after* `seald` is already running ([committee-mode.md](bundle/docs/committee-mode.md#L186)). `SS-030` reads an unmounted `/mnt/persist` (missing local records of `SS-094`), and incoming `SS-025` `session_witness` calls write replicas onto the unencrypted rootfs mountpoint directory, which Phase 2 then overmounts and hides!
- **Fix:** Add `-/mnt/persist` with shared mount propagation to `veritee-seald.service`, and add an admin-socket `persist_ready` notification sent by Phase 2 after mounting `/mnt/persist`:
  > **SS-030b** The seald service SHALL defer `SS-030` (`sync_witness`) and answer `unavailable` (`SS-101`) to peer `session_witness` and `session_fetch` requests until measured setup Phase 2 confirms `/mnt/persist` is mounted.

---

### F13 — Unbounded `slot` witness entries in tier 0 exhaust the 16 MiB `seal` partition after ~3,400 bound slots
- **Severity:** major
- **Location:** [design.md](bundle/change/design.md) §Replication, §Sizing; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-003, SS-050, SS-057, SS-100, SS-101; [witness.rs](bundle/seald/src/witness.rs) (`WitnessStore::persist`); [fsutil.rs](bundle/seald/src/fsutil.rs) (`write_atomic`)
- **Claim affected:** G1, 16 MiB tier-0 limit (Check 6)
- **Failure scenario:**
  1. Every `slot_bind` (`SS-050`) writes a ~210-byte JSON entry `(committee, node_index, purpose, slot) → digest` into `witness-log` in tier 0 on the binding node and on all `8` peers (`9 × 210 ≈ 1,890` bytes per committee slot on every node's `seal` partition), and neither `slot_burn` (`SS-057`) nor any checkpoint rule ever prunes `slot` entries.
  2. `fsutil::write_atomic` writes `.t0-<hash>.tmp` alongside `t0-<hash>` before `rename` on the 16 MiB ext4 `seal` partition (~13 MiB usable, shared with `k_tpm.blob` and tier 1), requiring `2×` `witness-log` bytes.
  3. After ~3,400 bound committee slots (~850 four-slot Bitcoin spends—one-third of one 10,000-slot pool in [design.md](bundle/change/design.md#L89)), `witness-log` reaches ~6.5 MiB and `Tier0Store::put` fails with `ENOSPC`, permanently halting `slot_bind` (`SS-100` `internal`) and peer `session_witness` (`SS-101` `unavailable`).
- **Fix:** Prune finalized stale `slot` entries from tier 0 once covered by `SS-064`:
  > **SS-050a** When `anchor_before_release` is `false` and the latest Midnight checkpoint `cp` (with monotone `cp.h`) has `index ≤ cp.h[purpose]` and `index ∉ cp.pending[purpose]`, the seald service MAY prune `(node_index, purpose, index)` of kind `slot` from tier 0 (for other seats unconditionally, and for its own seat once the index is `burned` or `absent`).

---

### F14 — Peer `SS-026` re-acks `u = pv` without restoring a missing `/mnt/persist` replica, causing `record_unavailable`, and `SS-038` contradicts `SS-039`
- **Severity:** major
- **Location:** [design.md](bundle/change/design.md) §Versions and the witness fence (line 53), §Replication; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-003, SS-026, SS-034, SS-035, SS-038, SS-039; [committee-mode.md](bundle/docs/committee-mode.md#L174) §Sealed persist volume
- **Claim affected:** G1, replication (Check 6), spec consistency (Check 8)
- **Failure scenario:**
  1. Seat `0` witnesses `v = 7` (`pd = A`) at peers `1..6` (`7, 8` miss `v = 7`). Peers `1..6` lose `/mnt/persist` (e.g., blank persist disk auto-formatted on reboot while `/var/lib/seald` retains tier 0 `(pv = 7, pd = A)`).
  2. Seat `0` reboots with its local `R7` intact and runs `SS-035`, sending `session_witness(0, sid, 7, epoch, R7)` to peers `1..6`. Under `SS-026`, peers `1..6` see `u = pv = 7` and `pd = A`, return signed acks, and **"leave [their] state unchanged"**—dropping `R7` without recreating the missing `replica` on `/mnt/persist` (breaking [design.md](bundle/change/design.md#L53): "A peer that acks a version holds its ciphertext").
  3. Seat `0` is later replaced by a blank-disk VM while `7, 8` are offline (`f = 2`): `sync_witness` selects `(7, A)` from `1..6`, `session_fetch` receives `not_found` (`SS-039`) from all 6, and `session_open` fails with `record_unavailable` (`SS-034`).
  4. Additionally, when `pv > 0` in tier 0 and `/mnt/persist` holds no `replica`, `SS-038` ("`pv > 0` and no refusal of SS-017, SS-019 or SS-028 applies → SHALL return `replica`") and `SS-039` ("holds no replica → SHALL refuse `not_found`") both apply simultaneously.
- **Fix:**
  > **SS-026 (revised)** When a `session_witness` request with `u = pv` and record digest `pd` arrives and no refusal of SS-017, SS-019, SS-028, SS-029 or SS-096 applies, if `/mnt/persist` does not hold `replica` with `SHA-256(replica) = pd`, the seald service SHALL write `record` to `replica` and call fsync before returning a signed ack.
  > **SS-038 / SS-039 (revised)** Add `SS-039` and `SS-096` to `SS-038`'s refusal list, and trigger `SS-039` (`not_found`) whenever `replica` is missing or `SHA-256(replica) ≠ pd`.

---

### F15 — Existing `seald` peer framing (`MAX_LINE = 1 MiB`), `PeerResponse` error mapping, `WitnessClient::refetch` conflict abort, and PCR14 cap break `spec.md` and G1
- **Severity:** major
- **Location:** [design.md](bundle/change/design.md) §Goals (G1), §Sizing; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-004, SS-022, SS-027, SS-038, SS-083, SS-095, SS-101; [api.rs](bundle/seald/src/api.rs#L55) (`MAX_LINE`, `serve_lines`, `serve_peer`), [node.rs](bundle/seald/src/node.rs#L599) (`handle_peer`), [witness.rs](bundle/seald/src/witness.rs#L450) (`refetch`), [tpm.rs](bundle/seald/src/tpm.rs#L58) (`cap`)
- **Claim affected:** G1, replication (Check 6), consistency with current code and docs (Check 9)
- **Failure scenario:**
  1. *Peer frame truncation (`api.rs` lines 55, 286, 328):* `serve_peer` uses `serve_lines` with `MAX_LINE = 1,048,576` bytes and emits app-format `{"ok":false,"error":"too_large"}`. A 10,000-slot session (~800 KiB binary, `> 1.06 MiB` base64 JSON; `SS-004` sets no upper bound on `S_max`, and `AttestPeerTransport` caps at `4 MiB` in `peer.rs` line 322) causes every `session_witness` (`SS-022`) and `session_fetch` (`SS-038`) to fail with `malformed peer reply`.
  2. *`unavailable` and `pv` lost on wire (`node.rs` line 599, `peer.rs` line 271):* `Node::handle_peer` maps every `Err(PeerError::Unavailable(_))` into `PeerResponse::Refused`, violating `SS-101`, and `PeerResponse::Refused { reason: String }` has no `pv` field for `SS-027` and `SS-095`.
  3. *Single faulty peer blocks `SS-083` (`witness.rs` line 450):* `WitnessClient::refetch` returns `Err(WitnessError::PeerConflict)` if 1 faulty peer (`1 ≤ f = 2`) reports a conflicting `slot` digest; `witness_synced` stays `false` and `SS-083` refuses every session operation with `not_ready` forever.
  4. *`seald` crash requires VM reboot (`tpm.rs` line 58, [committee-signing-mode.md](bundle/docs/committee-signing-mode.md#L584)):* G1 claims a session survives "a `seald` crash", but `Local::unseal` caps PCR14 so a crashed `seald` fails `TpmError::Policy` until a VM reboot increments `boot_counter`; a bug that crashes `seald` on `3` nodes forces 3 VM reboots, triggering `whole_restart = true` (`SS-067`) and burning the window.
- **Fix:** Bound `S_max ≤ 2,097,152` in `SS-004`/`SS-081` and raise `MAX_LINE` and `MAX_ATTEST_LINE` above `4 MiB` with distinct peer/app overflow responses; add `PeerResponse::Unavailable` and `PeerResponse::Refused { code, pv: Option<u64> }`; tolerate up to `f` conflicting peers in `WitnessClient::refetch` ([committee-signing-mode.md](bundle/docs/committee-signing-mode.md#L761) Recommendation 7); and either qualify G1 ("survives a `seald` crash after VM reboot") or add Recommendation 6's `K_tpm` holder.

---

### F16 — `SS-088` (`S_max`) omits `slot_bind`, `slot_burn` on `absent` slots, and `SS-068` restart burns, allowing `work` to exceed `S_max`
- **Severity:** major
- **Location:** [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-004, SS-050, SS-051, SS-057, SS-068, SS-088
- **Claim affected:** SS-004, SS-088, spec consistency (Check 8)
- **Failure scenario:** Let `S_max = 65,536`. The app calls `slot_put` until serialized `work` is `65,530` bytes (`≤ S_max`, passing `SS-088`).
  1. App calls `slot_bind(sid, 120, d)`: `SS-088` checks `session_put` and `slot_put` only, so `SS-050` commits `(node_index, purpose, 120) → d` to tier-0 witness logs on `w` peers, and `SS-051` replaces `free(share)` with `bound(share, d)` (+32-byte digest), pushing serialized `work` past `S_max`.
  2. App calls `slot_burn` (`SS-057`) on `absent` indices `2000..4000`, or `SS-068` Scenario 2 burns `B = 200` `absent` indices in `(cp_boot.h, cp_boot.h + B]` during `session_open`: each inserts an unremovable `burned` tombstone (`SS-059`) into `work.slots` with no `S_max` check, overflowing `S_max`.
- **Fix:**
  > **SS-088 (revised)** Measure `work` size by accounting each `free` slot at its worst-case `bound(share, d)` size and reserving space for `B` `burned` tombstones; if `session_put`, `slot_put`, or `slot_burn` on an `absent` index would make this accounted size exceed `S_max`, refuse the call with `too_large`.

---

### F17 — Missing cryptographic/wire domain bindings and internal contradictions in refusal rules (`SS-008`, `SS-012`, `SS-020`, `SS-057`, `SS-081`, `SS-089`, `SS-093`)
- **Severity:** minor
- **Location:** [design.md](bundle/change/design.md) §Keys; [spec.md](bundle/change/specs/seald-sessions/spec.md) SS-007, SS-008, SS-012, SS-020, SS-022, SS-025, SS-026, SS-028, SS-038, SS-041, SS-042, SS-050, SS-057, SS-081, SS-089, SS-093, SS-096, SS-100, SS-101
- **Claim affected:** Spec and design consistency (Check 8)
- **Failure scenario:**
  1. *Incompatible crypto/wire encodings:* `SS-012` omits the `SealedToNode` HPKE `context` (`aad`) and Chaum-Pedersen `partial_context`, so an independent requester and peer fail HPKE `open`; `SS-007` omits HKDF `salt`, output length (`32` bytes), and a domain label inside `H2C(x)`; `SS-008` omits integer endianness (`u64 BE` / `u32 BE`) in `header` and `aad`; `SS-022`/`SS-025`/`SS-028` omit `sign_labeled` domain tags.
  2. *`SS-081` rejects existing `seald.sock` operations:* `SS-081` refuses with `bad_request` any app request line that "does not parse as an operation of SS-040" (the 11 session/slot ops), refusing existing `put`, `get`, `destroy`, `list`, `ratchet`, `status`, `witness`, `install_prf_share`, `rekey`, and `close_epoch` calls on `/run/veritee/seald.sock`; `SS-081`/`SS-096` also omit `node_index < n` (so `node_index = 999` returns `not_current` instead of `bad_request`).
  3. *Missing refusal guards, checkpoint callers, refusal-order quirks & undefined post-error state:* `SS-020` ("A checkpoint starts in...") omits `SS-035` and `SS-052`; `SS-091` orders `bad_request` (`SS-017`) before `fenced` (`SS-019`) (reversing `Group::gate` in [group.rs](bundle/seald/src/group.rs#L444)) and `not_current` (`SS-014`) before `bad_evidence` (`SS-013`, checking unverified `BootClaim` fields before attestation verification); `SS-012`, `SS-025`, `SS-026`, and `SS-038` omit `SS-096` from their refusal lists (e.g., `session_partial` with `v = 0` when `pv = 0` satisfies both `SS-012` and `SS-096`); `SS-041`, `SS-042`, and `SS-093` omit `"and no refusal applies"` (conflicting with `SS-082`, `SS-083`, `SS-085`, `SS-054`, `SS-072`); `SS-089` omits `SS-050` (`no_quorum`, which mutates the own witness log), `SS-100` (`internal`), and `SS-101` (`unavailable`), and neither `SS-010` nor `SS-100` states what happens to `v_max`, `work`, or `unsealed`; `SS-020` ("the epoch of tier 1 for a session with `v = 0`") is undefined when `witness_synced` is `true` (`SS-083` passes) before tier 1 has ever been unlocked (`SealedStore::sealed_epoch` is `None`); and `SS-057` (`slot_burn`) leaves burned indices in `unsealed` when `anchor_before_release = true` and the anchor never landed, violating `SS-002`.
- **Fix:** Specify exact HKDF/HPKE/DLEQ/signature labels and big-endian field widths in `SS-007`, `SS-008`, `SS-012`, `SS-022`, `SS-025`, and `SS-028`; include existing `seald.sock` ops and `0 ≤ node_index < n` in `SS-081`/`SS-096`; list `SS-052` (and `SS-035`) in `SS-020` and place `bad_evidence` ahead of `not_current` in `SS-091`; add `"and no refusal applies"` to all positive operation rules; list `SS-050`, `SS-100`, and `SS-101` in `SS-089` with explicit post-conditions; fall back to `cfg.epoch` in `SS-020` when tier 1 is uninitialized; and remove `slot` from `unsealed` in `SS-057`.

---

## Summary of Required Checks (1–9)

| Check | Verdict | Reference / Reason |
|---|---|---|
| 1a. G1 (survives crash, reboot, blank-disk replacement with `≤ f` faulty) | **Fails** | F2 (1 Byzantine peer wipes session), F5 (`anchor_before_release` deadlock), F7 (`c = 6` & `cp_boot` split-brain), F8 (`conflict`/`no_quorum` restore deadlock), F9 (ECDSA `slot_stale`), F10 (`close_epoch`/`rekey` bricks sessions), F12 (`/mnt/persist` EROFS & Phase 1/2 mount race), F13 (16 MiB `seal` full), F14 (missing replica on re-ack), F15 (`MAX_LINE = 1 MiB`, `refetch` abort, PCR14 cap). |
| 1b. G2 (single-ticket nonce-slot binding under `c ≤ n − 1 − 2f`) | **Fails** | F3 (blank-disk replacement under `c = 4` unbinds slot), F5 (`anchor_before_release` double release on rollback). |
| 1c. G3 (whole-committee restart loses `≤ B` Schnorr slots, zero key shares, zero double-use) | **Fails** | F5 (`anchor_before_release` safety/liveness), F6 (staggered 2-seat wave rollback & `cp3.h` regression reuse nonces), F7 (`cp_boot` split loses `> B` slots; `c = 6` stalls spends), F9 (ECDSA per-address slots incompatible). |
| 1d. G4 (destroyed record / consumed slot share never reopens) | **Fails** | F3 (blank-disk replacement under `c = 4` reopens `v = 7`), F4 (`slot_burn`/`session_destroy` after `no_quorum` skip checkpoint), F7 (late node after `cp2` skips burning `bound` shares), F11 (Decision 4 challenge: whole-committee rollback reloads closed-epoch `σ_i` and old ciphertexts). |
| 1e. G5 (no single operator opens a session; one enclave never opens another's) | **Partially sound; fails operator half** | Cross-seat enclave isolation (Decision 1) holds (see Sound Checks); single-operator half fails under Decision 3 without PCR15 pinning (F1). |
| 2. Witness fence | **Partially sound; fails on blank-disk replacement & 1 Byzantine peer** | Clones/superseded tickets, peers joining after missing versions, and non-blank-disk `c ≤ n − 1 − 2f` hold (see Sound Checks); blank-disk replacement VM under `c = 4` fails (F3), and 1 Byzantine peer fences out real state via `SS-035`-before-`SS-036` (F2). |
| 3. Nonce-slot binding | **Partially sound; fails on blank-disk replacement & `anchor_before_release`** | Crash between the two witness rounds and restored `free` slot with `anchor_before_release = false` and non-blank seat hold (see Sound Checks); blank-disk replacement fails under `c = 4` (F3), and `anchor_before_release` fails both liveness and safety (F5). |
| 4. Reservation window & restart burn | **Partially sound; fails on `c = 6` split-brain, `cp_boot` race, wave rollback & ECDSA** | Empty-ledger boot (`SS-098`) and `slot_stale` (`SS-064`) under monotone `cp.h` on Schnorr pools hold (see Sound Checks); fails on 3-node reboot & `cp_boot` disagreement (F7), wave rollback & missing normal `cp2.h ≥ cp1.h` (F6), and ECDSA per-address slots (F9). |
| 5. Whole-committee restart from rolled-back disks | **Fails** | Uniform rollback reopens destroyed entries, `≤ cp_boot.h` shares, and closed epochs (F11) and allows `cp3.h` regression (F6); mixed disks fail under `anchor_before_release` (F5) and late-booting nodes (F7). |
| 6. Replication | **Fails** | Blank-disk VM fails under `c = 4` (F3); majority/tie/two-records-per-version deadlock `session_open` (F8) and allow 1-Byzantine-peer wipe (F2); ack-then-lose-replica violates `design.md` and bricks `session_fetch` (F14); 16 MiB tier-0 fills after ~3,400 bound slots (F13). |
| 7. Epochs | **Fails** | Peer `close_epoch` ignores `pe` in `SS-003`, own/unwitnessed sessions are invisible to `SS-078`/`SS-080`, `rekey` lacks `purpose` and corrupts open/closed RAM state, and pre-sync `close_epoch` is unguarded (F10). |
| 8. Spec and design consistency | **Fails** | Post-`no_quorum` erasure bugs (F4), `S_max` overflow (F16), `SS-026`/`SS-038`/`SS-039` conflicts (F14), missing `SS-027` `pv` handling (F8), and missing domain labels / refusal guards / `SS-020` & `SS-089` entries / `SS-091` order quirks (F17). |
| 9. Consistency with current code and docs | **Fails** | Unpinned PCR15 breaks G5 (F1); `ProtectSystem=strict` & Phase 1/2 mount race block `/mnt/persist` (F12); `MAX_LINE = 1 MiB`, `PeerResponse`, `WitnessClient::refetch`, and PCR14 cap conflict with `spec.md` and G1 (F15); `FollowerLedger` lacks anchor records (F5). |

---

## Required Checks Found Sound

- **Check 1e / Decision 1 — Cross-seat enclave isolation (one enclave never opens another seat's session):** Sound because `node_index` is bound into `sid` (`SS-006`), `K_sess` (`SS-007`), and the AEAD AAD (`SS-008`), while peers verify that `BootClaim` names the latest ticket of `node_index` (`SS-014`), refuse self-seat requests (`SS-017`), and HPKE-seal partials to `BootClaim`'s `NodeKeys` (`SS-012`, `SS-015`).
- **Check 2 (clones, superseded boot tickets, and header tampering):** Sound because a clone or superseded VM is refused locally (`SS-082`) and by peers on partials, witnesses, and fetches (`SS-014`, `SS-028`), superseded peers refuse and their acks do not count (`SS-019`, `SS-023`), and mutating a record header to `v ≥ pv` fails XChaCha20-Poly1305 AAD and key binding (`SS-007`, `SS-008`, `SS-037`).
- **Check 2 (old-record fence and peers joining the quorum after missing versions, under `c ≤ n − 1 − 2f` when the seat's disk was not lost independently):** Sound when any forgetful seat is counted among the `c` colluders, because even if all `(n − 1) − w = f` peers that missed version `v` later join the partial quorum and `c − 1` of the `w` acking peers (`SS-023`, `SS-025`) forget `pv ≥ v`, at least `w − (c − 1) ≥ f + 2` peers refuse `< v` (`SS-016`), leaving at most `1 + (n − 1) − (f + 2) = t − 1 < t` partials (`SS-009`, `SS-010`).
- **Check 3 (`slot_bind`, `slot_release_ok`, `unsealed`, crash between the two witness rounds, and restored `free` slot, for `anchor_before_release = false` without blank-disk replacement):** Sound because `SS-050` commits `(node_index, purpose, slot) → d` to `w` peers before `SS-051` sets `bound(share, d)` in `unsealed`, `SS-055`/`SS-056` return `release = false` until `SS-023` clears `unsealed` at `w` checkpoint acks, and after a mid-bind crash or rollback `sync_witness` recovers `d` so `SS-056` blocks release on `free` and `SS-054` refuses any `d' ≠ d` with `conflict`.
- **Check 4 (boot with no checkpoint on the ledger, `SS-099` non-slot sessions, and lower bound `slot_stale` on fungible Schnorr pools under monotone `cp.h`):** Sound because `SS-065` prevents any `slot_bind` before a checkpoint lists `purpose` so `SS-098` and `SS-099` safely burn nothing at boot, and `SS-064` (`slot_stale`) blocks binding any `free` Schnorr slot `≤ cp.h[purpose]` outside `cp.pending[purpose]` so post-checkpoint reservations stay inside `(cp.h, cp.h + B]` (`SS-063`, `SS-066`).
- **Check 8 (`SS-090` app refusal order and error code inventory):** Sound once positive rules carry `"and no refusal applies"` (F17), because every error/reason code used across `SS-001`–`SS-101` is defined and `SS-090` gives a total, deterministic priority order (`bad_request` → node state → session/input bounds → slot state → ledger window/conflict) over all app refusal codes.
