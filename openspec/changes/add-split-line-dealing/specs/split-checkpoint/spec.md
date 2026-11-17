## ADDED Requirements

### Requirement: CP-001 Checkpoint fields

**CP-001** The committee contract SHALL keep for each landed checkpoint the fields `seq`, `epoch`, `board_height`, `board_root`, `witness_root`, `pools`, `settle_root`, `bf_root`, `boot_counters`, `restart_seq`, `seat_roots` and `restores`.

`boot_counters` maps each seat with a `RestoreDone` to its boot counter. `seat_roots` holds one Merkle root per seat log (CP-016). `restores` holds the new `RestoreDone` statements (DESIGN §7.13).

#### Scenario: Size at launch

- **WHEN** a checkpoint lands at `n = 9` with two committee pools
- **THEN** its payload is 1,008 bytes

### Requirement: CP-002 Pool fields

**CP-002** The committee contract SHALL keep for each committee pool `(s, e)` of a checkpoint the fields `h`, `pending_min`, `pending_root` and `pending_count`.

`h` is the highest index that a request reserved or a restart burn retired. `pending_min` is the lowest index that a request live at the checkpoint holds, or `h + 1`. `pending_root` is a Merkle root over the sorted pending list, which stays on the board under `board_root`. 52 bytes per pool.

#### Scenario: No live request

- **WHEN** no request live at the checkpoint holds an index of pool `(BIP340, 3)` and `h = 400`
- **THEN** the checkpoint has `pending_min = 401` and `pending_count = 0`

### Requirement: CP-003 Checkpoint interval

**CP-003** The committee node SHALL submit one checkpoint transaction with `t` node signatures every 60 s of board time.

A checkpoint needs `t` signers, the number that can sign under `X_f`, so a committee that cannot sign cannot keep its checkpoints landing (DECISIONS 86, HO-068).

#### Scenario: One minute

- **WHEN** 60 s of board time pass after the last checkpoint
- **THEN** the committee submits one checkpoint

### Requirement: CP-004 Checkpoint after a restore

**CP-004** When a seat appends a `RestoreDone` statement to its seat log, the committee node SHALL submit a checkpoint that carries it before the next planned reboot.

`f + 1` reboots one at a time then stay partial restarts (DESIGN §7.11).

#### Scenario: Rolling patch

- **WHEN** node 4 reboots and appends `RestoreDone`
- **THEN** a checkpoint carries it before node 5 reboots

### Requirement: CP-005 No committee write per request

**CP-005** The committee node SHALL submit no Midnight transaction per request, per put, per slot binding, per release anchor or per boot statement.

The committee writes one checkpoint per interval, which at a handoff is the handover checkpoint with `EKS_{e+1}` and the roster (HO-047), and one record per `coldStart` or `recover` event (DECISIONS 52, owner rule of 2026-11-14; DECISIONS 83). At 160 to 400 requests per second that is 1/60 committee transaction per second.

#### Scenario: Busy minute

- **WHEN** 24,000 requests end in one checkpoint interval
- **THEN** the committee submits one checkpoint transaction and no settle transaction

### Requirement: CP-006 Epoch key set

**CP-006** When every node of epoch `e` has `w` acks for its `NodeKeys`, the committee node SHALL put the epoch key set `EKS_e` of all `n` `NodeKeys` into the handover checkpoint that opens epoch `e`, or into the first checkpoint at genesis.

#### Scenario: New epoch

- **WHEN** the nine nodes of epoch 4 each hold six acks
- **THEN** the handover checkpoint that opens epoch 4 carries `EKS_4`, and the Key Registry takes it from there (DECISIONS 83)

### Requirement: CP-007 Floor lowered

**CP-007** If a checkpoint has `h` below the `h` of the previous landed checkpoint for any committee pool, then the committee contract SHALL refuse the checkpoint with the code `h_lowered`.

#### Scenario: Lower floor

- **WHEN** a checkpoint shows `h = 90` after a landed `h = 100`
- **THEN** the checkpoint is refused

### Requirement: CP-008 Pending floor above the floor

**CP-008** If a checkpoint has `pending_min > h + 1` for any committee pool, then the committee contract SHALL refuse the checkpoint with the code `pending_gap`.

An index in `(h, pending_min)` would pass the window and escape the restart burn (DESIGN §7.13).

#### Scenario: Gap

- **WHEN** a checkpoint shows `h = 100` and `pending_min = 105`
- **THEN** the checkpoint is refused

### Requirement: CP-009 Jump after a restart

**CP-009** Where `slot_anchor` is off, if a checkpoint `cp2` after the landed checkpoint `cp1` keeps the boot counters of fewer than `w + 1` seats and, for any committee pool, has `cp2.h < cp1.h + B` or `cp2.pending_min ≤ cp1.h + B`, then the committee contract SHALL refuse `cp2` with the code `restart_jump`.

The contract reads two integers per pool. The proof that this rule implies the list rule is DESIGN §7.13 (DECISIONS 52, D4 option (c)).

#### Scenario: No jump

- **WHEN** a checkpoint after a whole-committee restart keeps `h` at `cp1.h + 10` with `B = 200`
- **THEN** the checkpoint is refused

### Requirement: CP-010 Boot counter without a statement

**CP-010** If a checkpoint records a boot counter for a seat without that seat's `RestoreDone` statement in the same or an earlier checkpoint, then the committee contract SHALL refuse the checkpoint with the code `no_restore_statement`.

#### Scenario: Counter only

- **WHEN** a checkpoint raises seat 3 to boot counter 12 with no `RestoreDone` for counter 12
- **THEN** the checkpoint is refused

### Requirement: CP-011 Restart marker

**CP-011** When the first checkpoint that carries, or follows a checkpoint that carries, a `RestoreDone` with `whole_restart = true` that names a checkpoint at or above the current `restart_seq` lands, the committee contract SHALL set `restart_seq` to that checkpoint's `seq` and keep `restart_seq` unchanged at every other checkpoint.

Sessions SS-121 (DECISIONS 69).

#### Scenario: Marker set

- **WHEN** checkpoint 501 carries a `RestoreDone` with `whole_restart = true` naming checkpoint 500 and `restart_seq = 200`
- **THEN** checkpoint 501 has `restart_seq = 501`

### Requirement: CP-012 Board-first root signing

**CP-012** The checkpoint signer SHALL sign a `bf_root` only over leaves of which no two hold one `nf` and none holds an `nf` of an earlier landed `bf_root`.

#### Scenario: Repeated nf

- **WHEN** two ordered board-first calls of an interval hold one `nf`
- **THEN** no honest node signs a `bf_root` over both

### Requirement: CP-013 Settlement root signing

**CP-013** The checkpoint signer SHALL sign a `settle_root` only over the leaves of exactly the requests that ended between the board heights of the previous checkpoint and this one, each with the outcome of the board record, and with no leaf that gives an `auth` an outcome other than the VOID that Midnight records for it.

#### Scenario: Carried VOID then other outcome

- **WHEN** Midnight records `auth` as settled VOID and a replay offers `(auth, RELEASED)`
- **THEN** no honest node signs a root over that leaf

### Requirement: CP-014 Pending root signing

**CP-014** The checkpoint signer SHALL sign `pending_root` only over the sorted list of the committee slots that live requests hold on the board at or above the `pending_min` of the previous landed checkpoint for that pool, with `pending_min` its lowest entry or `h + 1` and `pending_count` its length.

A pool that the previous landed checkpoint does not list has no floor. An index below the floor gets no honest vote (SL-013, finding F7, DECISIONS 71).

#### Scenario: Two live requests

- **WHEN** live requests hold indices 95, 96, 120 and 121 and `h = 130`
- **THEN** the signed fields are `pending_min = 95` and `pending_count = 4`

#### Scenario: Precedence below the landed floor

- **WHEN** the previous landed checkpoint has `pending_min = 2`, live requests hold indices 1 and 2, and `h = 2`
- **THEN** the signed fields are `pending_min = 2` and `pending_count = 1`

### Requirement: CP-015 Seat root signing

**CP-015** The checkpoint signer SHALL sign no seat root over a seat log that holds a second binding for one slot key or a second put of one digest.

The roots form one chain across checkpoints (Sessions SS-136).

#### Scenario: Second put

- **WHEN** seat 2's log holds two put entries with one digest
- **THEN** no honest node signs a root over that log

### Requirement: CP-016 Seat log

**CP-016** The committee node SHALL append its `RestoreDone(committee, node_index, boot_ctr, cp.seq, whole_restart)` statements signed with `bk_sig`, its put entries, its slot-anchor binding entries `(nf, e)` and its `release` entries of `anchor_before_release` charters to the append-only seat log of its seat on the board, and count an entry only once a landed checkpoint root covers it.

Midnight holds only the roots (DECISIONS 51 item 11). `RestoreDone` is 117 bytes (DECISIONS 69).

#### Scenario: Entry in the tail

- **WHEN** a put entry lies above the board height of the latest landed checkpoint
- **THEN** the entry does not count yet

### Requirement: CP-017 Continuous seat

**CP-017** The committee node SHALL treat as continuous each seat whose latest boot ticket has the boot counter that the latest landed checkpoint records for that seat.

A checkpoint records a boot counter only from a signed `RestoreDone` (CP-010).

#### Scenario: Rebooted seat

- **WHEN** seat 6 holds boot ticket 9 and the latest checkpoint records 8
- **THEN** seat 6 is not continuous

### Requirement: CP-018 Restart classification

**CP-018** Where `mode = TEE`, when a node completes its first witness sync after a boot, the committee node SHALL read the boot tickets and the latest checkpoint `cp` from one verified ledger snapshot and classify the boot as a whole-committee restart for fewer than `w + 1` continuous seats.

The node decides from the ledger only, because a rolled-back node cannot tell from its own disk (DESIGN §7.11, Sessions D-005).

#### Scenario: Region outage

- **WHEN** all nine nodes reboot and no seat is continuous
- **THEN** each node classifies a whole-committee restart

### Requirement: CP-019 Ledger not verified

**CP-019** If the ledger snapshot does not read or does not verify, then the committee node SHALL stay not ready with the code `ledger_unverified` and read the ledger again.

#### Scenario: Midnight unreachable

- **WHEN** a booting node cannot verify the ledger snapshot
- **THEN** it opens no session and serves no request

### Requirement: CP-020 Committee pool burn

**CP-020** When a node classifies a whole-committee restart, the committee node SHALL burn every index in `[cp.pending_min, cp.h + B]` of each committee pool of each checkpoint `cp` that it read before any session opens.

Indices in the range that are not pending were reserved by an ended request, skipped or burned, so the burn loses no usable slot (DESIGN §7.13 items 1 and 2).

#### Scenario: Burn range

- **WHEN** `cp.pending_min = 95`, `cp.h = 130` and `B = 200`
- **THEN** indices 95 to 330 are burned

### Requirement: CP-021 Account pool burn

**CP-021** When a node classifies a whole-committee restart, the committee node SHALL burn every `free` and `bound` slot of every account pool once per restart generation.

A rolled-back disk can show a claimed slot `free` (DECISIONS 51 item 6). The node finds its pools in its sessions (`keys`, local records, witness sync entries), so the burn needs no list of named slots. A generation ends by CP-027 (DECISIONS 69).

#### Scenario: ECDSA address at a restart

- **WHEN** an address holds 20 unused ECDSA slots at a whole-committee restart
- **THEN** all 20 are burned and the address refills by a new session before its next ECDSA spend

### Requirement: CP-022 Running nodes burn

**CP-022** When a node that did not reboot reads a ledger that shows a whole-committee restart, the committee node SHALL burn the sets of CP-020 and CP-021 in its open sessions at once and record the burn at the next seal of each session.

`slot_bind` refuses each burned index before the seal. A crash before the seal loses the burn with the RAM, and the next boot decides again from the ledger (Sessions D-040, DECISIONS 69).

#### Scenario: Survivor node

- **WHEN** node 1 kept running while eight nodes rebooted from old disks
- **THEN** node 1 burns the same sets

### Requirement: CP-023 Union of burn sets

**CP-023** The committee node SHALL burn the union of the burn sets of every checkpoint that it read for one whole-committee restart.

#### Scenario: Two checkpoints read

- **WHEN** a node read checkpoints 500 and 501 during one restart
- **THEN** it burns the ranges of both

### Requirement: CP-024 Sessions created after a restart

**CP-024** When a node creates a pool session after it classified a whole-committee restart and before the restart ends (CP-027), the committee node SHALL open the session with the burned indices of CP-020.

Every disk can roll back to a state before that session existed (DESIGN §7.11).

#### Scenario: New pool session

- **WHEN** a node creates pool session `slots-BIP340-3` after the restart
- **THEN** the session opens with indices 95 to 330 burned

### Requirement: CP-025 Account-pool binds after a restart

**CP-025** While a node has classified a whole-committee restart and no landed checkpoint carries a `restart_seq` above the previous marker, the committee node SHALL bind no account-pool slot.

When that checkpoint lands, the node writes the marker into each burned account pool (Sessions SS-120 to SS-125).

#### Scenario: Bind before the marker

- **WHEN** an ECDSA request asks for a bind before the marker checkpoint lands
- **THEN** the node binds nothing

### Requirement: CP-026 Late boot after a restart

**CP-026** When a node opens an account pool whose recorded restart mark is below `restart_seq`, the committee node SHALL burn every `free` and `bound` slot of that pool before any bind.

A node that boots after the marker checkpoint sees continuous seats; the marker carries the burn to it (DECISIONS 51 item 6, Sessions D-024).

#### Scenario: Node boots late

- **WHEN** a node boots after checkpoint 501 set `restart_seq = 501` and opens a pool with mark 200
- **THEN** it burns that pool's unburned slots

### Requirement: CP-027 End of a restart

**CP-027** While a node has classified a whole-committee restart, the committee node SHALL keep the restart open until a landed checkpoint carries a new `restart_seq` and `w + 1` continuous seats.

A later loss of continuity before then burns again (Sessions D-028).

#### Scenario: Second loss

- **WHEN** continuity drops below `w + 1` before the marker checkpoint shows `w + 1` continuous seats
- **THEN** the node burns again

### Requirement: CP-028 Partial restart

**CP-028** When a node classifies a boot with at least `w + 1` continuous seats, the committee node SHALL resume every session and every pending request without a restart burn.

#### Scenario: One reboot

- **WHEN** one node reboots and eight seats are continuous
- **THEN** nothing is burned

### Requirement: CP-029 Restart with slot anchors

**CP-029** Where `slot_anchor` is on, when a node classifies a whole-committee restart, the committee node SHALL burn nothing, make each `free` slot with a covered binding in the seat log `bound` to that digest, and release on no slot whose restored digest differs from its covered binding.

#### Scenario: Anchored committee

- **WHEN** a slot restores `free` from an old disk and a covered entry binds it to `d`
- **THEN** the slot is `bound(d)`

### Requirement: CP-030 Fewer than t intact

**CP-030** When fewer than `t` nodes have tier 0 intact at a whole-committee restart, the recovery group SHALL act on a Midnight `coldStart(committee_id)` record signed by `q` registered operators and reshare `x_f` to the fresh nodes.

The committee then deals a new nonce pool. Requests that held committee slots end VOID and settle FINAL or RELEASED by RQ-052 (DECISIONS 53).

#### Scenario: Tier 0 lost on five nodes

- **WHEN** only four nodes have tier 0 intact
- **THEN** `E` reshares `x_f` after the `coldStart` record

### Requirement: CP-031 ECDSA reshare after a recovery

**CP-031** Where `slot_anchor` is on, when the recovery group reprovisions a committee, the recovery group SHALL reshare no ECDSA slot that a covered entry of the seat logs up to the root of the latest checkpoint binds, and treat a seat log that it cannot read in full as binding every slot of that seat.

Option (r3) of DECISIONS 51 item 8. `E` holds the slot key of each seat and `k_nf`.

#### Scenario: Unreadable seat log

- **WHEN** `E` cannot fetch seat 7's log up to the latest root
- **THEN** `E` reshares no ECDSA slot of seat 7

### Requirement: CP-032 No ECDSA reshare without anchors

**CP-032** Where `slot_anchor` is off, the recovery group SHALL reshare no ECDSA slot.

Every ECDSA address, the guardian slots `G_g` included, refills by a new session before its next ECDSA spend (DESIGN §7.11 item 2).

#### Scenario: Launch committee recovery

- **WHEN** `E` reprovisions a launch committee
- **THEN** no ECDSA slot share reaches the successor

### Requirement: CP-033 Non-TEE restart

**CP-033** Where `mode = NON_TEE`, when all nodes restart at once, the committee node SHALL keep no slot share, end every request that held a slot VOID, deal a new nonce pool and mark every ECDSA address for refill.

The ended requests settle FINAL or RELEASED by RQ-052.

#### Scenario: Non-TEE region outage

- **WHEN** a non-TEE committee restarts at once
- **THEN** every slot it held is gone and a new pool is dealt

### Requirement: CP-034 Recovery transition

**CP-034** When no committee checkpoint has landed for `Δ_rec` Midnight blocks, the Recovery contract SHALL accept `recover(committee_id)` from any party and record a recovery transition.

`Δ_rec` is a charter value, 30 days of Midnight blocks at launch.

#### Scenario: Committee gone

- **WHEN** no checkpoint lands for 30 days
- **THEN** `recover` records a transition and `E` may reprovision an exit-only successor

### Requirement: CP-035 Early recovery

**CP-035** If `recover(committee_id)` is called before `Δ_rec` Midnight blocks have passed since the latest landed checkpoint, then the Recovery contract SHALL refuse the call with the code `recovery_early`.

#### Scenario: Live committee

- **WHEN** `recover` is called one day after a checkpoint
- **THEN** the call is refused

### Requirement: CP-036 Replay floor

**CP-036** If a node at admission meets a request ordered below the maximum of the board heights its peers report and the board height of the latest landed checkpoint, and cannot prove that it has not served that request, then the committee node SHALL refuse the request with the code `below_floor`.

DESIGN §7.7, replay floor.

#### Scenario: Old request after reboot

- **WHEN** a rebooted node sees a request ordered below its replay floor with no proof of non-service
- **THEN** it refuses the request

### Requirement: CP-037 Release anchor

**CP-037** Where a charter sets `anchor_before_release`, the committee node SHALL release a partial of that charter's request only after a landed checkpoint root covers its `release` entry in the seat log.

It adds no Midnight transaction and about one checkpoint interval plus `F_M` per release (DESIGN §7.7).

#### Scenario: High-value charter

- **WHEN** a request of an `anchor_before_release` charter is anchored
- **THEN** its release waits for the next checkpoint root

### Requirement: CP-038 Cold start

**CP-038** The committee node SHALL lose no key, move no coin and let no slot collect honest partials for two tickets across a whole-committee restart with any number of disks rolled back to one old state.

Claim C16. Adversary: `|C| ≤ f`, any number of rolled-back disks; keys need tier 0 intact on `t` nodes or `E`. Conditional on O5, O10, O17.

#### Scenario: Every disk rolled back

- **WHEN** all nine disks roll back to the state of one hour ago and the committee restarts
- **THEN** no slot signs two tickets and every key opens from tier 0

### Requirement: CP-039 Bounded loss

**CP-039** The committee node SHALL burn at a whole-committee restart at most `B` usable committee indices plus the pending indices for each checkpoint read and pool, plus `B` indices for each seat that syncs after a rollback of every disk, plus the unused ECDSA slots of every address.

Each checkpoint that moves `restart_seq` jumps the window (CP-041, DECISIONS 69).

Claim C16. The requests that held burned slots end VOID (RQ-048).

#### Scenario: Count of burned usable slots

- **WHEN** a node read one checkpoint with `B = 200` and three pending indices in one pool
- **THEN** it burns at most 203 usable indices of that pool

### Requirement: CP-040 Pending floor lowered

**CP-040** If a checkpoint has `pending_min` below the `pending_min` of the previous landed checkpoint for any committee pool, then the committee contract SHALL refuse the checkpoint with the code `pending_min_lowered`.

An honest committee never lowers its pending floor (CP-014, DECISIONS 71). A committee application restarted from rolled-back disks could name an old index pending again (Sessions SS-146, D-039, DECISIONS 69).

#### Scenario: Old index pending again

- **WHEN** a checkpoint shows `pending_min = 1` after a landed `pending_min = 3`
- **THEN** the checkpoint is refused

### Requirement: CP-041 Jump on a moved restart marker

**CP-041** Where `slot_anchor` is off, if a checkpoint `cp2` after the landed checkpoint `cp1` has a `restart_seq` other than that of `cp1` and, for any committee pool, has `cp2.h < cp1.h + B` or `cp2.pending_min ≤ cp1.h + B`, then the committee contract SHALL refuse `cp2` with the code `restart_jump`.

Seats that sync one at a time keep `w + 1` boot counters between checkpoints, so CP-009 never fires for them (Sessions SS-147, DECISIONS 69).

#### Scenario: Seats sync one at a time

- **WHEN** checkpoint 502 moves `restart_seq` from 501 to 502 and keeps `h` at `cp1.h + 10` with `B = 200`
- **THEN** the checkpoint is refused

### Requirement: CP-042 Lost restore statement

**CP-042** If a ledger read shows that the board lost a `RestoreDone` statement of the node before a landed checkpoint covered it, then the committee node SHALL append the statement again.

The node keeps the statement in RAM. A checkpoint that lands before the new append records no boot counter for the seat (Sessions SS-145, D-037, DECISIONS 69).

#### Scenario: Board tail lost

- **WHEN** the board loses the tail that held the `RestoreDone` of node 4 before checkpoint 502 covered it
- **THEN** node 4 appends the statement again

### Requirement: CP-043 Later ledger view not verified

**CP-043** If a ledger view after the first verified one does not read or does not verify, then the committee node SHALL keep the last verified view and answer not ready with the code `ledger_unverified` to every restart decision and release that needs a verified view until a new view verifies.

A later unverified view never replaces authenticated restart state or coverage (Sessions D-044, DECISIONS 69).

#### Scenario: Forged coverage

- **WHEN** a later ledger view claims coverage of a put entry and does not verify
- **THEN** the node keeps the last verified view and binds nothing on that coverage
