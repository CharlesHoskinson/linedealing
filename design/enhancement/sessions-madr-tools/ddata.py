"""Single source for the D records of seald Sessions (BASE-001 r1).

render.py writes decisions/D-NNN.md, the decisions array of baseline.yaml
and traceability.yaml from this data.
"""

OWNER = "The owner, confirmed 2026-11-14 in the working session (mpcexperiments LOOP.md log, 2026-11-14)."
LEAD = "Lead decision under owner AFK delegation, 2026-11-14."
LEAD18 = LEAD + " Recorded in the item 18 log entry of mpcexperiments LOOP.md."
LEAD19 = LEAD + " Recorded in sessions-review/TRIAGE.md, table \"Decisions for MADR (item 27)\"."

# Check handles. Items 21 to 24 have not run. ran() marks an item 20 check that the lead ran in item 28.
def q(qi, what):
    return {"item": 22, "check": qi, "what": what}

def lean(task, what):
    return {"item": 21, "check": f"tasks.md {task}", "what": what}

def proto(what):
    return {"item": 20, "check": "proto/sessions-sim", "what": what}

def ran(test, what):
    """A prototype check that the lead ran on the fixed rules (item 28)."""
    return {"item": 20, "check": f"proto/sessions-sim {test}", "what": what, "status": "passed"}

def prod(task, what):
    return {"item": 24, "check": f"tasks.md {task}", "what": what}


D = []

D.append(dict(
    id="D-001", title="Sessions are bound to one seat",
    state="confirmed", basis="explicit", authority=OWNER,
    source_refs=["SRC-001", "SRC-008"],
    design_decision=1,
    context=(
        "A session holds Shamir shares and node-local secrets of one seat. After a failure, some enclave must open the session again. "
        "The question is which enclaves may open it: only the holder of the latest boot ticket of the seat, or any admitted node of the committee."
    ),
    drivers=[
        ("SS-006", "The session id is a function of the committee, the seat and the purpose."),
        ("SS-007", "The session key input names the seat."),
        ("SS-012", "A peer serves a partial only when every check of the requester passes."),
        ("SS-014", "A peer refuses a requester that does not hold the latest boot ticket of the seat."),
        ("G5", "No operator, cloud service or single enclave derives a session key alone."),
    ],
    options=[
        ("Seat-bound sessions",
         "Only the enclave that holds the latest boot ticket of seat `node_index` opens the sessions of that seat.",
         ["No enclave holds two shares of one committee secret.", "A replacement VM in the same seat reopens the sessions."],
         ["The sessions of a lost seat stay closed until the operator gives the seat a new VM and ticket."]),
        ("Node-portable sessions",
         "Any admitted node of the committee opens the session of any seat.",
         ["A live node can take over the work of a dead seat at once."],
         ["One enclave then holds two shares of one secret, and the threshold `t` falls by one for each takeover."]),
        ("Seat-bound with transfer",
         "Sessions are seat-bound, and an operator-approved transfer moves a session to another seat.",
         ["A seat can be drained without a VM replacement."],
         ["The transfer is the node-portable case behind one more approval, with the same threshold loss."]),
    ],
    chosen="Seat-bound sessions",
    rationale="It is the only option that keeps one share of each secret in one enclave. A lost seat comes back through a replacement VM in the same seat.",
    consequences=[
        ("Good", "The threshold of each committee secret stays `t` after any restore."),
        ("Good", "A replacement VM with a blank disk reopens the sessions of its seat (SS-033, SS-036)."),
        ("Bad", "A dead seat contributes nothing until the operator runs the replacement path."),
        ("Neutral", "Peers check the latest boot ticket of the seat on every partial (SS-014)."),
    ],
    confirmation=[
        ("conformance", "Model the requester checks of `session_partial` in the oracle, one branch for each refusal.", ["SS-012", "SS-013", "SS-014", "SS-015", "SS-017"], lean("2.6", "apply branches for SS-012 to SS-017")),
        ("conformance", "Test that `peer.rs` refuses a requester without the latest boot ticket of the seat, and a request that names another committee or the receiving peer's own seat.", ["SS-014", "SS-017"], prod("5.2", "peer request checks")),
        ("outcome", "Replace one VM with a blank disk and check that the new VM of the seat reopens every session of the seat.", ["G1", "SS-033", "SS-036"], proto("replaceSlot row of the failure table")),
    ],
    revisit_when=[
        "A design needs one enclave to hold the shares of two seats.",
        "The threshold rule `t = n − f` changes.",
        "Rotation or reshare (split-line DESIGN §8) moves shares between seats.",
    ],
    affected=["CTX-001", "AGG-001", "CON-002", "MOD-001", "MOD-002"],
    obligations=["SS-006", "SS-007", "SS-012", "SS-014", "SS-017"],
    consumed=[],
))

D.append(dict(
    id="D-002", title="A whole-committee restart burns the reservation window and the pending slots",
    state="confirmed", basis="explicit", authority=OWNER,
    source_refs=["SRC-001", "SRC-004", "SRC-006", "SRC-007", "SRC-008"],
    design_decision=2,
    context=(
        "After a whole-committee restart, fewer than `w + 1` seats are continuous, and tier 0 of more than `c` seats can be rolled back. "
        "The witness fence of split-line DESIGN §7.7 then does not hold. A rolled-back record can show a nonce slot as `free` after the node bound it and released a partial on it. "
        "The question is how the committee stops each reuse of a slot without an outside anchor for each binding."
    ),
    drivers=[
        ("G3", "A whole-committee restart, also from rolled-back disks, never reuses a nonce slot."),
        ("SS-063", "The window upper bound limits a bind to `cp.h + B`."),
        ("SS-064", "The window lower bound refuses an index at or below `cp.h` that is not pending."),
        ("SS-067", "The node classifies a whole-committee restart from the ledger."),
        ("SS-068", "The restart burn of a sequential pool."),
        ("SS-104", "The contract forces the jump of `h` after a restart."),
        ("SS-114", "The restart burn of an account pool."),
        ("ASM-001", "The fence holds only for `c ≤ n − 1 − 2f`."),
    ],
    options=[
        ("Burn the window and the pending slots",
         "Burn `(h_cp, h_cp + B]` and every slot of a request pending at the latest checkpoint, and void those requests, unless the charter sets `anchor_before_release`.",
         ["No ledger write per bind.", "The loss has a bound that the committee sets with `B`."],
         ["Requests that hold burned slots end VOID, and the owner posts them again."]),
        ("Always anchor each binding",
         "Make `anchor_before_release` mandatory for every charter.",
         ["A restart burns nothing and voids nothing (SS-073)."],
         ["Each bind waits for one Midnight write."]),
        ("Burn the whole pool and deal again",
         "Discard every slot share after a restart and run a fresh slot dealing (split-line DESIGN §7.11 step 1).",
         ["No slot state survives a rollback, so no analysis of burn sets is necessary."],
         ["Every unused slot is lost, and the pool is empty until the dealing completes."]),
    ],
    chosen="Burn the window and the pending slots",
    rationale="It stops reuse after a rollback of every disk with no ledger write per bind. Charters that accept the write cost choose the anchored mode instead.",
    consequences=[
        ("Good", "No nonce slot is used twice, also when every disk was rolled back to one old state (SS-068)."),
        ("Good", "Slots above `h_cp + B`, the keys and the sessions resume."),
        ("Bad", "The requests that hold burned slots end VOID (SS-036, SS-041 return `burned`)."),
        ("Bad", "The loss bound holds only when the app reserves sequential-pool indices in increasing order with no gaps. Review finding A-F19 shows that the bound is false for out-of-order reservation. SS-064 retires each index at or below `h` that is not pending. A skipped index is therefore lost at the next checkpoint, with or without a restart. Reservations at 200, 400, 600, 800 and 1000 lose 995 unused indices before any restart. D-011 records the reservation order."),
        ("Bad", "Nodes that read different latest checkpoints at the restart burn the union of their sets, so the loss can pass one window (review finding B-F7, SS-113)."),
        ("Bad", "The account-pool burn widens the loss beyond the two sets that this decision names. A node that classifies the restart burns every `free` and `bound` slot of each account-pool session (SS-114). Every other node burns them at its first open after the restart checkpoint (SS-123, D-024). A whole-committee restart therefore consumes the unused account-pool supply of every seat. Only the recovery group path of split-line DESIGN §7.11 reprovisions it (D-018)."),
        ("Neutral", "Anchored charters burn nothing and pay one ledger write per bind (SS-070, SS-073)."),
    ],
    confirmation=[
        ("outcome", "Check that no nonce slot releases partials for two digests after a rollback of every disk, with checkpoints during the restart and a late boot.", ["G3", "SS-064", "SS-068", "SS-104", "SS-113"], q("QI-06", "same burn sets, late node never binds a burned slot")),
        ("outcome", "Check that a session created after the restart never binds an index of the burn sets.", ["SS-041", "SS-068"], q("QI-13", "session created after the restart")),
        ("conformance", "Prove that no bound nonce slot stays `free` after a whole-committee restart.", ["SS-068"], lean("2.7", "invariant for SS-068")),
        ("outcome", "Run a total restart with coordinated disk rollback and record the slots lost per pool.", ["G3", "SS-068", "SS-114"], proto("total restart and coordinated rollback rows")),
        ("conformance", "Test the window, the restart decision and the burn on the mock ledger.", ["SS-063", "SS-064", "SS-067", "SS-068"], prod("5.5", "mock-ledger restart tests")),
    ],
    revisit_when=[
        "A Midnight write per bind becomes cheap enough to make `anchor_before_release` the default.",
        "The app stops reserving sequential-pool indices in increasing order (split-line DESIGN §4.1).",
        "Item 20 measurements show that the loss of `B` slots or of the account-pool supply per restart is too high.",
        "A QI-06 or QI-07 counterexample shows a reuse.",
    ],
    affected=["CTX-001", "CTX-004", "AGG-002", "INV-009", "CON-003", "JNY-003"],
    obligations=["SS-063", "SS-064", "SS-067", "SS-068", "SS-104", "SS-113", "SS-114"],
    consumed=[],
))

D.append(dict(
    id="D-003", title="The session key comes from the threshold PRF only",
    state="confirmed", basis="explicit", authority=OWNER,
    source_refs=["SRC-001", "SRC-004", "SRC-008"],
    design_decision=3,
    context=(
        "A replacement VM in the same seat has a new vTPM and a blank disk. It must derive the session key of its seat. "
        "The question is whether the session key also takes a factor from the local `K_tpm`."
    ),
    drivers=[
        ("G1", "A session survives a replacement VM in the same seat."),
        ("G5", "Each session key needs PRF partials from `t` distinct share holders."),
        ("SS-007", "The session key derivation."),
        ("SS-009", "The node combines exactly `t` valid partials."),
        ("SS-011", "The node erases the key after the operation."),
        ("SS-110", "Peers check the app image."),
    ],
    options=[
        ("Threshold PRF only", "`K_sess,v` is HKDF of the threshold PRF output and nothing else.",
         ["A replacement VM derives the key."],
         ["The app image is then the only gate on `session_get` inside the enclave."]),
        ("Threshold PRF and K_tpm", "`K_sess,v` is HKDF of the PRF output and a `K_tpm`-sealed local secret.",
         ["An operator with a custom app disk cannot read the sessions."],
         ["A replacement VM cannot open the sessions of its seat, so G1 fails."]),
        ("K_tpm only", "The local vTPM seals the session.",
         ["No peer takes part in an open."],
         ["Every VM loss loses the sessions, so G1 fails."]),
    ],
    chosen="Threshold PRF only",
    rationale="Only this option lets a replacement VM in the seat reopen the sessions. SS-110 closes the gap that the missing `K_tpm` factor leaves.",
    consequences=[
        ("Good", "A replacement VM reopens the sessions of its seat."),
        ("Bad", "The requesting enclave rebuilds the whole symmetric key, so the scheme gives no threshold decryption (review finding A-F14). G5 states what holds: `t` share holders take part, and the key leaves RAM after one operation."),
        ("Bad", "Without `K_tpm`, an operator can boot the seat with an own app disk and read every secret of the seat through `seald.sock` (review finding B-F1). SS-110 and D-019 add that check. It needs the TLS evidence out of PCR15 (ASM-003)."),
        ("Neutral", "Confidentiality against `t` colluding broken enclaves stays a non-goal."),
    ],
    confirmation=[
        ("conformance", "Check the key derivation against the golden vectors of the reference suite.", ["SS-007", "SS-008"], prod("5.7", "golden vector tests in seald")),
        ("conformance", "Test that evidence with an unapproved PCR15 value gets `bad_evidence`.", ["SS-110"], prod("5.2", "peer app-image check")),
        ("outcome", "Replace a VM with a blank disk and open each session of the seat with `t` peer partials.", ["G1", "SS-009"], proto("replaceSlot row of the failure table")),
    ],
    revisit_when=[
        "Guide recommendation 5 (TLS evidence out of PCR15) cannot be implemented.",
        "A threshold decryption scheme fits the record size and latency budget.",
        "An approved app image is found to leak session values.",
    ],
    affected=["CTX-001", "CTX-002", "AGG-001", "CON-002"],
    obligations=["SS-007", "SS-009", "SS-011", "SS-110"],
    consumed=[],
))

D.append(dict(
    id="D-004", title="The PRF share σ_i is sealed in tier 0",
    state="confirmed", basis="explicit", authority=OWNER,
    source_refs=["SRC-001", "SRC-004", "SRC-009", "SRC-008"],
    design_decision=4,
    context=(
        "The PRF share `σ_i` lives in RAM in the current code. After a whole-committee restart no node holds it, so no node derives a session key until the recovery group acts. "
        "The question is whether `σ_i` is sealed in tier 0 under `K_tpm`, as split-line DESIGN §7.4 specifies."
    ),
    drivers=[
        ("G1", "A session survives a whole-committee restart."),
        ("SS-074", "The PRF share in tier 0."),
        ("SS-075", "The PRF share loads at boot."),
        ("SS-079", "`close_epoch` erases the share from RAM and tier 0."),
        ("SS-097", "The share loads with a late epoch record."),
    ],
    options=[
        ("Tier 0 under K_tpm", "Seal `σ_i` in tier 0 under `K_tpm`.",
         ["`t` nodes with intact disks restart without the recovery group."],
         ["A disk snapshot holds `σ_i`."]),
        ("RAM only", "Keep `σ_i` in RAM, and restore it through the recovery group after a whole-committee restart (guide recommendation 2).",
         ["No disk snapshot holds `σ_i`."],
         ["Every whole-committee restart needs the recovery group, and the production binary has no recovery group transport."]),
    ],
    chosen="Tier 0 under K_tpm",
    rationale="It closes guide recommendation 2 in favor of a restart without the recovery group for the session keys and the sequential pools.",
    consequences=[
        ("Good", "`t` nodes with intact tier 0 derive session keys after a whole-committee restart."),
        ("Bad", "A rollback of the disks of more than `c` seats reopens erased entries and closed-epoch shares inside the enclaves (review findings A-F1, B-F11). G4 states its bound. The window burn, `slot_stale` and the monotone `h` still stop each reuse of a slot."),
        ("Bad", "The restart without the recovery group does not cover account-pool slot supply. D-002, D-018 and D-024 burn every unused account-pool slot at a whole-committee restart, and only the recovery group reprovisions them."),
        ("Neutral", "Split-line DESIGN §2.2, §4.5, §7.4, §7.8, §7.11 and claim C16 change from \"RAM only\" to \"session-sealed, witness-fenced\" (item 25)."),
    ],
    confirmation=[
        ("conformance", "Test the tier-0 load at boot, the mismatch check and the erase in `close_epoch`.", ["SS-074", "SS-075", "SS-076", "SS-079"], prod("5.3", "group.rs and store.rs tests")),
        ("outcome", "Check that no PRF share is erased while a session of any seat needs its epoch.", ["SS-078", "SS-079", "SS-080"], q("QI-10", "epoch close safety")),
        ("outcome", "Restart every node with `t` intact disks and open every session without the recovery group.", ["G1", "SS-075"], proto("total restart row")),
    ],
    revisit_when=[
        "A rollback-protected store (for example a TPM NV counter) becomes available for tier 0.",
        "The committee needs account-pool signing to restart without the recovery group.",
    ],
    affected=["CTX-001", "AGG-001", "INV-011"],
    obligations=["SS-074", "SS-075", "SS-076", "SS-077", "SS-079", "SS-097"],
    consumed=[],
))

# ---- item 18 open-question decisions ----

D.append(dict(
    id="D-005", title="Classify a whole-committee restart from the ledger at w + 1 continuous seats",
    state="provisional", basis="proposed", authority=LEAD18,
    source_refs=["SRC-001", "SRC-002", "SRC-008"],
    context=(
        "At boot a node must decide if the fence of split-line DESIGN §7.7 still holds. A rolled-back node cannot tell from its own disk. "
        "The question is which data and which threshold decide a whole-committee restart. The item 18 decision keeps the `w + 1` threshold and sends it to the item 22 Quint model."
    ),
    drivers=[
        ("SS-067", "The restart decision."),
        ("SS-098", "No checkpoint at boot."),
        ("SS-106", "An unreadable ledger snapshot keeps the node `not_ready`."),
        ("SS-113", "A running node also classifies."),
        ("G3", "A whole-committee restart never reuses a nonce slot."),
    ],
    options=[
        ("Ledger, w + 1 continuous seats", "A seat is continuous when its latest boot counter equals the counter in the latest checkpoint. Fewer than `w + 1` continuous seats is a whole-committee restart.",
         ["A rolled-back node decides the same way as an intact node.", "With `w + 1` continuous seats, a committed version has `w` acks among peers that kept their state."],
         ["The decision needs a verified ledger snapshot at every boot."]),
        ("Ledger, n − c continuous seats", "Use the collusion bound of the fence as the threshold.",
         ["The threshold follows the fence bound exactly."],
         ["`c` counts colluding operators, which no node can observe."]),
        ("Own disk and witness log", "The node decides from its own records.",
         ["No ledger read at boot."],
         ["A rolled-back node sees an old, consistent state and decides wrong."]),
    ],
    chosen="Ledger, w + 1 continuous seats",
    rationale="Only the ledger gives every node the same view after a rollback, and the threshold uses quantities that each node can count.",
    consequences=[
        ("Good", "Every node that reads one checkpoint decides the same way."),
        ("Bad", "A ledger outage at boot keeps the node `not_ready` (SS-106)."),
        ("Neutral", "The item 22 model checks the threshold, the fork tie at `n = 3f + 1` (D-016) and the late-node rule (D-013)."),
    ],
    confirmation=[
        ("outcome", "Check that a wave of small rollbacks never passes as continuous seats.", ["SS-067", "SS-112", "SS-117"], q("QI-05", "wave rollback")),
        ("outcome", "Check that every node burns the same sets and that a three-seat reboot does not stall the pool forever.", ["SS-067", "SS-113"], q("QI-06", "restart liveness")),
        ("outcome", "Check that a ledger read failure never sets `whole_restart = false`.", ["SS-098", "SS-106"], q("QI-14", "ledger read failure")),
    ],
    revisit_when=[
        "The item 22 model finds a trace in which `w + 1` continuous seats do not keep the fence.",
        "The committee size or `f` changes the relation between `w` and `c`.",
    ],
    affected=["CTX-001", "CON-003", "JNY-003"],
    obligations=["SS-067", "SS-098", "SS-106"],
    consumed=[],
))

D.append(dict(
    id="D-006", title="The reservation window applies under anchor_before_release too",
    state="provisional", basis="proposed", authority=LEAD18,
    source_refs=["SRC-002", "SRC-008"],
    context=(
        "With `anchor_before_release`, a restart burns nothing, because the ledger anchors every binding. "
        "The question is whether `slot_bind` still applies the window bounds and the checkpoint precondition in that mode. The item 18 decision keeps one rule for both modes."
    ),
    drivers=[
        ("SS-063", "Window upper bound."),
        ("SS-064", "Window lower bound."),
        ("SS-065", "No checkpoint."),
        ("SS-066", "Bind reads the latest checkpoint."),
        ("SS-090", "Refusal order for app operations."),
    ],
    options=[
        ("One window rule for both modes", "SS-063 to SS-066 apply in both modes. Only the restart jump (SS-104) and the pruning (SS-108) exclude anchored charters.",
         ["`slot_bind` has one refusal list and one order in both modes."],
         ["An anchored charter still needs a checkpoint before a bind and stays inside the window."]),
        ("No window under anchor_before_release", "Anchored charters bind any unclaimed index.",
         ["No throughput limit from `B` in the anchored mode."],
         ["Two bind paths with different refusals, and a charter that changes mode crosses between them."]),
    ],
    chosen="One window rule for both modes",
    rationale="One rule keeps the bind refusals and their order the same for every charter.",
    consequences=[
        ("Good", "The oracle, the model and the code have one bind path."),
        ("Bad", "An anchored charter is limited to `B` binds between checkpoints."),
    ],
    confirmation=[
        ("outcome", "Check that no slot releases for a digest other than its anchor, with the window in force.", ["SS-063", "SS-064", "SS-070", "SS-073"], q("QI-12", "anchored mode")),
        ("conformance", "Pin each window edge of SS-063 and SS-064.", ["SS-063", "SS-064"], lean("2.9", "window edges")),
    ],
    revisit_when=["Anchored charters need more than `B` binds between two checkpoints."],
    affected=["CTX-001", "AGG-002"],
    obligations=["SS-063", "SS-064", "SS-065", "SS-066"],
    consumed=[],
))

D.append(dict(
    id="D-007", title="session_close discards changes that have no checkpoint",
    state="provisional", basis="proposed", authority=LEAD18,
    source_refs=["SRC-002", "SRC-008"],
    context="The question is what `session_close` does with a working copy that differs from version `v`. The item 18 decision keeps SS-047 as written.",
    drivers=[
        ("SS-047", "Close a session."),
        ("SS-024", "Too few acks."),
        ("SS-118", "Retry of an unsealed erasure."),
    ],
    options=[
        ("Discard", "Zeroize `work` and lose the changes since the last checkpoint.",
         ["Close needs no quorum and never fails with `no_quorum`."],
         ["The app loses changes that it did not checkpoint."]),
        ("Checkpoint on close", "Seal and witness `work` before the close.",
         ["No change is lost."],
         ["Close can fail with `no_quorum`, and the session then stays open in RAM."]),
        ("Refuse while dirty", "Refuse `session_close` while `dirty = true`.",
         ["The app must decide."],
         ["A session with no quorum cannot leave RAM."]),
    ],
    chosen="Discard",
    rationale="Close always succeeds and always erases. The app calls `session_checkpoint` first when it needs the changes.",
    consequences=[
        ("Good", "Close is a local erase with no network step."),
        ("Bad", "The app must checkpoint before close. Burns and destroys checkpoint before they return success (SS-057, SS-046), so close never undoes an erasure that returned success."),
    ],
    confirmation=[
        ("conformance", "Model `session_close` as an erase of `work` in the oracle.", ["SS-047"], lean("2.6", "apply branch for SS-047")),
        ("outcome", "Check that a burn or destroy that returned success is in a version with `w` acks.", ["SS-057", "SS-058", "SS-118"], q("QI-11", "erasure durability")),
    ],
    revisit_when=["An app needs close to persist its changes."],
    affected=["AGG-001", "CON-001"],
    obligations=["SS-047"],
    consumed=[],
))

D.append(dict(
    id="D-008", title="The refusal order stands as written",
    state="provisional", basis="proposed", authority=LEAD18 + " Review finding B-F17.3 asked for one change, which the triage rejected.",
    source_refs=["SRC-002", "SRC-004", "SRC-008"],
    context="When more than one refusal applies, the node must return one code. The oracle, the model and the code must return the same one. The question is the order.",
    drivers=[
        ("SS-089", "A refusal changes nothing."),
        ("SS-090", "Refusal order for app operations."),
        ("SS-091", "Refusal order for peer requests."),
    ],
    options=[
        ("Order as written", "Cheap checks first. The ticket check (`not_current`) comes before the evidence check (`bad_evidence`).",
         ["The ticket check reads only the ledger and is cheaper."],
         ["A requester with bad evidence and an old ticket learns that its ticket is old."]),
        ("Evidence before ticket", "Move `bad_evidence` before `not_current` (review finding B-F17.3).",
         ["The evidence verdict comes first."],
         ["Each refused request pays the evidence verification."]),
    ],
    chosen="Order as written",
    rationale="The cheaper ledger check runs first, and the order is fixed for the formal pipeline.",
    consequences=[
        ("Good", "One deterministic code for each refused request."),
        ("Neutral", "The order is part of the golden vectors (tasks.md 4.5)."),
    ],
    confirmation=[
        ("conformance", "Define the closed refusal type and `refusals` in the order of SS-090 and SS-091.", ["SS-090", "SS-091"], lean("2.5", "refusal order")),
        ("conformance", "Prove that each refusal leaves the state unchanged.", ["SS-089"], lean("2.8", "SS-089")),
        ("conformance", "Check the refusal codes of production `seald` against the golden vectors.", ["SS-090", "SS-091"], prod("5.7", "golden vector tests")),
    ],
    revisit_when=["A new refusal code is added.", "A check moves to another cost class."],
    affected=["CON-001", "CON-002"],
    obligations=["SS-089", "SS-090", "SS-091"],
    consumed=[],
))

D.append(dict(
    id="D-009", title="B and S_max are committee parameters set from measurement",
    state="provisional", basis="proposed", authority=LEAD18,
    source_refs=["SRC-002", "SRC-008"],
    context="The window `B` and the session size limit `S_max` bound the restart loss and the record size. No source gives their values. The item 18 decision sends both to the item 20 measurement.",
    drivers=[
        ("SS-004", "Committee parameters, with `B ≥ 1` and `1 ≤ S_max ≤ 2,097,152`."),
        ("SS-063", "Window upper bound."),
        ("SS-088", "Session too large."),
        ("SS-109", "Peer line limit."),
    ],
    options=[
        ("Measured committee parameters", "Keep `B` and `S_max` in the measured metadata and set their values from the item 20 measurement.",
         ["The values follow measured checkpoint rate and record cost."],
         ["The values stay open until item 20 completes."]),
        ("Fixed protocol constants now", "Write numbers into the spec today.",
         ["No open item."],
         ["The numbers would have no source."]),
    ],
    chosen="Measured committee parameters",
    rationale="The profile forbids invented targets, and the spec already bounds both parameters.",
    consequences=[
        ("Good", "Each committee sets its own trade between restart loss and checkpoint rate."),
        ("Bad", "Q-002 stays open until item 20 reports."),
        ("Neutral", "The SS-004 scenario value `B = 200` is an example, not a decided value."),
    ],
    confirmation=[
        ("outcome", "Measure the restart loss against `B` and the record cost against `S_max`.", ["SS-004", "SS-063", "SS-088"], proto("parameter measurement")),
        ("conformance", "Test the metadata checks of `session_window` and `session_max_bytes`.", ["SS-004"], prod("5.6", "metadata checks")),
    ],
    revisit_when=["Item 20 reports its measurements.", "The checkpoint interval changes."],
    affected=["CON-006", "Q-002"],
    obligations=["SS-004", "SS-088"],
    consumed=[],
))

D.append(dict(
    id="D-010", title="The record travels in the witness message, on a 4 MiB peer line",
    state="provisional", basis="proposed", authority=LEAD18 + " Item 19 then set the limit in SS-109.",
    source_refs=["SRC-002", "SRC-004", "SRC-008"],
    context="A record of `S_max` bytes does not fit the current 1 MiB peer line (review findings A-F17, B-F15.1). The item 18 decision sent the record size and the wire encodings to item 24.",
    drivers=[
        ("SS-022", "The witness carries the record."),
        ("SS-026", "A peer acks the same version again and writes a lost replica."),
        ("SS-109", "Peer line limit for sessions."),
    ],
    options=[
        ("Raise the session line limit", "Accept peer session lines of up to 4,194,304 bytes.",
         ["An ack still proves that the peer holds the ciphertext."],
         ["A peer reads up to 4 MiB for one request."]),
        ("Chunked transfer", "Send the record in parts and ack the last part.",
         ["Lines stay at 1 MiB."],
         ["An ack no longer covers one message, and the peer needs state between parts."]),
    ],
    chosen="Raise the session line limit",
    rationale="It keeps one message for each witness, which SS-022 and SS-026 depend on.",
    consequences=[
        ("Good", "No new peer state between messages."),
        ("Bad", "Memory per peer connection rises for session requests."),
        ("Neutral", "The wire encodings and labels (review finding B-F17.1) go to the golden vectors of the reference suite."),
    ],
    confirmation=[
        ("conformance", "Send a record of `S_max` bytes and check that each peer reads it.", ["SS-109"], prod("5.2", "peer line limit test")),
    ],
    revisit_when=["`S_max` rises above 2 MiB.", "The peer transport changes."],
    affected=["CON-002"],
    obligations=["SS-109"],
    consumed=[],
))

D.append(dict(
    id="D-011", title="Sequential pools reserve in index order and lose skipped indices",
    state="provisional", basis="proposed", authority=LEAD18 + " Item 19 restated the loss (review finding A-F19).",
    source_refs=["SRC-001", "SRC-002", "SRC-006", "SRC-008", "SRC-009"],
    context=(
        "Split-line DESIGN §4.1 lets a request name any unclaimed slot. The window lower bound (SS-064) refuses each index at or below `cp.h` that is not pending. "
        "The question is how the app reserves indices of a sequential pool, and what happens to an index that it skips."
    ),
    drivers=[
        ("SS-063", "Window upper bound."),
        ("SS-064", "Window lower bound."),
        ("G3", "The restart loss of a sequential pool."),
    ],
    options=[
        ("Index order with a lower bound", "The app reserves in increasing order. A skipped index falls below `h` at the next checkpoint and is lost.",
         ["One scalar `h` per pool on Midnight."],
         ["A skipped index is lost."]),
        ("Holes on Midnight", "The checkpoint records the unused indices below `h`.",
         ["No index is lost."],
         ["The checkpoint grows with the holes."]),
        ("No lower bound", "Accept a bind at or below `h`.",
         ["No index is lost."],
         ["A slot at or below `h_cp` bound after the checkpoint is in neither burn set, so a restart can reuse it."]),
    ],
    chosen="Index order with a lower bound",
    rationale="The lower bound is necessary for G3, and one scalar per pool keeps the checkpoint small.",
    consequences=[
        ("Bad", "Split-line DESIGN §4.1 narrows for sequential pools: a request may not name any unclaimed slot. Item 25 maps this."),
        ("Bad", "The reservation order and the vote bound of the app have no requirement in an authoritative spec (Q-001)."),
    ],
    confirmation=[
        ("outcome", "Check that pruning and the lower bound never let a second digest bind.", ["SS-064", "SS-108"], q("QI-09", "covered entries")),
        ("conformance", "Pin each window edge of SS-063 and SS-064.", ["SS-063", "SS-064"], lean("2.9", "window edges")),
    ],
    revisit_when=["Split-line DESIGN §4.1 keeps free slot choice for sequential pools.", "Item 20 shows a high hole rate."],
    affected=["CTX-001", "CTX-003", "AGG-002", "Q-001", "Q-003"],
    obligations=["SS-063", "SS-064"],
    consumed=[],
))

# ---- TRIAGE choices (item 19) ----

D.append(dict(
    id="D-012", title="A blank-tier-0 peer rebuilds its entries for other seats before it serves",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-006"],
    context="A peer that boots with a blank tier 0 has lost the fence entries it held for other seats. A series of such replacements erases the fence of a seat with no collusion (review finding A-F2).",
    drivers=[("SS-102", "Peer state rebuilt on a blank tier 0."), ("SS-016", "Peer refuses an old version.")],
    options=[
        ("Peer-state sync at boot", "Fetch the entries of other seats from `w` peers before any ack or partial.", ["Keeps the bound.", "No chain write."], ["Boot waits for `w` peers."]),
        ("Count each replaced peer as forgetful", "Shrink `c` for each replacement.", ["No new message."], ["The bound shrinks with each replacement until no fence is left."]),
        ("Anchor every version on Midnight", "Peers read versions from the ledger.", ["The ledger is the fence."], ["One chain write per checkpoint."]),
    ],
    chosen="Peer-state sync at boot",
    rationale="It keeps the fence bound and needs no chain write.",
    consequences=[("Good", "Replacing peers one at a time never lowers the fence."), ("Bad", "A blank-tier-0 peer answers `unavailable` until the fetch completes.")],
    confirmation=[("outcome", "Replace peers one at a time with checkpoints between the replacements, and check that the fence never falls.", ["SS-102", "SS-016"], q("QI-02", "sequential peer replacement"))],
    revisit_when=["Peer churn makes the boot fetch too slow."],
    affected=["CTX-002", "INV-003"],
    obligations=["SS-102"],
    consumed=[],
))

D.append(dict(
    id="D-013", title="The committee contract enforces the checkpoint rules",
    state="provisional", basis="proposed", authority=LEAD19 + " The item 18 decision sends the late-node rule to the item 22 model.",
    source_refs=["SRC-004", "SRC-006", "SRC-007", "SRC-008"],
    context="`seald` reads the checkpoint but the committee application writes it. The question is where the rules on `h`, the restart jump and anchors are enforced.",
    drivers=[("SS-103", "Floor only rises."), ("SS-104", "Checkpoint after a whole-committee restart."), ("SS-105", "One anchor for each nonce slot."), ("SS-117", "Checkpoint boot counters.")],
    options=[
        ("Contract rules", "The committee contract refuses a checkpoint that breaks a rule.", ["The rule binds every writer of the checkpoint."], ["The contract grows."]),
        ("seald checks the chain", "Each node checks the chain of checkpoints itself.", ["No contract change."], ["A node cannot stop a checkpoint that the app writes."]),
    ],
    chosen="Contract rules",
    rationale="Only the contract can refuse a checkpoint before nodes read it.",
    consequences=[("Good", "A node that boots after `cp2` relies on `slot_stale` against a checkpoint that the contract checked."), ("Bad", "G3 depends on contract code outside `seald` (item 24).")],
    confirmation=[
        ("outcome", "Check the wave rollback against the contract rules.", ["SS-103", "SS-117"], q("QI-05", "wave rollback")),
        ("outcome", "Check the late boot after `cp2` and a non-monotone `h` attempt.", ["SS-103", "SS-104"], q("QI-06", "late boot")),
        ("conformance", "Add the rules to the mock ledger and test each refusal.", ["SS-103", "SS-104", "SS-105", "SS-117"], prod("5.5", "mock-ledger contract tests")),
    ],
    revisit_when=["The Midnight contract cannot express a rule.", "The checkpoint writer changes."],
    affected=["CTX-004", "INV-005", "CON-003"],
    obligations=["SS-103", "SS-104", "SS-105", "SS-117"],
    consumed=[],
))

D.append(dict(
    id="D-014", title="A checkpoint records a boot counter only from a signed RestoreDone",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-007"],
    context="A checkpoint that records the boot counter of a rolled-back seat before that seat syncs makes the seat look continuous (review finding B-F6 path A).",
    drivers=[("SS-112", "Restore statement."), ("SS-117", "Checkpoint boot counters."), ("SS-067", "Restart decision.")],
    options=[
        ("Signed restore statement", "The seat signs `RestoreDone` after its sync, and the contract requires it.", ["A seat is continuous only after it synced."], ["One ledger write per boot."]),
        ("Compare counters across two checkpoints", "The contract compares boot counters of consecutive checkpoints.", ["No new statement."], ["The wave rollback of B-F6 passes this rule."]),
    ],
    chosen="Signed restore statement",
    rationale="It stops the wave rollback, and D-024 reuses the statement for the restart marker.",
    consequences=[("Good", "A series of small rollbacks cannot pass as continuous seats."), ("Neutral", "D-024 adds the field `whole_restart` to the statement.")],
    confirmation=[("outcome", "Build the B-F6 path A trace and check that it fails.", ["SS-112", "SS-117", "SS-067"], q("QI-05", "wave rollback"))],
    revisit_when=["The boot ticket itself proves the sync."],
    affected=["CTX-001", "CTX-004", "CON-004"],
    obligations=["SS-112", "SS-117"],
    consumed=[],
))

D.append(dict(
    id="D-015", title="Restore authenticates first and seals the result as a new version",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-006", "SRC-007"],
    context="Restore re-witnessed `v_max` and could not pass a peer with another digest of that version (A-F8). One faulty peer could make restore overwrite honest replicas before authentication (B-F2).",
    drivers=[("SS-030", "Version learned at the sync."), ("SS-031", "Candidate order."), ("SS-035", "No peer change before authentication."), ("SS-036", "Restore opens the record."), ("SS-111", "Signed version reports.")],
    options=[
        ("Re-witness v_max", "Witness the restored version again.", ["No new version."], ["Deadlocks on a split version."]),
        ("Authenticate, then seal v_max + 1", "Try candidates from the highest version down and seal the result as a new version.", ["No new message.", "The PRF fence keeps the fallback safe."], ["Each restore adds a version."]),
        ("Commit certificates", "Attach `w` signed acks to each version.", ["Restore knows the committed version."], ["A new message and a larger tier 0."]),
    ],
    chosen="Authenticate, then seal v_max + 1",
    rationale="It needs no new message, and a new version ends each split of one version into two records.",
    consequences=[("Good", "No peer state changes before a candidate authenticates."), ("Neutral", "Every restore increments the version.")],
    confirmation=[
        ("outcome", "Check that the fallback never opens a version below a committed one with `c` in bound.", ["SS-030", "SS-031", "SS-035", "SS-036"], q("QI-03", "restore fallback")),
        ("outcome", "Check that a split version never blocks restore with `n − f` live nodes.", ["SS-031", "SS-036"], q("QI-04", "split version")),
    ],
    revisit_when=["Commit certificates become necessary for another reason."],
    affected=["AGG-001", "JNY-001"],
    obligations=["SS-030", "SS-031", "SS-033", "SS-034", "SS-035", "SS-036"],
    consumed=[],
))

D.append(dict(
    id="D-016", title="A split version restores by plurality, then by the lower digest",
    state="provisional", basis="proposed", authority=LEAD19 + " The item 18 decision sends the fork tie at `n = 3f + 1` to the item 22 model.",
    source_refs=["SRC-004", "SRC-006", "SRC-008"],
    context="The PRF fence does not separate two records of one version. Restore must choose one.",
    drivers=[("SS-031", "Candidate order."), ("SS-032", "Restore with tied digests.")],
    options=[
        ("Plurality, then byte order", "Try the digest with the most signed reports, then the lower digest.", ["Deterministic, and the committed record wins when `c` is in bound."], ["Forgetful peers can change the order (design Limits)."]),
        ("Refuse with conflict", "Stop the restore.", ["No wrong choice."], ["Deadlock (A-F8)."]),
        ("Commit certificates", "Pick the certified record.", ["Exact."], ["A new message."]),
    ],
    chosen="Plurality, then byte order",
    rationale="It needs no new message and is deterministic. A new version follows the restore (D-015).",
    consequences=[("Bad", "Forgetful peers within the bound can make restore open the uncommitted record of a split version."), ("Neutral", "That record is a checkpoint that the same seat sealed.")],
    confirmation=[("outcome", "Check that the committed digest wins when `c` is in bound, also at `n = 3f + 1`.", ["SS-031", "SS-032"], q("QI-04", "split version tie"))],
    revisit_when=["The item 22 model shows a loss at `n = 3f + 1`."],
    affected=["AGG-001"],
    obligations=["SS-031", "SS-032"],
    consumed=[],
))

D.append(dict(
    id="D-017", title="Version reports carry the seat-signed witness statement",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-007"],
    context="One faulty peer reported a false high version and raised `v_max` (B-F2).",
    drivers=[("SS-111", "Signed version reports.")],
    options=[
        ("Signed statements", "A report counts only with the signature of the seat's boot key.", ["No count, and one forged report changes nothing."], ["Peers store the signature with each entry."]),
        ("f + 1 matching reports", "Trust a version that `f + 1` peers report.", ["No signature storage."], ["Colluding peers still forge."]),
    ],
    chosen="Signed statements",
    rationale="It stops a forged version from one peer with no count.",
    consequences=[("Good", "A faulty peer cannot raise `v_max`."), ("Neutral", "D-012 and D-024 reuse the signed statements.")],
    confirmation=[
        ("outcome", "Check that one faulty peer cannot raise `v_max` or change a replica.", ["SS-111"], q("QI-03", "forged report")),
        ("conformance", "Test that an unsigned report leaves `v_max` unchanged.", ["SS-111"], prod("5.2", "witness sync test")),
    ],
    revisit_when=["The boot key scheme changes."],
    affected=["CTX-002", "CON-002"],
    obligations=["SS-111"],
    consumed=[],
))

D.append(dict(
    id="D-018", title="Account pools have no window and burn at a whole-committee restart",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-007", "SRC-009"],
    context=(
        "ECDSA slots are per address. A checkpoint `h` for them shows the account on Midnight against split-line DESIGN §4.1, and the window bricks old addresses (review finding B-F9). "
        "The question is how account pools stay safe after a whole-committee restart."
    ),
    drivers=[("SS-004", "`sequential_pools` lists the sequential pools. Other sessions with slots are account pools."), ("SS-063", "The window applies to sequential pools only."), ("SS-065", "A bind in any pool needs a checkpoint."), ("SS-114", "Restart burn of an account pool.")],
    options=[
        ("Burn and reprovision", "A node that classifies the restart burns every `free` and `bound` account slot once per boot. The recovery group reprovisions unused slots under new indices.", ["No account data on Midnight."], ["Every unused account slot of the seat is lost at a restart."]),
        ("Per-address h on Midnight", "Give each account pool its own floor.", ["Small loss."], ["Shows each account on Midnight."]),
        ("Board reconciliation in seald", "`seald` reads the board claims.", ["Exact loss."], ["`seald` gains a board reader."]),
        ("Restart flag that late nodes read", "Carry the restart in a signed statement and the checkpoint.", ["Covers nodes that boot after the restart checkpoint."], ["New fields in three records."]),
    ],
    chosen="Burn and reprovision",
    rationale="It shows nothing on Midnight and reuses the recovery group path. The fourth option is adopted on top of it in D-024 for the nodes that boot after the restart checkpoint.",
    consequences=[("Bad", "A whole-committee restart burns the unused account-pool supply (D-002)."), ("Good", "D-024 closes the late-boot gap that this choice alone leaves.")],
    confirmation=[("outcome", "After a rollback of every disk, check that a node that classifies the restart never releases an account-pool slot for two digests.", ["SS-065", "SS-114"], q("QI-07", "account-pool burn"))],
    revisit_when=["Account pools gain a privacy-preserving floor on Midnight."],
    affected=["CTX-001", "AGG-002", "D-024"],
    obligations=["SS-004", "SS-063", "SS-065", "SS-114"],
    consumed=[],
))

D.append(dict(
    id="D-019", title="Peers check the app image before they serve a session partial",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-007"],
    context="Without `K_tpm` in the session key (D-003), an operator with a custom app disk reads every secret of its seat (B-F1).",
    drivers=[("SS-110", "Peer checks the app image."), ("G5", "No operator derives a session key alone.")],
    options=[
        ("Pin PCR15", "Peers check the PCR15 value against the approved images, after guide recommendation 5.", ["Uses the existing evidence."], ["Needs the TLS evidence out of PCR15."]),
        ("Add K_tpm back", "Reintroduce the local factor.", ["No peer check."], ["Against owner decision 3."]),
        ("Approved app_root on the ledger", "Check the ticket's app root against a ledger list.", ["No PCR change."], ["Peers do not check `app_root` of a boot ticket today."]),
    ],
    chosen="Pin PCR15",
    rationale="It keeps decision 3 and uses the evidence that peers already verify.",
    consequences=[("Bad", "Depends on ASM-003 (guide recommendation 5).")],
    confirmation=[("conformance", "Test that evidence with another PCR15 value gets `bad_evidence`.", ["SS-110"], prod("5.2", "peer app-image check"))],
    revisit_when=["Guide recommendation 5 is not implemented."],
    affected=["CTX-002", "ASM-003"],
    obligations=["SS-110"],
    consumed=[{"id": "D-003", "version": 1}],
))

D.append(dict(
    id="D-020", title="Session operations run one at a time per session",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-006"],
    context="`seald` runs one thread per connection. A checkpoint of one call cleared `unsealed` for a binding that its record did not hold (A-F13).",
    drivers=[("SS-107", "One operation at a time."), ("SS-023", "Version becomes current at `w` acks.")],
    options=[
        ("One lock per session", "Run app operations, restore and rekey of one session one at a time.", ["Simple, and the operations are short."], ["A slow checkpoint delays the next call."]),
        ("Per-binding version tags", "Track which version holds each binding.", ["More parallel."], ["More state and more proof work."]),
    ],
    chosen="One lock per session",
    rationale="It is simpler, and the operations are short.",
    consequences=[("Good", "A checkpoint always seals the working copy that the next ack refers to.")],
    confirmation=[("outcome", "Interleave bind and checkpoint on one session and check that no unsealed binding releases.", ["SS-107", "SS-023"], q("QI-08", "interleaving"))],
    revisit_when=["Throughput per session becomes a limit."],
    affected=["AGG-001", "INV-008"],
    obligations=["SS-107", "SS-023"],
    consumed=[],
))

D.append(dict(
    id="D-021", title="A running node burns too when the ledger shows a whole-committee restart",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-007"],
    context="Continuous nodes did not burn, so the pool stalled after a three-seat reboot (B-F7 part A).",
    drivers=[("SS-113", "Restart burn on a running node."), ("SS-120", "Restore statement of a running node.")],
    options=[
        ("Every node evaluates at each checkpoint", "A running node applies the burn when the ledger shows fewer than `w + 1` continuous seats.", ["All nodes burn the same sets."], ["Running nodes burn too."]),
        ("Only booting nodes burn", "The contract forces the jump.", ["Running nodes keep their slots."], ["The pool stalls."]),
    ],
    chosen="Every node evaluates at each checkpoint",
    rationale="All nodes burn the same sets, so the next checkpoint can pass the contract rule.",
    consequences=[("Good", "The pool moves again after a partial reboot that crosses the threshold."), ("Bad", "A second restart in one uptime of a running node does not burn again (Q-007).")],
    confirmation=[("outcome", "Check three-seat reboot liveness and a second restart in one uptime.", ["SS-113"], q("QI-06", "running node burn"))],
    revisit_when=["QI-06 finds a trace with a second restart in one uptime."],
    affected=["CTX-001", "JNY-003", "Q-007"],
    obligations=["SS-113", "SS-120"],
    consumed=[],
))

D.append(dict(
    id="D-022", title="Slot entries below cp.h that are not pending leave tier 0",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-006"],
    context="`slot` witness entries grow with no bound in tier 0 (A-F16).",
    drivers=[("SS-108", "Covered slot entries leave tier 0."), ("SS-064", "Window lower bound.")],
    options=[
        ("Prune covered entries", "Delete each entry that `slot_stale` already guards.", ["Tier 0 stays small with no new storage."], ["Depends on the lower bound."]),
        ("Move the log off tier 0", "Store the log on `/mnt/persist`.", ["No pruning rule."], ["The log loses tier-0 protection."]),
    ],
    chosen="Prune covered entries",
    rationale="It keeps tier 0 small with no new storage.",
    consequences=[("Neutral", "Anchored charters keep their entries (SS-108 excludes them).")],
    confirmation=[("outcome", "Roll back after a deletion and check that no second digest binds.", ["SS-108", "SS-064"], q("QI-09", "pruning"))],
    revisit_when=["The lower bound changes (D-011)."],
    affected=["CTX-002"],
    obligations=["SS-108"],
    consumed=[{"id": "D-011", "version": 1}],
))

D.append(dict(
    id="D-023", title="Epoch close waits for every session that any seat holds in that epoch",
    state="provisional", basis="proposed", authority=LEAD19,
    source_refs=["SRC-004", "SRC-006", "SRC-007"],
    context="`close_epoch` looked only at the node's own sessions, so three nodes could strand a fourth seat (A-F6, A-F7, B-F10).",
    drivers=[("SS-078", "Rekey."), ("SS-079", "Close an epoch."), ("SS-080", "Epoch in use.")],
    options=[
        ("Refuse while any entry has the epoch", "Refuse while tier 1, an own session, a local record or a peer entry of another seat uses the epoch.", ["Uses state that the node has."], ["A slow seat delays the close."]),
        ("Committee barrier on the ledger", "Close only after a ledger record shows that every seat rekeyed.", ["Exact."], ["A ledger write and a new record."]),
    ],
    chosen="Refuse while any entry has the epoch",
    rationale="It uses state that the node already has.",
    consequences=[("Bad", "A seat that never rekeys keeps the epoch open.")],
    confirmation=[("outcome", "Check that no PRF share is erased while a session of any seat needs it.", ["SS-078", "SS-079", "SS-080"], q("QI-10", "epoch close"))],
    revisit_when=["A seat that never rekeys blocks epoch close in practice."],
    affected=["INV-011"],
    obligations=["SS-078", "SS-079", "SS-080"],
    consumed=[],
))

D.append(dict(
    id="D-024", title="A restart marker burns the account pools of nodes that boot after the restart checkpoint",
    state="provisional", basis="proposed", authority=LEAD + " Closes blocking review finding B-F9 as item 27 requires.",
    source_refs=["SRC-002", "SRC-004", "SRC-005", "SRC-007", "SRC-009"],
    context=(
        "After a whole-committee restart, every node that classifies the restart burns its account pools (SS-114). "
        "A node that boots after the first checkpoint that follows the restart sees continuous seats and classifies no restart. "
        "If its disk was rolled back, it restores account slots as `free` that it bound before the rollback. The peers lost their `slot` entries in the same rollback, so the fence does not stop a second bind. "
        "Account pools have no floor on Midnight, so `slot_stale` does not stop it either. This is the open part of review finding B-F9. "
        "The question is how such a node learns that its account slots need a burn, without account data on Midnight."
    ),
    drivers=[
        ("G2", "No nonce slot is used for two tickets."),
        ("G3", "A whole-committee restart never reuses a nonce slot."),
        ("SS-114", "Restart burn of an account pool."),
        ("SS-065", "A bind in any pool needs a checkpoint."),
        ("SS-112", "Restore statement."),
        ("SRC-009", "Split-line DESIGN §4.1: slot ids never appear on Midnight."),
    ],
    options=[
        ("Restart marker", "`RestoreDone` gains the field `whole_restart`. A running node that classifies a restart also signs one (SS-120). The contract makes each checkpoint carry `restart_seq`, a monotone marker that becomes the checkpoint's own `seq` when a new flagged statement exists (SS-121, SS-122). Each session body holds `restart_mark`. A node that does not classify the restart burns an account-pool session when its mark is below the marker (SS-123). A node that classified it raises the mark at its next checkpoint (SS-125) and binds no account slot before the restart checkpoint exists (SS-124).",
         ["Covers a node that boots after any later checkpoint, not only the first one.", "Covers a session that the classifying node did not open in that boot.", "A rolled-back record carries an old mark and burns.", "One committee-wide number on Midnight shows no account."],
         ["Three records gain a field, and the contract gains two rules.", "Account binds wait for the restart checkpoint, about one checkpoint interval."]),
        ("Flag in one checkpoint", "The checkpoint that follows the restart carries `whole_restart`, and late nodes read it.",
         ["One field."],
         ["A node that boots after the next checkpoint sees no flag and does not burn."]),
        ("Burn account pools at every boot", "Every boot burns every account slot.",
         ["No new field."],
         ["Every reboot of one node loses its account supply."]),
        ("Contract derives the restart from boot counters", "The contract marks a restart when fewer than `w + 1` counters match between two checkpoints.",
         ["No node-signed flag."],
         ["The checkpoint writer controls which counters a checkpoint records, so a restart that spans two checkpoints never shows."]),
        ("Per-address floor on Midnight", "Give each account pool its own `h`.",
         ["Exact guard."],
         ["Shows each account on Midnight, against split-line DESIGN §4.1."]),
        ("Board reconciliation in seald", "`seald` reads the board claims of each account slot at open.",
         ["Exact loss."],
         ["`seald` gains a board reader for one case."]),
        ("Anchor account binds", "Make `anchor_before_release` mandatory for account pools.",
         ["Late nodes are safe through SS-072 and SS-119."],
         ["One ledger write per account bind, and the anchor record names the pool."]),
    ],
    chosen="Restart marker",
    rationale=(
        "It is the only option that guards every late node with no account data on Midnight and no burn at a normal reboot. "
        "The flag in one checkpoint, the candidate of the review triage, misses a node that boots after a later checkpoint, so the marker must persist and only rise. "
        "The node-signed flag avoids a restart that the contract cannot see in the boot counters. "
        "The bind gate keeps two restarts with no checkpoint between them from sharing one marker while a slot is bound."
    ),
    consequences=[
        ("Good", "Each account-pool session burns once for each whole-committee restart, on every node. A session whose record holds the latest marker burns nothing at a later open (SS-123), so reprovisioned slots survive normal reboots."),
        ("Good", "Anchored charters are unchanged: SS-072 and SS-119 already guard their late nodes."),
        ("Bad", "Every seat loses its unused account-pool supply at a whole-committee restart (D-002). The recovery group reprovisions it."),
        ("Bad", "A node that ran through the restart and never saw it on the ledger keeps a low mark and burns its account pools at its next boot."),
        ("Bad", "A node that classified the restart writes the marker only at the next checkpoint of each burned session (SS-125). If it reboots before that checkpoint, the session burns again, and slots put after the restart burn with it."),
        ("Neutral", "SS-104 keeps its boot-counter trigger for sequential pools. The marker does not change it."),
    ],
    confirmation=[
        ("outcome", "Build the late-boot trace of QI-07 (a node that boots after `cp2`, and also after `cp3`) and check that no account-pool slot releases for two digests.", ["SS-120", "SS-121", "SS-122", "SS-123", "SS-124", "SS-125"], q("QI-07", "late-boot trace, now expected to hold")),
        ("outcome", "Check the once property: a second open after the restart checkpoint burns no reprovisioned slot.", ["SS-123", "SS-125"], q("QI-07", "once per restart")),
        ("outcome", "Check two restarts with no checkpoint between them and a bind attempt between them.", ["SS-124"], q("QI-07", "two restarts, one marker")),
        ("conformance", "Model the marker fields and prove that no account-pool slot releases for two digests across a restart.", ["SS-123", "SS-124", "SS-125"], lean("2.7", "account-pool invariant across a restart")),
        ("outcome", "Run a total restart with rollback of every disk and a late boot, and check the account slots of the late node.", ["SS-123"], ran("tests/regressions.rs q06_late_boot_account_burns_via_marker", "late boot burns through the marker")),
        ("conformance", "Add `restart_seq` to the mock ledger and test both contract refusals.", ["SS-121", "SS-122"], prod("5.5", "mock-ledger marker tests")),
    ],
    revisit_when=[
        "Account pools gain a privacy-preserving floor on Midnight.",
        "QI-07 finds a trace that reuses an account slot.",
        "The checkpoint interval grows so far that the bind gate of SS-124 delays account signing too long.",
    ],
    affected=["CTX-001", "CTX-004", "AGG-002", "INV-006", "INV-009", "CON-003", "CON-004", "JNY-003"],
    obligations=["SS-002", "SS-005", "SS-008", "SS-069", "SS-112", "SS-120", "SS-121", "SS-122", "SS-123", "SS-124", "SS-125"],
    consumed=[{"id": "D-014", "version": 1}, {"id": "D-018", "version": 1}],
))


# ---------------------------------------------------------------------------
# Item 28: resolutions of the prototype questions Q-01 to Q-11
# (proto/sessions-sim/QUESTIONS.md). New records are provisional lead decisions.
# ---------------------------------------------------------------------------

LEAD28 = "Lead decision under owner AFK delegation, 2026-11-14."
OWNER_CONFIRMED = "The owner, confirmed 2026-11-14 in the working session."




D.append(dict(
    id="D-025", title="The blank-tier-0 fetch ignores the owner and rebuilds the replicas",
    state="provisional", basis="proposed", authority=LEAD28,
    source_refs=["SRC-002", "SRC-010"],
    context=(
        "A replaced seat fetches the fence of every other seat from `w` peers (SS-102 as D-012 wrote it). "
        "Prototype questions Q-01, Q-02 and Q-03 show a series that breaks it at `n = 4` and `n = 6`. Seat 0 commits version 2 at exactly `w` peers. "
        "Each of those peers is replaced in turn and fetches from seat 0 and a peer that missed version 2. Seat 0 has no entry for itself, so both answers show version 1. "
        "Then seat 0 rolls back its own disks and opens version 1: an erased entry opens again and a nonce slot releases a second digest. "
        "The answer set can miss the committed version exactly when the owner and the non-holders fill it, `1 + (n − 1 − w) ≥ w`, that is `w − 1 ≤ f`. "
        "Prototype question Q-05 shows a second gap: the fetch rebuilds the fence but no ciphertext, so after the series the session cannot open at all (G1)."
    ),
    drivers=[
        ("G2", "No nonce slot is used for two tickets within the bound."),
        ("G4", "A destroyed entry does not open again within the bound."),
        ("G1", "A session survives a replacement VM in the same seat."),
        ("SS-102", "Peer state rebuilt on a blank tier 0."),
        ("SS-016", "Partial fence."),
    ],
    options=[
        ("w + 1 answers, owner ignored, replicas fetched",
         "Fetch from `w + 1` peers. For each seat keep the highest signed version that a peer other than that seat reports. Fetch the replica of each kept entry (SS-126, SS-127).",
         ["At least `w` answers come from non-owners, and at most `f` of them miss a committed version, so one answer holds it whatever the owner does.",
          "A rolled-back or faulty owner cannot lower its own fence through the fetch.",
          "The replaced seat holds what it held before the loss, so it can leave the count of G2 (D-026)."],
         ["One more answer: the fetch needs `n − f` live seats, so it tolerates `f − 1` other unavailable seats.",
          "The fetch also moves the replicas, up to `S_max` per session of each other seat."]),
        ("Owner answers with its own latest statement",
         "Keep `w` answers and let each source include its own signed latest statement and slot entries (the candidate of question Q-01).",
         ["Smallest change.", "Prevents the traced series in the prototype."],
         ["A rolled-back owner answers with its old statement. With the owner among the `w` answers, the set can still miss the committed version when `w − 1 ≤ f`.",
          "Without replicas the session stays closed (question Q-05)."]),
        ("Count each replaced seat for ever",
         "Leave SS-102 and read G2 literally: every seat that ever lost tier 0 counts in `c`.",
         ["No change to the protocol."],
         ["After `c + 1` replacements over the life of a committee, G2 no longer holds. That contradicts the purpose of the fetch."]),
        ("A checkpoint after each replacement",
         "Require the owner of each session to checkpoint after each replacement before the next one.",
         ["The prototype shows that one owner checkpoint closes the exposure."],
         ["It binds every owner to the replacement schedule of other seats, and an owner that is down cannot comply."]),
    ],
    chosen="w + 1 answers, owner ignored, replicas fetched",
    rationale=(
        "It is the only option that holds for every owner state, also an owner that rolls back or lies about itself. "
        "The counting argument needs no assumption about the owner: a committed version has `w` acks, at most `f` non-owner peers miss it, "
        "and the in-bound losses at that time are fewer than `w − f`, so fewer than `w` non-owner answers can be stale. "
        "The replica fetch makes the replaced seat equal to an intact holder, which D-026 needs."
    ),
    consequences=[
        ("Good", "The series of questions Q-01 to Q-03 no longer opens an erased entry or releases a second digest at any of the five parameter sets of the prototype, and the owner session opens again (G1)."),
        ("Bad", "A blank-tier-0 fetch needs `w + 1 = n − f` answers instead of `w`."),
        ("Bad", "The fetch moves the replicas of the other seats. A seat with many large sessions takes longer to become ready."),
        ("Neutral", "When no peer holds a replica, the entry still fences lower versions and the next checkpoint of the owner sends a new record (SS-127)."),
    ],
    confirmation=[
        ("outcome", "Build the owner-rollback series with `w − 1 ≤ f` and an owner that answers with its old version, and check that no erased entry opens and no slot releases twice.", ["SS-102", "SS-016"], q("QI-15", "replacement series and owner rollback")),
        ("outcome", "After a series of replacements with completed fetches, check that the owner restores its latest committed version.", ["SS-126", "SS-127"], q("QI-16", "replicas after a series")),
        ("outcome", "Replay the traces of questions Q-01 to Q-03 at (4,1), (7,2), (5,1), (6,2), (9,2): violation with the old SS-102, none with the new one.", ["SS-102", "SS-126"], ran("tests/regressions.rs q01_fence_series_owner_rollback, q02_sequential_series_owner_rollback, q03_account_series_owner_rollback", "series traces, old rule fails, new rule holds")),
        ("outcome", "Replay the trace of question Q-05: the owner restore opens the latest version with the replica fetch.", ["SS-126", "SS-127"], ran("tests/regressions.rs q05_series_replicas_rebuilt", "replica rebuilt")),
        ("conformance", "Prove that a fetch with `w + 1` answers keeps every committed version within the bound.", ["SS-102"], lean("2.7", "fetch keeps the fence")),
    ],
    revisit_when=[
        "A committee runs with `n − f` live seats so often that the fetch of `w + 1` answers delays replacements.",
        "QI-15 finds a series that lowers a fence with the new rule.",
    ],
    affected=["CTX-002", "INV-003", "JNY-002", "CON-002"],
    obligations=["SS-102", "SS-126", "SS-127"],
    consumed=[{"id": "D-012", "version": 1}],
))

D.append(dict(
    id="D-026", title="Losses count in c while they last",
    state="provisional", basis="proposed", authority=LEAD28,
    source_refs=["SRC-001", "SRC-010"],
    context=(
        "G2 counted in `c` each seat whose tier 0 was lost or rolled back. Prototype question Q-04 asks whether a replaced seat stays in `c` after its fetch completes. "
        "Read literally, every committee leaves the bound after `c + 1` replacements over its life, and the fetch of SS-102 has no purpose. "
        "The design states the purpose of the fetch: a series of replaced peers must not erase a fence with no collusion."
    ),
    drivers=[("G2", "Collusion bound of the fence."), ("G4", "Erasure within the bound."), ("SS-102", "Peer state rebuilt on a blank tier 0."), ("SS-016", "Partial fence.")],
    options=[
        ("Count losses while they last",
         "For one session, `c` counts the colluding operators and each seat whose tier 0 was lost or rolled back after the current version committed. A lost seat stops counting when its fetch completes. A rolled-back seat stops counting for a session when a later version of that session commits.",
         ["A committee stays inside the bound over any number of replacements.", "Each retirement has a reason: after the fetch the seat holds the fence (D-025), and after a later commit the stale state guards nothing."],
         ["The claim depends on D-025. With the old SS-102 it is false at `w − 1 ≤ f`."]),
        ("Count every loss for ever", "Each seat that ever lost or rolled back tier 0 counts.", ["Simple."], ["G2 expires after `c + 1` replacements."]),
        ("Count the peak of active losses only", "Retire rollbacks at the next boot too.", ["Simplest bound."], ["A rolled-back seat keeps stale fences for versions committed before the rollback. Its next boot does not repair them."]),
    ],
    chosen="Count losses while they last",
    rationale="It matches the purpose of the fetch and keeps every retirement tied to a state that guards the version again.",
    consequences=[
        ("Good", "Series of replacements with completed fetches stay inside G2 and G4."),
        ("Neutral", "The prototype counts rollbacks for the rest of a run, which is stricter than this rule. Its in-bound runs are in bound here too."),
        ("Bad", "The bound now has a time dimension. The Quint model must track when each loss starts and ends."),
    ],
    confirmation=[
        ("outcome", "Model losses with start and end events and check G2 and G4 against the count at each step.", ["SS-102", "SS-016"], q("QI-20", "concurrent loss accounting")),
        ("outcome", "Run the 300-seed table and the 200-seed sweep with no G2, G3 or G4 event, under a count that is stricter than this reading (rollbacks count for the whole run).", ["SS-102"], ran("cargo run --release, tests/sweep.rs", "fixed-rule table and sweep")),
    ],
    revisit_when=["QI-20 finds a trace in which a retired seat serves a stale partial."],
    affected=["ASM-001", "INV-001", "INV-003"],
    obligations=["SS-102", "SS-016"],
    consumed=[{"id": "D-025", "version": 1}],
))

D.append(dict(
    id="D-027", title="An account-pool share goes into a nonce slot once, by a put record on Midnight",
    state="provisional", basis="proposed",
    authority=LEAD28 + " The owner directed on 2026-11-14 that the fix is in the spec and recommended a witness of each put share digest.",
    source_refs=["SRC-002", "SRC-009", "SRC-010"],
    context=(
        "Prototype question Q-11: every disk rolls back to a snapshot taken before an account-pool slot existed. After the snapshot, seat 0 put a share, bound it and released a partial. "
        "After the rollback the node classifies the restart correctly, but SS-114 finds no slot to burn, because the restored record does not hold it. "
        "If the app puts the same share again, the slot binds a second digest and the second partial reveals the nonce and the key share. "
        "Account pools have no floor on Midnight (D-018), so `slot_stale` does not apply. A rollback of every disk also rolls back every peer, "
        "so a witness entry at the peers is lost with the slot. Only the ledger is outside the rollback."
    ),
    drivers=[
        ("G3", "A whole-committee restart, also from rolled-back disks, never reuses a nonce slot."),
        ("G2", "No nonce slot is used for two tickets."),
        ("SS-114", "Restart burn of an account pool."),
        ("SRC-009", "Split-line DESIGN §4.1: slot ids never appear on Midnight."),
    ],
    options=[
        ("Put record on Midnight",
         "`slot_put` on an account pool submits `(committee, node_index, SHA-256(\"VT1/slot-put\" ‖ share), put_tag)` with a fresh random `put_tag` (SS-128). The contract keeps one record for each digest (SS-132). `slot_put` refuses a digest on the ledger (SS-129). `slot_bind` waits for the record (SS-130) and refuses a record with another `put_tag` (SS-131).",
         ["Sound for every rollback: a release needs a bind, a bind needs the record, and the ledger does not roll back.",
          "It matches share bytes, so it also stops the same share under another index.",
          "The record shows no purpose, no index and nothing about the secret share."],
         ["One ledger record for each account-pool put on each seat. Writes can batch with the checkpoints.",
          "A bind waits for the record, at most about one checkpoint interval."]),
        ("Put witness at the peers",
         "Witness the put digest at `w` peers before the share is usable, and refuse a re-put that peers report (the recommended mechanism).",
         ["No ledger write.", "Stops a re-put after a rollback inside the bound of G2."],
         ["Question Q-11 rolls back every disk, the peers included. The witness entries are lost with the slot, and the re-put passes. It does not close the finding."]),
        ("Put witness at the peers and on Midnight",
         "Both records.",
         ["The peer entry answers before the ledger record lands."],
         ["The bind waits for the ledger record anyway, so the peer entry adds a round and no safety."]),
        ("Restart generation in the slot index",
         "Each account slot index carries the `restart_seq` of its dealing, and seald refuses an index of an older generation.",
         ["No new ledger record."],
         ["seald cannot verify the generation of raw share bytes. It depends on the app, and the owner asked for a rule in the spec."]),
        ("Mandatory anchors for account pools",
         "Set `anchor_before_release` for every account pool.",
         ["Existing rules (SS-070, SS-105)."],
         ["The anchor record names the purpose, so it shows the account (D-024)."]),
        ("A Limit", "State that a coordinated rollback with a re-put of the same share is outside G3.", ["No change."], ["G3 claims no reuse after a rollback of every disk. A Limit would withdraw it."]),
    ],
    chosen="Put record on Midnight",
    rationale=(
        "It moves the recommended put witness to the one place that a rollback of every disk does not reach. "
        "The `put_tag` lets a node tell its own put from an earlier put that a rollback removed, so the rule does not depend on how fresh the ledger view is at the put."
    ),
    consequences=[
        ("Good", "The trace of question Q-11 releases no second digest: the re-put returns `slot_used` under the same index and under any other index."),
        ("Good", "G3 holds for account pools with no Limit for absent slots."),
        ("Bad", "One ledger record for each account-pool share on each seat, about 32 slots times `n` records for each address birth."),
        ("Bad", "A share that the recovery group reprovisions with the same bytes is refused. Reprovisioning must reshare, which DESIGN §7.11 already does."),
        ("Bad", "The record matches bytes. A reshare of the nonce of a used slot has new bytes. DESIGN §7.11 must exclude the slots claimed after the latest Midnight checkpoint (Q-009, item 25)."),
        ("Bad", "A put that `session_close` discards, or that a crash loses before its checkpoint, leaves its record on the ledger. That share cannot go in again, and the slot is lost."),
        ("Bad", "The put records show, for each seat, how many account-pool shares it puts and when. They show no account (SRC-009). Births are already visible on the board."),
        ("Bad", "Share repair recomputes the same bytes. A node that lost its session record cannot put a repaired account-pool share again, and it needs new slots from the recovery group."),
        ("Neutral", "Sequential pools keep their floor `h` and need no put record."),
    ],
    confirmation=[
        ("outcome", "Roll back every disk to a state before an account slot existed, put the same share again under the same and another index, and check that no slot binds a second digest.", ["SS-128", "SS-129", "SS-130", "SS-131", "SS-132"], q("QI-17", "put record across a coordinated rollback")),
        ("outcome", "Replay the trace of question Q-11: second release with the old rule, `slot_used` and no release with the new rule.", ["SS-128", "SS-129", "SS-131"], ran("tests/regressions.rs q11_absent_account_slot_after_whole_rollback", "absent-slot rollback")),
        ("outcome", "Bind before the put record lands, then after.", ["SS-130"], ran("tests/regressions.rs q11_put_pending_then_bind", "put_pending path")),
        ("conformance", "Add the put record to the mock ledger and test the contract refusal of a second record.", ["SS-132"], prod("5.5", "mock-ledger put record tests")),
    ],
    revisit_when=["Account pools gain a privacy-preserving floor on Midnight.", "The ledger cost of put records becomes a limit for address births."],
    affected=["CTX-001", "CTX-004", "AGG-002", "INV-009", "INV-012", "CON-007", "MOD-004"],
    obligations=["SS-128", "SS-129", "SS-130", "SS-131", "SS-132", "SS-089", "SS-090"],
    consumed=[{"id": "D-018", "version": 1}, {"id": "D-024", "version": 1}],
))

D.append(dict(
    id="D-028", title="A restart generation ends at a checkpoint with the marker and w + 1 continuous seats",
    state="provisional", basis="proposed", authority=LEAD28,
    source_refs=["SRC-002", "SRC-010"],
    context=(
        "SS-113 fires only while `whole_restart = false`, and nothing set it back in one uptime (question Q-007, prototype question Q-09). "
        "A running node that saw one restart therefore missed a second loss of continuity: its new account slots stayed bound and releasable."
    ),
    drivers=[("SS-113", "Restart burn on a running node."), ("SS-123", "Late burn of an account pool."), ("SS-124", "Account-pool bind before the restart checkpoint."), ("G3", "No reuse after a restart.")],
    options=[
        ("End at the restart checkpoint with continuity",
         "When the latest checkpoint has `restart_seq` above `cp_boot.seq` and at least `w + 1` continuous seats, write the marker into each open account-pool session and set `whole_restart` to `false` (SS-133).",
         ["A second loss of continuity burns again.", "No burn repeats while the committee is still coming back, because the end waits for `w + 1` continuous seats."],
         ["One more rule on the running node."]),
        ("End at the restart checkpoint", "Reset at `restart_seq` above `cp_boot.seq` alone.", ["Simpler."], ["A restart checkpoint with few continuous seats re-fires SS-113 at once and burns another window."]),
        ("Keep the flag for the uptime", "No reset.", ["No change."], ["The open gap of question Q-007."]),
    ],
    chosen="End at the restart checkpoint with continuity",
    rationale="It closes the gap and does not add burns during a restart.",
    consequences=[
        ("Good", "Each loss of continuity in one uptime burns once."),
        ("Neutral", "The marker in an open session changes in `work` and seals at its next checkpoint, as SS-125 does."),
    ],
    confirmation=[
        ("outcome", "Two restarts in one uptime of a running node, with a bind between them, and check that the second burns.", ["SS-133", "SS-113"], q("QI-18", "re-arm of SS-113")),
        ("outcome", "Replay the trace of question Q-09: the flag stays set with the old rule, the second loss burns with the new rule.", ["SS-133"], ran("tests/regressions.rs q09_second_continuity_loss_rearms_ss113", "re-arm")),
    ],
    revisit_when=["QI-18 finds a burn that repeats during one restart."],
    affected=["Q-007", "JNY-003", "INV-009"],
    obligations=["SS-133", "SS-113"],
    consumed=[{"id": "D-021", "version": 1}, {"id": "D-024", "version": 1}],
))

D.append(dict(
    id="D-029", title="The body has one canonical encoding, and the accounted size is its length",
    state="provisional", basis="proposed", authority=LEAD28,
    source_refs=["SRC-001", "SRC-010"],
    context=(
        "SS-088 compared an accounted size with `S_max`, but no requirement defined the encoding. Prototype question Q-07 measured one candidate layout: "
        "10,000 bound Schnorr slots exceed 1 MiB, against the design claim of under 1 MiB."
    ),
    drivers=[("SS-088", "Session too large."), ("SS-008", "Record seal."), ("SS-109", "Peer line limit.")],
    options=[
        ("Fixed encoding in design.md", "Length-prefixed fields, sorted entries and slots, burned runs, free slots counted at bound size (SS-134, SS-135).", ["Two nodes produce one body for one `work`.", "The size check is exact."], ["Golden vectors must cover it (item 23)."]),
        ("Leave it to the implementation", "Define the size by whatever the code serializes.", ["No spec text."], ["The size check and the 4 MiB line are not testable from the spec."]),
    ],
    chosen="Fixed encoding in design.md",
    rationale="The size bound is a requirement only with a defined encoding.",
    consequences=[
        ("Good", "A pool of 10,000 bound Schnorr slots has an accounted size of 1,070,035 bytes and a record of 1,070,127 bytes, inside `S_max`. The design no longer claims under 1 MiB."),
        ("Neutral", "Account-pool slots carry 16 more bytes for the `put_tag` of D-027."),
    ],
    confirmation=[
        ("outcome", "Measure the body and record sizes of 10,000 slots in each state with the encoding.", ["SS-134", "SS-135"], ran("tests/measurements.rs", "encoding sizes")),
        ("conformance", "Golden vectors of the body encoding.", ["SS-134"], prod("5.7", "body encoding vectors")),
    ],
    revisit_when=["The share size or the digest size changes."],
    affected=["AGG-001", "CON-006"],
    obligations=["SS-134", "SS-135", "SS-088"],
    consumed=[{"id": "D-009", "version": 1}],
))

D.append(dict(
    id="D-030", title="B covers the reservations of one checkpoint interval, and a checkpoint follows each RestoreDone",
    state="provisional", basis="proposed", authority=LEAD28,
    source_refs=["SRC-001", "SRC-010"],
    context=(
        "Prototype question Q-08: `f + 1` reboots one at a time, with recovery but no checkpoint between them, leave `w` continuous seats, and the nodes classify a whole-committee restart. "
        "Continuity is relative to the latest checkpoint. Separately, `B` below the reservations of one checkpoint interval refuses binds: at `B = 8`, 500 of 1,000 binds at 16 reservations per interval."
    ),
    drivers=[("SS-004", "Committee parameters."), ("SS-063", "Window bound."), ("SS-067", "Restart decision.")],
    options=[
        ("Parameter rule and cadence rule", "Set `B` at least to the largest number of reservations between two checkpoints, and post a checkpoint after each `RestoreDone` before the next planned reboot.", ["No protocol change.", "Measured: the smallest `B` with no refusal equals the reservations per interval (1, 4, 16)."], ["Both rules bind the committee application, which has no spec (Q-008)."]),
        ("Count a seat with a RestoreDone as continuous", "Continuity from statements, not checkpoints.", ["No cadence rule."], ["A statement does not show that the seat kept its tier 0. It changes the restart decision of D-005."]),
    ],
    chosen="Parameter rule and cadence rule",
    rationale="Both failures are loss and throughput, not safety, and the cheaper fix is operational.",
    consequences=[("Bad", "A committee that reboots faster than it checkpoints burns windows as if it restarted."), ("Neutral", "Q-002 now has measured values for `B`.")],
    confirmation=[("outcome", "Reboot `f + 1` seats one at a time with no checkpoint between them, and check that the nodes classify a whole-committee restart and that the next checkpoint jumps past the window.", ["SS-067"], ran("tests/faults.rs staggered_reboots_faster_than_checkpoint_cadence", "serial reboots")),
                  ("outcome", "Measure refusals at reservation rates 1, 4 and 16 per interval.", ["SS-063"], ran("tests/measurements.rs", "window refusals"))],
    revisit_when=["The committee application gains an EARS spec (Q-001, Q-008)."],
    affected=["Q-002", "Q-008", "ASM-002", "CON-006"],
    obligations=["SS-004", "SS-063", "SS-067"],
    consumed=[{"id": "D-005", "version": 1}, {"id": "D-009", "version": 1}],
))

D.append(dict(
    id="D-031", title="Nodes that read different checkpoints at one restart burn the union",
    state="provisional", basis="proposed", authority=LEAD28,
    source_refs=["SRC-001", "SRC-010"],
    context=(
        "Prototype question Q-10: when a checkpoint lands during a restart, nodes that synced before it burn the window of `cp1`, and nodes that sync after it can classify a restart against `cp2` and burn its window. "
        "With `B = 8` the union was `[1, 17]`, `2B + 1` indices. The design said that all nodes burn the same sets."
    ),
    drivers=[("SS-067", "Restart decision."), ("SS-068", "Sequential restart burn."), ("SS-104", "Checkpoint after a restart."), ("G3", "Loss bound.")],
    options=[
        ("State the union as the bound", "Each checkpoint that a restarting node reads adds at most `B` indices and its pending slots.", ["It follows the rules as written and adds no mechanism.", "Every set stays unusable through SS-104 and `slot_stale`."], ["The loss is larger than one window."]),
        ("One generation checkpoint for all", "The ledger names one checkpoint that every node of the restart uses.", ["One window."], ["A second restart after that checkpoint must burn its own window, so the ledger needs a generation counter that the marker of D-024 does not give."]),
    ],
    chosen="State the union as the bound",
    rationale="The union is safe, and a single window needs a new ledger mechanism for a loss of a few `B`.",
    consequences=[("Bad", "The loss of decision 2 (D-002) can reach the union of the windows of the checkpoints read during one restart.")],
    confirmation=[("outcome", "Model a checkpoint during a restart and check that the burned union never binds and stays within one window per checkpoint read.", ["SS-067", "SS-068", "SS-104"], q("QI-19", "union bound")),
                  ("outcome", "Measure the union with two boot checkpoints.", ["SS-068"], ran("tests/measurements.rs restart_windows_and_different_boot_checkpoint_union_ss068", "2B + 1 union"))],
    revisit_when=["Restarts with checkpoints in flight become common enough that the union matters."],
    affected=["JNY-003", "INV-009"],
    obligations=["SS-067", "SS-068", "SS-104"],
    consumed=[{"id": "D-002", "version": 1}],
))


# --- Owner rulings of 2026-11-14 on existing records ---------------------------
_by = {d["id"]: d for d in D}
for _i in range(5, 25):
    _d = _by[f"D-{_i:03d}"]
    _d.update(state="confirmed", basis="explicit", authority=OWNER_CONFIRMED)

_ACCEPT = ("Accepted", "The owner accepted on 2026-11-14 that a whole-committee restart burns every unused account-pool slot of every seat, and that only the recovery group refills them. This widens the loss of decision 2.")
_by["D-002"]["consequences"] += [_ACCEPT, ("Bad", "Nodes that read different checkpoints at one restart burn the union of their sets, at most `B` indices and the pending slots for each checkpoint read (D-031). The decision text is unchanged.")]
_by["D-018"]["consequences"] += [_ACCEPT]
_by["D-024"]["consequences"] += [_ACCEPT, ("Neutral", "D-027 adds put records for slots that a rollback removes, and D-028 ends a restart generation so that SS-113 can fire again.")]
_by["D-012"]["consequences"] += [("Neutral", "D-025 amends SS-102: the fetch takes `w + 1` answers, ignores the owner about itself and rebuilds the replicas.")]
_by["D-021"]["consequences"] += [("Neutral", "D-028 (SS-133) closes the gap of a second restart in one uptime.")]
_by["D-009"]["consequences"] += [("Neutral", "D-029 fixes the body encoding and D-030 the rule for `B`.")]


# --- Item versions (artifact contract: an item's version rises when its content changes) ---
for _id in ["D-002"] + [f"D-{i:03d}" for i in range(5, 25)]:
    _by[_id]["version"] = 2
for _d in D:
    if int(_d["id"][2:]) >= 25:
        _d["consumed"] = [{"id": c["id"], "version": _by[c["id"]].get("version", 1)} for c in _d["consumed"]]


# --- Item 29 (BASE-001 revision 3): per-checkpoint Midnight commitments --------
OWNER_RULING = ("The owner, ruling of 2026-11-14 in the working session (SRC-011): \"use the batched design you are insane to make "
                "that many commits to midnight save space, tokens, and transactions\". Standing rule: no design writes to Midnight per "
                "event; it commits per checkpoint and keeps item data on the board or at peers, checked against the root.")
LEAD29 = ("Lead decision, 2026-11-14, applying the owner's standing rule of SRC-011 (one root or a few fixed-size fields per checkpoint, "
          "item data off Midnight). Split-line DESIGN 7.13 still lists the pending indices in the checkpoint; the lead reconciles DESIGN.")

_by["D-012"]["options"][0] = (
    "Peer-state sync at boot",
    "Fetch the entries of other seats from `w + 1` peers before any ack or partial, keep for each seat the highest version that a peer other than that seat reports, and fetch the replicas (as D-025 amends it).",
    ["Keeps the bound, also against a rolled-back owner.", "No chain write."],
    ["Boot waits for `w + 1` peers."])
_by["D-012"]["obligations"] = ["SS-102", "SS-126", "SS-127"]
_by["D-012"]["consequences"] = [c for c in _by["D-012"]["consequences"] if "D-025 amends SS-102" not in c[1]] + [
    ("Neutral", "D-025 amends this record: the fetch takes `w + 1` answers, ignores the owner about itself and rebuilds the replicas (SS-102, SS-126, SS-127). The owner confirmed D-025 on 2026-11-14.")]

for _id in ("D-025", "D-031"):
    _by[_id].update(state="confirmed", basis="explicit", authority=OWNER_CONFIRMED)
_by["D-031"]["consequences"] += [("Accepted", "The owner accepted on 2026-11-14 the union bound: up to about `2B + 1` slots per whole-committee restart.")]

_by["D-024"]["consequences"] = [(k, t.replace("D-027 adds put records", "D-027 adds put entries in the seat log")) for k, t in _by["D-024"]["consequences"]]

_by["D-002"]["consequences"] += [
    ("Neutral", "D-034 burns the interval `[pending_min, h + B]` of the checkpoint read. It holds the window and every pending index, and its other indices were already refused by `slot_stale`, so the loss does not grow."),
    ("Neutral", "D-033 removes the Midnight write per bind of the anchored option. It now costs about one checkpoint interval plus Midnight finality per release and no transaction.")]
_by["D-006"]["consequences"] += [
    ("Neutral", "D-033 names the seald committee parameter `slot_anchor` and moves its anchor into binding entries in the seat log. The window rule of this record applies to it unchanged.")]
_by["D-013"]["drivers"] = [(i, t) for i, t in _by["D-013"]["drivers"] if i != "SS-105"] + [("SS-136", "Seat-log root chain.")]
_by["D-013"]["obligations"] = ["SS-103", "SS-104", "SS-117", "SS-136"]
_by["D-013"]["confirmation"] = [
    (k, m, [t for t in tg if t != "SS-105"] + (["SS-136"] if "SS-105" in tg else []), c) for k, m, tg, c in _by["D-013"]["confirmation"]]
_by["D-013"]["consequences"] += [
    ("Neutral", "D-032 retires SS-105: the contract keeps no anchor record and chains one seat-log root per seat instead (SS-136). D-034 checks the restart jump with `pending_min`.")]
_by["D-014"]["consequences"] += [
    ("Neutral", "D-032 moves the statement to the seat log of the seat. The next checkpoint carries it, and SS-117 reads it there, so a boot costs no Midnight transaction of its own.")]

_d27 = _by["D-027"]
_d27.update(
    title="An account-pool share goes into a nonce slot once, by a put entry in the seat log under a checkpoint root",
    state="confirmed", basis="explicit",
    authority=OWNER_RULING + " Earlier the same day the owner directed that the fix is in the spec and recommended a witness of each put share digest. The seat-log form follows split-line DESIGN 7.4 (SRC-012).",
    source_refs=["SRC-002", "SRC-009", "SRC-010", "SRC-011", "SRC-012"],
    context=_d27["context"] + (
        " The first fix put one Midnight record per put: `n` records per ECDSA slot, 144 for one `K = 8`, `L = 2` request at `n = 9` "
        "and 90,000 for a refill of 10,000 slots. The owner ruled that no design writes to Midnight per event."),
    drivers=_d27["drivers"] + [("SRC-011", "Owner ruling: Midnight takes per-checkpoint commitments, never a per-event write.")],
    options=[
        ("Put entry in the seat log under a checkpoint root",
         "`slot_put` on an account pool appends `(SHA-256(\"VT1/slot-put\" ‖ share), put_tag)` with a fresh random `put_tag` to the seat log on the board (SS-128). "
         "Each checkpoint chains one root per seat over the log (SS-136). `slot_put` refuses a digest in the log (SS-129). `slot_bind` waits until a landed root covers the entry (SS-130) "
         "and refuses a slot whose first covered entry has another `put_tag` (SS-131). seald reads the full log against the root (SS-137) and refuses account-pool work without it (SS-138).",
         ["Sound for every rollback: a release needs a bind, a bind needs a covered entry, the roots on Midnight do not roll back, and the chain keeps every covered entry.",
          "No Midnight transaction per put: a refill of 10,000 slots costs 4.41 MB of board at `n = 9` and nothing on Midnight.",
          "It matches share bytes, so it also stops the same share under another index.",
          "The entry shows no purpose, no index and nothing about the secret share, and Midnight shows nothing per put."],
         ["The duplicate-put refusal needs the full log behind the root (ASM-006). A withheld log stops the account pools of the seat.",
          "A bind right after a put waits for the next checkpoint: about one checkpoint interval plus Midnight finality.",
          "49 board bytes per put per seat."]),
        ("Put record on Midnight",
         "`slot_put` submits `(committee, node_index, put digest, put_tag)` to Midnight, and the contract keeps one record per digest (the first fix of question Q-11).",
         ["Sound for every rollback.", "The contract holds every digest, so no data-availability assumption."],
         ["`n` transactions per ECDSA slot: 144 transactions and 21,024 bytes per `K = 8`, `L = 2` request at `n = 9`, 272 at `n = 17`.",
          "90,000 transactions and 13.1 MB per refill of 10,000 slots at `n = 9`, 170,000 at `n = 17`.",
          "14,400 to 57,600 transactions per second at 100 to 400 requests per second when each request refills 16 slots.",
          "The owner ruling of SRC-011 forbids a per-event Midnight write."]),
        ("Put witness at the peers",
         "Witness the put digest at `w` peers before the share is usable, and refuse a re-put that peers report.",
         ["No ledger write.", "Stops a re-put after a rollback inside the bound of G2."],
         ["Question Q-11 rolls back every disk, the peers included. The witness entries are lost with the slot, and the re-put passes."]),
        ("Restart generation in the slot index",
         "Each account slot index carries the `restart_seq` of its dealing, and seald refuses an index of an older generation.",
         ["No new record."],
         ["seald cannot verify the generation of raw share bytes. It depends on the app, and the owner asked for a rule in the spec."]),
        ("Mandatory slot anchors for account pools",
         "Set `slot_anchor` for every account pool.",
         ["Existing rules (SS-070 to SS-073)."],
         ["A binding entry names a slot, not a share. A re-put of the same share under another index binds a new nullifier and passes."]),
        ("A Limit", "State that a coordinated rollback with a re-put of the same share is outside G3.", ["No change."], ["G3 claims no reuse after a rollback of every disk. A Limit would withdraw it."]),
    ],
    chosen="Put entry in the seat log under a checkpoint root",
    rationale=("It keeps the put witness outside every disk rollback, as the put record did, and Midnight takes one root per seat per checkpoint instead of one "
               "transaction per put. The `put_tag` and the first-entry rule make the result independent of how fresh the view of the node is."),
    consequences=[
        ("Good", "The trace of question Q-11 releases no second digest: the re-put returns `slot_used` under the same index and under any other index, also when the board tail is lost."),
        ("Good", "G3 holds for account pools with no Limit for absent slots."),
        ("Good", "No Midnight transaction per put. The rejected per-event option cost 144 transactions per `K = 8`, `L = 2` request and 90,000 per refill of 10,000 slots at `n = 9`."),
        ("Bad", "A seat whose covered log no reader can serve stops its account pools (`log_unavailable`, ASM-006). No share binds twice."),
        ("Bad", "A bind right after a put waits for the next checkpoint."),
        ("Bad", "A share that the recovery group gives the same bytes is refused."),
        ("Bad", "The entry matches bytes. A reshare of a used slot has new bytes, so without `slot_anchor` the recovery group reissues no ECDSA slot and each ECDSA address refills by a new slot session (Q-009, DECISIONS 51 choice 8)."),
        ("Bad", "A put that `session_close` discards, or that a crash loses before its checkpoint, leaves its entry in the seat log. That share cannot go in again, and the slot is lost."),
        ("Bad", "The seat log shows, for each seat, how many account-pool shares it puts and when. It shows no account (SRC-009). Births are already visible on the board."),
        ("Bad", "Share repair recomputes the same bytes. A node that lost its session record cannot put a repaired account-pool share again, and the address refills by a new slot session."),
        ("Neutral", "Sequential pools keep their floor `h` and need no put entry."),
    ],
    confirmation=[
        ("outcome", "Roll back every disk to a state before an account slot existed, lose the board tail, put the same share again under the same and another index, and check that no slot binds a second digest.", ["SS-128", "SS-129", "SS-130", "SS-131", "SS-136", "SS-137"], q("QI-17", "put entry across a coordinated rollback")),
        ("outcome", "Withhold a seat log and lose a covered batch, and check that no share binds twice and nothing releases.", ["SS-137", "SS-138"], q("QI-21", "board withholding")),
        ("outcome", "Roll back every disk across a checkpoint boundary with the tail lost, and check that a covered put stays refused.", ["SS-129", "SS-136", "SS-137"], q("QI-23", "rollback across a checkpoint")),
        ("outcome", "Replay the trace of question Q-11: second release with no put rule, `slot_used` and no release with the seat-log rule.", ["SS-128", "SS-129", "SS-131"], ran("tests/regressions.rs q11_absent_account_slot_after_whole_rollback", "absent-slot rollback")),
        ("outcome", "Bind before a checkpoint covers the put, then after.", ["SS-130"], ran("tests/regressions.rs q11_put_pending_then_bind, uncovered_put_cannot_bind", "put_pending until covered")),
        ("outcome", "Lose the board tail after a covered put and a release, roll back every disk and put the share again.", ["SS-129", "SS-137"], ran("tests/commitments.rs q11_lost_tail_covered_put_not_rebound, rollback_across_checkpoint_boundary", "covered put survives tail loss")),
        ("outcome", "Withhold the seat log after a rollback of every disk.", ["SS-138"], ran("tests/commitments.rs withheld_log_refuses_bind_never_releases", "log_unavailable, no release")),
        ("conformance", "Add the seat-root chain to the mock ledger and test that no checkpoint drops a covered entry.", ["SS-136"], prod("5.5", "mock-ledger seat-root chain tests")),
    ],
    revisit_when=["Account pools gain a privacy-preserving floor on Midnight.",
                  "A Midnight contract can check a non-membership proof per put cheaply, so the full-log read is no longer needed.",
                  "Seat logs prove unavailable in operation (ASM-006)."],
    affected=["CTX-001", "CTX-004", "AGG-002", "INV-009", "INV-012", "CON-007", "MOD-004", "ASM-006"],
    obligations=["SS-128", "SS-129", "SS-130", "SS-131", "SS-137", "SS-138", "SS-089", "SS-090"],
    consumed=[{"id": "D-018", "version": 1}, {"id": "D-024", "version": 1}, {"id": "D-032", "version": 1}],
)

D.append(dict(
    id="D-032", title="Midnight takes one root per seat per checkpoint and no per-event write",
    state="confirmed", basis="explicit", authority=OWNER_RULING + " The seat-log form follows split-line DESIGN 7.4 and 11.6 (SRC-012).",
    source_refs=["SRC-001", "SRC-011", "SRC-012"],
    context=(
        "The Sessions design wrote to Midnight once per event: a put record per account-pool put on each seat (SS-128 as first written), an anchor record per binding "
        "on each seat under the anchored option (SS-070), and a `RestoreDone` transaction per boot of each seat (SS-112). At the design throughput of 100 to 400 "
        "requests per second per core, the put records alone reach 14,400 to 57,600 Midnight transactions per second at `n = 9` when each request refills 16 ECDSA slots. "
        "The owner ruled that no design writes to Midnight per event."),
    drivers=[("SRC-011", "Owner ruling: per-checkpoint commitments only."), ("SS-128", "Put entry."), ("SS-070", "Anchor before release."),
             ("SS-112", "Restore statement."), ("G3", "No reuse after a rollback of every disk.")],
    options=[
        ("Seat logs on the board with a chained root per seat",
         "Each seat appends its put entries, binding entries and `RestoreDone` statements to an append-only seat log on the board, carried on its board vote. "
         "Each checkpoint carries one batch root per seat, and the contract chains it into the seat root (SS-136). seald reads the full log and checks it against the root (SS-137) "
         "and refuses account-pool work and anchored binds without it (SS-138, SS-139). The checkpoint carries the `RestoreDone` statements of its interval (SS-117).",
         ["Midnight takes one transaction per 60 seconds whatever the load: 944 bytes at `n = 9`, 1,648 at `n = 17`.",
          "The chain keeps every covered entry, so a rollback of every disk and a lost board tail change no covered entry.",
          "It is the seat log of split-line DESIGN 7.4 and 11.6."],
         ["The full log must stay readable (ASM-006).", "An event that gates a bind or a release waits for the next checkpoint.", "32 bytes per seat per checkpoint, also when a seat is idle."]),
        ("One Midnight transaction per event",
         "A put record per put (146 bytes), an anchor record per binding (154 bytes) and a `RestoreDone` transaction per boot (115 bytes), on each seat.",
         ["The contract holds each item, so no data-availability assumption."],
         ["144 transactions per `K = 8`, `L = 2` request at `n = 9`, 90,000 per refill of 10,000 slots, 18 per anchored bind of two inputs.",
          "14,400 to 57,600 transactions per second at the design throughput.", "The owner ruling forbids it."]),
        ("One combined root over every seat log",
         "One batch root per checkpoint over the entries of all seats.",
         ["32 bytes per checkpoint instead of `32·n`."],
         ["A seat must read every seat log to check its own.", "The recovery group checks one seat at a time (DESIGN 7.11).", "DESIGN 7.4 keeps one root per seat."]),
        ("Entries under board_root only",
         "Use the board root that the checkpoint already carries.",
         ["No new field."],
         ["An absence check scans every board block since genesis.", "The contract has no per-seat chain to keep covered entries."]),
        ("The entries in the checkpoint transaction",
         "Batch the items of an interval into the checkpoint itself.",
         ["No board data-availability assumption."],
         ["The bytes grow with the events: 4.41 MB on Midnight per refill of 10,000 slots at `n = 9`.", "It breaks the fixed-size rule of SRC-011."]),
    ],
    chosen="Seat logs on the board with a chained root per seat",
    rationale="It is the only option with a fixed Midnight cost per checkpoint under which the contract still keeps every covered entry. The board already orders the events, so the seat log adds no ordering mechanism.",
    consequences=[
        ("Good", "Midnight takes no transaction per request, per pool refill, per binding or per boot statement. At `n = 9` the load is one checkpoint of 944 bytes per 60 seconds, about 16 bytes per second."),
        ("Good", "Midnight shows nothing per event. The board shows the seat-log entries, which name no purpose, no index and no digest."),
        ("Bad", "A seat log that no reader can serve in full stops the account pools and the anchored binds of its seat (ASM-006)."),
        ("Bad", "The checkpoint signers must refuse a batch with a second put of one digest or a second binding of one nullifier. The committee application has no EARS spec for it (Q-010)."),
        ("Neutral", "The Midnight writes that remain are the checkpoint (every 60 seconds and after each `RestoreDone`), the boot ticket (one per boot of a seat) and the epoch record (`n` per epoch), each per checkpoint or rarer (design.md, \"Midnight writes\")."),
    ],
    confirmation=[
        ("outcome", "Count the Midnight transactions of each prototype run: only checkpoints and boot tickets under the seat-log rules, more under the per-event rules.", ["SS-112", "SS-128", "SS-136"], ran("tests/commitments.rs fixed_midnight_writes_only_checkpoints_and_boot_tickets", "Midnight write count")),
        ("outcome", "Withhold a seat log, lag a root and roll back across a checkpoint, and check G2 and G3.", ["SS-136", "SS-137", "SS-138"], q("QI-21", "board withholding")),
        ("outcome", "Check that a put or binding whose root has not landed allows no bind or release.", ["SS-130", "SS-071"], q("QI-22", "root lag")),
        ("conformance", "Model the seat log and the root chain in the oracle and prove that a covered entry stays in every later verified log.", ["SS-136", "SS-137"], lean("2.7", "covered entries stay")),
        ("conformance", "Add the batch roots, the chain and the carried statements to the mock ledger.", ["SS-117", "SS-136"], prod("5.5", "mock-ledger seat logs")),
    ],
    revisit_when=["Midnight byte cost makes `32·n` bytes per checkpoint matter.", "Seat logs prove unavailable in operation.", "Compact can check a non-membership proof cheaply."],
    affected=["CTX-003", "CTX-004", "CON-003", "CON-004", "CON-005", "CON-007", "MOD-003", "MOD-004", "ASM-006"],
    obligations=["SS-112", "SS-117", "SS-120", "SS-121", "SS-122", "SS-136", "SS-137", "SS-138"],
    consumed=[{"id": "D-013", "version": 1}, {"id": "D-014", "version": 1}],
))

D.append(dict(
    id="D-033", title="The seald slot anchor writes binding entries to the seat log, keyed by a slot nullifier",
    state="confirmed", basis="explicit",
    authority=OWNER_RULING + " Nullifier keying follows split-line DESIGN O32 (SRC-012).",
    source_refs=["SRC-001", "SRC-011", "SRC-012"],
    context=(
        "Under the anchored option, each bind submitted `(committee, node_index, purpose, index, H(tk))` to Midnight, and SS-105 kept one record per slot key: "
        "one transaction per binding per seat, 18 for a request with two inputs at `n = 9`. The record named the purpose, and so the account, in the clear, which "
        "conflicts with the nullifier keying of split-line DESIGN O32. The name `anchor_before_release` meant both a charter option and the seald committee parameter."),
    drivers=[("SS-070", "Anchor before release."), ("SS-073", "Restart with anchors."), ("SS-119", "Release check with anchors."),
             ("SRC-011", "Owner ruling: no per-event Midnight write."), ("G3", "A whole-committee restart burns nothing under the anchor.")],
    options=[
        ("Binding entries in the seat log, keyed by a slot nullifier",
         "The committee parameter `slot_anchor` (SS-004). `slot_bind` appends `(nf, e)` to the seat log and succeeds only when a landed checkpoint covers it (SS-070, SS-071). "
         "Another digest for the nullifier is a `conflict` (SS-072). A restart sets each `free` slot with a covered entry to `bound` and burns nothing (SS-073). "
         "A release needs the first covered entry with the same digest (SS-119). A withheld log refuses binds (SS-139).",
         ["A whole-committee restart burns nothing and voids nothing, as before.", "No Midnight transaction per binding.",
          "The entry shows no purpose, no index and no digest.", "One name for each mechanism."],
         ["A release waits for the next checkpoint.", "The seat log must stay readable (ASM-006).", "`k_nf` is a new committee secret that the session `keys` and the recovery backup hold."]),
        ("Anchor record on Midnight per binding",
         "The previous rule (SS-070 as first written, SS-105).",
         ["The contract keeps one record per slot key."],
         ["18 transactions and 2,772 bytes per request with two inputs at `n = 9`, 34 at `n = 17`; 7,200 per second at 400 requests per second.",
          "The record shows the account.", "The owner ruling forbids it."]),
        ("Binding entries keyed by purpose and index in the clear",
         "The seat-log form with the old key.",
         ["No new key."],
         ["The board shows the account pool of each binding.", "It conflicts with DESIGN O32."]),
        ("Drop the seald slot anchor",
         "Keep only the burn rules.",
         ["Less code."],
         ["Anchored committees lose the restart that burns nothing.", "The recovery group then reissues no ECDSA slot on any committee (r3)."]),
    ],
    chosen="Binding entries in the seat log, keyed by a slot nullifier",
    rationale="It keeps the anchored guarantee, a whole-committee restart that burns nothing, with no Midnight transaction per binding and no slot id on the board.",
    consequences=[
        ("Good", "An anchored committee keeps every slot through a whole-committee restart."),
        ("Good", "The board shows only nullifiers and ciphertext for a binding."),
        ("Bad", "Each release on an anchored committee waits about one checkpoint interval plus Midnight finality."),
        ("Bad", "The recovery group backup must hold `k_nf` to read the binding entries (DESIGN 7.11)."),
        ("Neutral", "D-006 stands: the window applies under `slot_anchor` too."),
        ("Neutral", "The charter option `anchor_before_release` of DESIGN 7.7 stays an app option for `release` entries. seald reads only `slot_anchor`."),
    ],
    confirmation=[
        ("outcome", "Check that no slot releases for a digest other than its first covered binding entry, and that an anchored slot restored as `free` releases for it.", ["SS-070", "SS-073", "SS-092", "SS-119"], q("QI-12", "anchored mode")),
        ("outcome", "Withhold the seat log of an anchored committee and check that nothing binds or releases.", ["SS-139"], q("QI-21", "board withholding")),
        ("conformance", "Test the nullifier, the encrypted digest and the first-entry rule in seald.", ["SS-070", "SS-072", "SS-119"], prod("5.4", "binding entries")),
    ],
    revisit_when=["The committee-wide `slot_anchor` of DESIGN O32 replaces the per-seat check.", "Release latency of one checkpoint interval becomes a limit."],
    affected=["CTX-001", "CON-005", "CON-006", "MOD-001", "ASM-006"],
    obligations=["SS-004", "SS-070", "SS-071", "SS-072", "SS-073", "SS-092", "SS-119", "SS-139"],
    consumed=[{"id": "D-006", "version": 1}, {"id": "D-032", "version": 1}],
))

D.append(dict(
    id="D-034", title="The checkpoint carries fixed-size pending fields, and the app proves pending membership at the bind",
    state="provisional", basis="derived", authority=LEAD29,
    source_refs=["SRC-001", "SRC-011", "SRC-012"],
    context=(
        "The checkpoint listed every pending index of each sequential pool, 8 bytes each. A request holds its `G·L` slots from reservation until FINAL at the confirmation depth. "
        "At 400 requests per second with 4 slots each, a 60-second life gives 96,000 indices and 768,000 bytes per checkpoint, and the Bitcoin depth of about 3,600 seconds gives 46 MB. "
        "That is item data on Midnight, which the standing rule of SRC-011 forbids."),
    drivers=[("SS-005", "Checkpoint view."), ("SS-064", "Window lower bound."), ("SS-068", "Restart burn."), ("SS-104", "Checkpoint after a restart."), ("SRC-011", "Fixed-size fields per checkpoint.")],
    options=[
        ("pending_min and pending_root, with a proof at the bind",
         "Each pool carries `pending_min`, `pending_root` and `pending_count` (52 bytes). `slot_bind` at or below `h` needs a proof under `pending_root` and refuses an index below `pending_min` (SS-064). "
         "The contract checks the restart jump with `pending_min` (SS-104). The restart burns `[pending_min, h + B]` (SS-068). Pruning drops entries below `pending_min` (SS-108).",
         ["52 bytes per pool per checkpoint at any load.", "The contract still enforces the restart jump.", "The restart burn reads fixed fields only, so a withheld pending list cannot block it."],
         ["The app sends a proof of about `33·log2(P)` bytes with each bind at or below `h`.", "The burn range also covers indices at or below `h` that were not pending. `slot_stale` already refused them.",
          "The contract cannot check that `pending_root` holds the true pending set. The signers set it, as they set the list before."]),
        ("Explicit pending list", "The previous field.", ["The contract checks membership directly."], ["768,000 bytes to 46 MB per checkpoint at the design throughput."]),
        ("Drop a request from the list once its slots are bound", "Keep the list, shorter.", ["Smaller list."], ["A fee bump binds later, and the list still grows with the load."]),
    ],
    chosen="pending_min and pending_root, with a proof at the bind",
    rationale="It keeps the checkpoint fixed-size and keeps the restart jump a contract rule.",
    consequences=[
        ("Good", "The checkpoint stays at 944 bytes at `n = 9` whatever the load."),
        ("Bad", "Each bind at or below `h` carries a pending proof."),
        ("Bad", "Split-line DESIGN 7.13 still lists the pending indices. The lead reconciles DESIGN or reverses this record."),
        ("Neutral", "The signers set `pending_min` and `pending_root` (Q-010)."),
    ],
    confirmation=[
        ("outcome", "Check that no index of a burn set binds after a restart with the new fields, and that a proof below `pending_min` never counts.", ["SS-064", "SS-068", "SS-104"], q("QI-24", "pending fields after a restart")),
        ("outcome", "Test the contract rule with `pending_min` and the membership check in the prototype.", ["SS-064", "SS-104"], ran("tests/commitments.rs pending_min_restart_jump_refused_and_accepted, sequential_pending_membership_requires_matching_root", "pending fields")),
        ("conformance", "Pin each window edge of SS-064 with and without a proof.", ["SS-064"], lean("2.9", "window edges")),
    ],
    revisit_when=["DESIGN keeps an explicit pending list for another reason.", "The proof per bind costs more than the list."],
    affected=["CON-003", "MOD-003", "MOD-004", "INV-009"],
    obligations=["SS-005", "SS-064", "SS-068", "SS-104", "SS-108"],
    consumed=[{"id": "D-002", "version": 1}, {"id": "D-011", "version": 1}, {"id": "D-013", "version": 1}, {"id": "D-022", "version": 1}],
))

D.append(dict(
    id="D-035", title="slot_bind_batch binds every slot of one pool session and board height in one witness round and one checkpoint",
    state="confirmed", basis="explicit",
    authority=OWNER_RULING + " DECISIONS 51 choice 3 applies the ruling to the bind (DESIGN 7.7, O36).",
    source_refs=["SRC-011", "SRC-012"],
    context="Split-line DESIGN 7.7 binds every slot that one board height fixes in one batch per pool session. seald bound one slot per call (SS-050, SS-051), and SS-107 runs the calls of one session one at a time, so `k` slots took `2k` witness rounds.",
    drivers=[("SS-050", "Bind witnesses the slot first."), ("SS-051", "Bind seals the binding."), ("SS-107", "One operation at a time."), ("SRC-011", "Use the batched design.")],
    options=[
        ("One batch call", "`slot_bind_batch` sends all `slot` entries in one message per peer and seals one checkpoint (SS-140). One refused item refuses the call (SS-141).",
         ["Two witness rounds per board height for any number of slots.", "One checkpoint per batch."], ["One bad item fails the whole call."]),
        ("One slot per call", "The previous API.", ["Simplest."], ["`2k` rounds for `k` slots, one session at a time."]),
        ("Partial success per item", "Bind the items that pass and report the others.", ["One bad item does not stop the rest."], ["A per-item result, and SS-089 no longer holds per call."]),
    ],
    chosen="One batch call",
    rationale="It gives the release latency of DESIGN 7.7 and keeps the rule that a refusal changes nothing.",
    consequences=[("Good", "A release waits for two bind rounds whatever the number of slots."), ("Bad", "The app retries a refused batch without the refused item.")],
    confirmation=[
        ("outcome", "Model the batch bind and check that a refused batch changes nothing and a bound batch releases each slot for one digest.", ["SS-140", "SS-141"], q("QI-25", "batch bind")),
        ("conformance", "Add the batch to the oracle with one branch for the refusal.", ["SS-140", "SS-141"], lean("2.6", "batch bind branches")),
    ],
    revisit_when=["Batches grow past the peer line limit of SS-109."],
    affected=["CON-001", "AGG-002", "MOD-001"],
    obligations=["SS-140", "SS-141"],
    consumed=[{"id": "D-020", "version": 1}],
))

_by = {d["id"]: d for d in D}
for _id, _v in {"D-002": 3, "D-006": 3, "D-012": 3, "D-013": 3, "D-014": 3, "D-024": 3, "D-025": 2, "D-027": 2, "D-031": 2}.items():
    _by[_id]["version"] = _v
for _d in D:
    if int(_d["id"][2:]) >= 25:
        _d["consumed"] = [{"id": c["id"], "version": _by[c["id"]].get("version", 1)} for c in _d["consumed"]]
