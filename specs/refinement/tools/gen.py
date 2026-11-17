"""Generate baseline.yaml and traceability.yaml for add-split-line-dealing.

Usage: python3 -I specs/refinement/tools/gen.py <repo root>

Hand-written model data (sources, contexts, aggregates, modules, contracts,
invariants, questions, assumptions) lives in this file. Requirements come
from the OpenSpec capability files. D items come from the DECISIONS entries
that the requirements cite, read from design/enhancement/DECISIONS.md and,
for entries 53 and 54, from branch quint-split (commit aa038fa).
"""
import pathlib
import re
import subprocess
import sys

import yaml

ROOT = pathlib.Path(sys.argv[1]).resolve()
REF = ROOT / "specs/refinement"
CHANGE = "openspec/changes/add-split-line-dealing"
QS = "aa038fa156dce5d5a47403db4b2b81ca0277daf0"

CAPS = [
    # prefix, capability, module, context
    ("RQ", "split-request", "MOD-001", "CTX-001"),
    ("SL", "split-slots", "MOD-002", "CTX-002"),
    ("AU", "split-authorization", "MOD-003", "CTX-003"),
    ("CP", "split-checkpoint", "MOD-004", "CTX-004"),
    ("EN", "split-envelope", "MOD-005", "CTX-005"),
    ("SH", "split-shard-holders", "MOD-006", "CTX-006"),
    ("HO", "split-handoff", "MOD-007", "CTX-008"),
]
REQ_RE = r"(?:RQ|SL|AU|CP|EN|SH|HO)-\d{3}"

# ---------------------------------------------------------------- specs
def cited_decisions(body):
    out = set()
    for grp in re.findall(r"DECISIONS? (\d+(?:(?: item \(\d+\)| D\d+)?(?:, | and )\d+)*(?: item \(\d+\)| D\d+)?)", body):
        grp = re.sub(r"item \(\d+\)|D\d+", "", grp)
        out |= {int(n) for n in re.findall(r"\d+", grp)}
    return sorted(out)


reqs = []
for prefix, cap, mod, ctx in CAPS:
    text = (ROOT / CHANGE / "specs" / cap / "spec.md").read_text(encoding="utf-8")
    blocks = re.split(r"^### Requirement: ", text, flags=re.M)[1:]
    for b in blocks:
        head, body = b.split("\n", 1)
        rid, title = head.split(" ", 1)
        assert rid.startswith(prefix), rid
        body = body.split("\n#### Scenario:")[0]
        reqs.append({
            "id": rid, "title": title.strip(), "cap": cap, "module": mod, "context": ctx,
            "body": body,
            "decisions": cited_decisions(body),
            "claims": sorted({int(c) for c in re.findall(r"\bC(\d+)\b", body)}),
            "deps": sorted(set(re.findall(rf"\b{REQ_RE}\b", body)) - {rid}),
            "questions": sorted(set(re.findall(r"\bQ-\d{3}\b", body))),
            "opens": sorted(set(re.findall(r"\bO\d+\b", body)), key=lambda s: int(s[1:])),
        })
REQ = {r["id"]: r for r in reqs}

# ---------------------------------------------------------------- DECISIONS
def entries(text):
    out = {}
    cur = None
    for line in text.split("\n"):
        m = re.match(r"^(\d+)\. (.*)$", line)
        if m:
            cur = int(m.group(1))
            out[cur] = [m.group(2)]
        elif cur is not None and (line.startswith("   ") or line == ""):
            out[cur].append(line)
        else:
            cur = None
    return out


def field(lines, *names):
    """Text of the first field among names, sub-bullets joined."""
    buf, on = [], False
    for line in lines[1:]:
        m = re.match(r"^   - ([A-Z][A-Za-z ]+?)(?: and authority| for item \d+| \([^)]*\))?:\s*(.*)$", line)
        if m:
            if on:
                break
            if m.group(1) in names:
                on = True
                if m.group(2):
                    buf.append(m.group(2))
            continue
        if on and line.strip():
            buf.append(line.strip().lstrip("- ").strip())
    return " ".join(buf).strip()


main_txt = (ROOT / "design/enhancement/DECISIONS.md").read_text(encoding="utf-8")
qs_txt = subprocess.run(["git", "-C", str(ROOT), "show", f"{QS}:design/enhancement/DECISIONS.md"],
                        capture_output=True, text=True, check=True).stdout
E_main, E_qs = entries(main_txt), entries(qs_txt)

consumed = sorted({d for r in reqs for d in r["decisions"]})

AUTH = {
    "lead-merge": "Lead decision for the merge of the three protocol lanes, 2026-11-14 (DECISIONS preamble).",
    "owner-19": "Owner ruling 2026-11-14: seizure is optional (DECISIONS section before entry 19).",
    "owner-21": "Owner ruling 2026-11-14: n shards, arbitrary actors (DECISIONS section before entry 21).",
    "lead-speed": "Lead decision on the speed lanes, 2026-11-14 (DECISIONS section before entry 26).",
    "lead-fold": "Lead decision folding entries 26 to 32 into the multi-shard design, 2026-11-14.",
    "lead-review3": "Lead decision on cross-family review 3 (review-3/TRIAGE.md) under owner delegation, 2026-11-14 (LOOP.md rules).",
    "lead-sessions": "Lead decision adopting seald Sessions (Veritee branch committee-sessions) under owner delegation, 2026-11-14.",
    "owner-52": "Owner ruling 2026-11-14, verbatim in LOOP.md log: 'use the batched design you are insane to make that many commits to midnight save space, tokens, and transactions'.",
    "lead-qs": "Lead decision under owner delegation on branch quint-split (Quint findings and paper review), 2026-11-14. Not merged to main.",
    "lead-replay": "Lead decision under owner delegation, 2026-11-14 (conformance replay of impl/, item 6 gaps G1, G2).",
    "lead-frame": "Lead decision under owner delegation, 2026-11-14 (envelope framing from the prototype, item 11).",
    "lead-settle": "Lead decision under owner delegation, 2026-11-15 (restart settlement leaves, item 12, Q-008).",
    "owner-f6": "Owner ruling, 2026-11-15 (item 14 finding F6: no reason STALLED after a committed RELEASE; late admission stays allowed).",
    "lead-quint14": "Lead decision under owner delegation, 2026-11-15 (fixes for the spec-only Quint findings F1 to F5, item 14).",
    "lead-17a": "Lead decision under owner delegation, 2026-11-15 (design findings of the paper review, item 17a).",
    "lead-25": "Lead decision under owner delegation, 2026-11-15 (Sessions records D-032 to D-045, item 25).",
    "owner-f7": "Owner ruling, 2026-11-15 (item 14c finding F7: CP-014 lists only indices at or above the previous pending_min; SL-004 unchanged).",
    "lead-40": "Lead pick, for owner confirmation, 2026-11-16 (enhancements from the literature survey, item 40).",
    "lead-41": "Lead pick, for owner confirmation, 2026-11-16 (committee handoff, item 41), inside the owner rulings of 2026-11-16: the user's shard stays unchanged, and the protocol must permit key rotation.",
}


def authority(n):
    if n <= 18:
        return "lead-merge"
    if n <= 20:
        return "owner-19"
    if n <= 25:
        return "owner-21"
    if n <= 32:
        return "lead-speed"
    if n <= 41:
        return "lead-fold"
    if n <= 50:
        return "lead-review3"
    if n == 51:
        return "lead-sessions"
    if n == 52:
        return "owner-52"
    if n in (53, 54):
        return "lead-qs"
    if n <= 56:
        return "lead-replay"
    if n == 57:
        return "lead-frame"
    if n == 58:
        return "lead-settle"
    if n == 64:
        return "owner-f6"
    if 65 <= n <= 68:
        return "lead-17a"
    if n == 69:
        return "lead-25"
    if n == 71:
        return "owner-f7"
    if 72 <= n <= 78:
        return "lead-40"
    if 79 <= n <= 86:
        return "lead-41"
    return "lead-quint14"


# Requirements that carry a decision without citing it (from the
# Confirmation targets added to entries 1-41 and from the slot rules).
EXTRA_OBL = {
    8: ["RQ-024", "RQ-030", "AU-010"],
    19: ["AU-006", "RQ-066"],
    20: ["AU-005", "AU-006", "AU-007"],
    21: ["SH-005", "SH-006"],
    22: ["SH-001", "SH-002", "SH-003", "SH-004", "SH-022"],
    27: ["EN-010", "SL-027"],
    28: ["EN-016"],
    29: ["RQ-030", "AU-011"],
    34: ["EN-018", "EN-022"],
    35: ["RQ-016", "RQ-017", "RQ-023", "SL-008"],
    36: ["SH-014", "SH-022"],
    38: ["RQ-035"],
    40: ["RQ-038"],
    # DECISIONS 59 to 63 change these requirements without each citing the entry.
    59: ["RQ-030", "RQ-037"],
    60: ["AU-023"],
    62: ["RQ-003"],
    # DECISIONS 64 changes RQ-045 (reason posts) through RQ-074.
    64: ["RQ-045"],
}

def split_conf(text):
    """Split a Confirmation field into (kind, clause) pairs on its kind prefixes."""
    if not text:
        return []
    parts = list(re.finditer(r"(conformance|outcome),\s*(.*?)(?=[;.]\s+(?:conformance|outcome),|$)", text))
    if not parts:
        return [("outcome", text)]
    return [(m.group(1), m.group(2).strip().rstrip(";.")) for m in parts]


# Claims a record names in its context when it has no Drivers field (53).
EXTRA_CLAIMS = {53: [7, 11]}

decisions = []
for n in consumed:
    src = E_main.get(n) or E_qs.get(n)
    if src is None:
        sys.exit(f"DECISIONS {n} cited but absent")
    on_main = n in E_main
    head = src[0]
    title = re.sub(r"\*\*", "", re.match(r"^\*\*(.+?)\*\*", head).group(1) if head.startswith("**") else head.split(". ")[0]).rstrip(".")
    headline = re.sub(r"^\*\*.+?\*\*\s*", "", head, count=1).strip()
    # Entries 1-41 state the choice in the entry text; their Outcome field names the option and authority.
    if n <= 41:
        pre = []
        for line in src[1:]:
            if line.startswith("   - Drivers:"):
                break
            if line.strip():
                pre.append(line.strip())
        headline = " ".join([headline] + pre).strip()
    outcome = (headline or title) if n <= 41 else (field(src, "Outcome", "Decision") or headline)
    options = field(src, "Considered options")
    rationale = field(src, "Rationale") or (f"Considered options: {options}" if options else "")
    drivers = field(src, "Drivers")
    conf = field(src, "Confirmation")
    revisit = field(src, "Revisit when")
    obl = sorted({r["id"] for r in reqs if n in r["decisions"]} | set(EXTRA_OBL.get(n, [])))
    claims = sorted({c for r in obl for c in REQ[r]["claims"]} | {int(c) for c in re.findall(r"\bC(\d+)\b", drivers)})
    spec_claims = {c for r in reqs for c in r["claims"]}
    claims = sorted((set(claims) | set(EXTRA_CLAIMS.get(n, []))) & spec_claims)
    inv = [f"INV-{c:03d}" for c in claims]
    deps = sorted({int(m) for m in re.findall(r"\b(?:entry|entries|item|items) (\d+)\b", " ".join(src)) if int(m) in consumed and int(m) != n})
    missing = [f for f, v in (("drivers", drivers), ("options", options), ("confirmation", conf), ("revisit", revisit)) if not v]
    d = {
        "id": f"D-{n:03d}",
        "version": 1,
        # entries 72 to 78 are lead picks that wait for the owner's confirmation
        "state": "provisional" if not on_main or 72 <= n <= 86 else "confirmed",
        "basis": "explicit",
        "source_refs": ["SRC-002"] if on_main else ["SRC-004"],
        "title": title,
        "choice": outcome,
        "rationale": rationale or "Stated in the entry text of record_ref.",
        "authority": AUTH[authority(n)],
        "evidence_refs": ["SRC-001", "SRC-002"] if on_main else ["SRC-003", "SRC-004"],
        "affected_ids": sorted({REQ[r]["context"] for r in obl} | {REQ[r]["module"] for r in obl}),
        "record_ref": (f"design/enhancement/DECISIONS.md entry {n}" if on_main
                       else f"git {QS[:7]} (branch quint-split) design/enhancement/DECISIONS.md entry {n}"),
        "driver_refs": inv or (["SRC-002"] if "owner" in drivers.lower() else ["SRC-001"]),
        "drivers_text": drivers or None,
        "consumed_items": [f"D-{m:03d}" for m in deps],
        "obligation_refs": obl,
        "confirmation": [
            {"kind": "conformance",
             "method": "Lean oracle (LOOP item 13) executes the obligation requirements as transitions and refusals; every refusal leaves the state unchanged.",
             "target_refs": obl},
            {"kind": "outcome",
             "method": "Quint model (LOOP item 14) checks the invariants of the claims that the obligation requirements name.",
             "target_refs": inv or obl},
        ] + [{"kind": k, "method": m, "target_refs": obl, "source": "DECISIONS record; evidence for the choice, not a check of these specs"}
             for k, m in split_conf(conf)],
        "revisit_when": [revisit] if revisit else ["Q-006"],
        "supersedes": None,
    }
    if not on_main:
        d["unresolved"] = ["Q-004"] + (["Q-006"] if missing else [])
    elif missing:
        d["unresolved"] = ["Q-006"]
    if missing:
        d["record_gaps"] = missing
    decisions.append(d)

# ---------------------------------------------------------------- hand data
SRC = [
    {"id": "SRC-001", "locator": "design/enhancement/DESIGN.md",
     "authority": "Design of record for split-line dealing. Where impl/ disagrees, DESIGN wins.",
     "revision": "mpcexperiments 4a20ccc (main), sha256 9a79302cafa2053abe2021967adcfaa944a70b9d0b24f58bfe112cb1b2735030"},
    {"id": "SRC-002", "locator": "design/enhancement/DECISIONS.md",
     "authority": "Lead and owner decisions 1 to 52 and 55 to 86 (59 to 64 and 71 fix the item 14 Quint findings F1 to F7; 72 to 78 are lead picks from the literature survey and 79 to 86 lead picks for the committee handoff, all waiting for the owner's confirmation). This change adds MADR fields under the consumed entries 8 to 40 and leaves every entry text as it was.",
     "revision": "mpcexperiments 4a20ccc (main), sha256 57c1ac8c1451670a5ea8a7a6327ce0827760ee10cb9a6db49d047cfc452b8af6 before the MADR fields"},
    {"id": "SRC-003", "locator": "design/enhancement/DESIGN.md on branch quint-split",
     "authority": "DESIGN hunks of DECISIONS 53 and 54 (restart settlement, ECDSA precedence) and the O38 row. Not merged to main; the specs take these hunks over the main copy.",
     "revision": f"{QS}, sha256 c1fa28a9b2e7184c947ee28d4f5042659ae7867c04fdff4cf3ee677c5af8dbec"},
    {"id": "SRC-004", "locator": "design/enhancement/DECISIONS.md on branch quint-split",
     "authority": "DECISIONS 53 and 54. Not merged to main (Q-004).",
     "revision": f"{QS}, sha256 32f6c02c0fba6504dc6abad24528528b8067e8ea1d92859771755e5ff193ff27"},
    {"id": "SRC-005", "locator": "LOOP.md (rules and log of 2026-11-14)",
     "authority": "Owner rules of the loop: lead decides disagreements with reasons; batched Midnight writes; no push.",
     "revision": "mpcexperiments 4a20ccc, sha256 bf5a3dcbc0184521f0f3ff49aac4b08d5ca793b164fbc96bcf825917a18080d3"},
    {"id": "SRC-006", "locator": "impl/ (src/split, src/request, envelope.rs)",
     "authority": "Evidence only. Gaps against DESIGN are listed in architecture.md.",
     "revision": "mpcexperiments 4a20ccc"},
    {"id": "SRC-007", "locator": "~/Projects/veritee/wt-sessions/openspec/changes/add-seald-sessions/specs/seald-sessions/spec.md",
     "authority": "seald Sessions requirements SS-001 to SS-145, the external context CTX-007 (DECISIONS 51).",
     "revision": "Veritee branch committee-sessions, baseline BASE-001 revision 5"},
]

CTX = [
    ("CTX-001", "request lifecycle", "Run each split-line request from post to settlement on the board: order, open, collect, admit, anchor, release, end and settle.", "MOD-001", ["CON-001", "CON-002", "CON-005", "CON-006"], "proposed; impl/src/split/state.rs is a partial prototype"),
    ("CTX-002", "slot pools", "Keep the committee Schnorr slot pools and the per-address ECDSA account pools, their states, precedence, window and binds.", "MOD-002", ["CON-001", "CON-004"], "proposed; impl/src/split/state.rs SlotState is a partial prototype"),
    ("CTX-003", "authorization ledger", "Hold asset records and authorizations on Midnight (FenrirAssets): accept, put in force, revoke, settle, carry VOIDs, land board-first roots.", "MOD-003", ["CON-002", "CON-003"], "proposed (Midnight contract)"),
    ("CTX-004", "checkpoint and restart", "Write the committee's Midnight checkpoints and decide every whole-committee restart, its burns and its recovery.", "MOD-004", ["CON-003", "CON-004"], "proposed"),
    ("CTX-005", "envelope", "Fix the one public frame, its checks and the threshold-PRF keys of every request type.", "MOD-005", ["CON-005"], "existing in impl/src/envelope.rs, extended"),
    ("CTX-006", "shard holders", "Govern actors outside Fenrir: access structure, birth, nonce pools, contributions, ECDSA leaf sets.", "MOD-006", ["CON-006", "CON-007"], "proposed"),
    ("CTX-008", "committee handoff", "Move every committee secret and authority from one epoch's roster to the next: ROTATE, carry, READY, HANDOVER, sweep, handover checkpoint, erase.", "MOD-007", ["CON-003", "CON-008"], "proposed"),
    ("CTX-007", "seald Sessions (external)", "Veritee's sealed session store and peer witness for slot state, seat logs and restore (SRC-007).", None, ["CON-004"], "existing upstream context, consumed through CON-004"),
]

AGG = [
    ("AGG-001", "request", "CTX-001", "MOD-001", "eid = H(hd ‖ auth_ref)", "phase, reason, order_pos, exp_c, collecting, actor slot table, anchor, released, any_release, restart_end, outcome (RQ-002)", [6, 9, 13, 18, 20], "One board block changes a request at most once per vote kind; the request commits with the block (RQ-006, RQ-056).", [42, 47, 53, 55]),
    ("AGG-002", "committee slot pool", "CTX-002", "MOD-002", "(suite, epoch) per committee", "slot states Free, Named, Reserved, Claimed, Burned, precedence holder, window position (SL-001, SL-002)", [12, 20], "A slot changes state inside one block evaluation; a bind first takes the seald witness (CON-004).", [27, 42, 44, 51]),
    ("AGG-003", "ECDSA account pool", "CTX-002", "MOD-002", "address (cm_addr) and leaf set T_ℓ", "ECDSA slots with leaf set, root, put entries, burns (SL-003)", [12, 17], "A put or bind counts once a landed checkpoint root covers its seat-log entry (SH-017, CP-016).", [43, 48, 51, 54]),
    ("AGG-004", "asset record", "CTX-003", "MOD-003", "record id on Midnight with nullifier per state", "profile, Γ hash, pin, nullifier, lock, hold accumulator, settlement (AU-001)", [6, 7, 11], "One Midnight transaction changes one record state; a settlement root lands per checkpoint (AU-020).", [8, 19, 20, 29, 47, 52]),
    ("AGG-005", "authorization", "CTX-003", "MOD-003", "auth_ref", "auth digest, source, in-force height, revocation height, board-first flag (AU-002)", [6, 7, 11], "In force and revoked are Midnight states; nodes read them at a finality depth (AU-010).", [8, 29, 49]),
    ("AGG-006", "checkpoint chain", "CTX-004", "MOD-004", "committee and checkpoint height h", "h, pending_min, pending_root, boot counters, restart_seq, seat roots, settle_root, bf_root (CP-001)", [16], "The contract accepts one checkpoint per height and checks the chain rules (CP-007 to CP-009).", [52, 53]),
    ("AGG-007", "actor nonce pool", "CTX-006", "MOD-006", "pool key under a pool-key root", "N_pool pairs (D, E), used flags (SH-013)", [3, 18, 19], "The actor's wallet marks a pair used and erases it in one step (SH-015).", [36]),
]

MOD = [
    ("MOD-001", "request state machine", "CTX-001", "split-request", "Request phases, votes, collection, anchors, release, end and settlement."),
    ("MOD-002", "slot manager", "CTX-002", "split-slots", "Pool states, precedence, window, binds and burns."),
    ("MOD-003", "FenrirAssets contract and authorize circuit", "CTX-003", "split-authorization", "Asset records, authorizations, holds, settlement roots."),
    ("MOD-004", "checkpoint writer and restart logic", "CTX-004", "split-checkpoint", "Checkpoint fields and signers, restart classification, burns, recovery, cold start."),
    ("MOD-005", "envelope codec", "CTX-005", "split-envelope", "Frame build and parse, public checks, layout, keys, capsules."),
    ("MOD-006", "actor wallet and birth coordinator", "CTX-006", "split-shard-holders", "Access structure, birth, pools, contribution rules."),
    ("MOD-007", "handoff state machine", "CTX-008", "split-handoff", "ROTATE intake, carry dealings, READY and HANDOVER, request ownership and sweep, handover checkpoint, erase."),
]

CON = [
    ("CON-001", "board order and slot precedence", "MOD-002", ["MOD-001"], ["CTX-001", "CTX-002"], "Requests name, reserve, claim and burn slots by board position; SLOT_TAKEN and lapse follow board order.", ["SL-004", "SL-005", "SL-006", "SL-008", "SL-009", "SL-010", "SL-016", "RQ-016", "RQ-026"], ["Q-003"]),
    ("CON-002", "authorization read", "MOD-003", ["MOD-001"], ["CTX-001", "CTX-003"], "Nodes read an authorization in force, its revocation height and its hold at a Midnight finality depth before release.", ["AU-010", "AU-016", "AU-018", "RQ-024", "RQ-030", "RQ-032", "RQ-033"], []),
    ("CON-003", "checkpoint contract", "MOD-004", ["MOD-003"], ["CTX-003", "CTX-004"], "One Midnight write per checkpoint carries pool fields, seat roots, settle_root and bf_root; no committee write per request.", ["CP-001", "CP-005", "CP-012", "AU-020", "AU-026"], []),
    ("CON-004", "seald Sessions slot API", "CTX-007", ["MOD-002", "MOD-004"], ["CTX-002", "CTX-004", "CTX-007"], "slot_bind, slot_put and restore under the peer witness; burns and restart decisions follow SS rules (DECISIONS 51).", ["SL-019", "SL-020", "SH-017", "CP-016", "CP-024"], ["Q-005"]),
    ("CON-005", "envelope frame", "MOD-005", ["MOD-001"], ["CTX-001", "CTX-005"], "One 16,384-byte frame, public checks before order, keys by threshold PRF after order.", ["EN-001", "EN-004", "EN-005", "EN-006", "EN-007", "EN-008", "EN-023", "RQ-003"], []),
    ("CON-006", "contribution", "MOD-006", ["MOD-001"], ["CTX-001", "CTX-006"], "An actor's contribution frame or embedded contribution fills one position; the combiner checks it at release.", ["EN-018", "EN-019", "RQ-018", "RQ-038", "SH-015", "SH-021"], []),
    ("CON-008", "activation record", "MOD-007", ["MOD-004", "MOD-001"], ["CTX-001", "CTX-004", "CTX-008"], "One Midnight record signed by t' seats of the armed epoch carries EKS_{e+1}, the roster, the ROTATE and the heartbeat under X_f; requests keep one owning epoch at every position.", ["HO-036", "HO-047", "HO-048", "HO-050", "HO-054", "HO-067", "HO-068", "CP-003", "CP-006", "CP-009"], []),
    ("CON-007", "birth certificate", "MOD-006", ["MOD-003"], ["CTX-003", "CTX-006"], "q BIRTH_OK signatures and escrow certificates admit an address record.", ["SH-009", "SH-011", "SH-012"], []),
]

CLAIM = {
    1: "Address binding: a certified address has key X = X_f + tw·G + Σ X_a with known shard logs.",
    2: "Birth proof of possession: no actor coalition certifies an X whose full key it knows.",
    3: "Sealed user half: all n nodes cannot sign outside the dealt variants.",
    4: "No spend without an admitted signing set.",
    5: "No spend without the committee: all actors with t − 1 nodes cannot sign.",
    6: "Authorization enforcement: no release without an unrevoked authorization in force on reserved slots.",
    7: "Hold enforcement (P2): a revoked authorization releases no new generation.",
    8: "Sealed until order: fewer than t nodes learn nothing before the ordering QC.",
    9: "Unselected variants stay sealed.",
    10: "Blindness: operators see only the listed public data.",
    11: "One spend per record state.",
    12: "One nonce use: no committee or ECDSA slot signs two messages.",
    13: "Liveness: a valid authorized envelope reaches FINAL, EXPIRED or VOID SLOT_TAKEN.",
    14: "Rotation: reshare at t = n − f preserves X_f and secrecy.",
    15: "Recovery: after Δ_rec without a checkpoint, the owner exits to D_exit.",
    16: "Cold start: a whole-committee restart loses no key, moves no coin, uses no slot twice.",
    17: "Unadmitted coalitions cannot sign.",
    18: "Sealed confinement per actor.",
    19: "No concurrent-session forgery against an actor.",
    20: "Reissue safety: a stalled request releases nothing; a reissue reuses no slot or pair.",
    21: "Actor identity hiding before release.",
}
cited_claims = sorted({c for r in reqs for c in r["claims"]})
for c in cited_claims:
    if c not in CLAIM:
        sys.exit(f"claim C{c} cited but not modelled")

AGG_OF_CLAIM = {}
for a in AGG:
    for c in a[5]:
        AGG_OF_CLAIM.setdefault(c, a[0])

QUESTIONS = [
    {"id": "Q-001", "blocks_readiness": False, "decision_owner": "lead",
     "question": "DESIGN names VOID cases without a reason code: malformed header (§5.4), dealer fault, foreign spend of the pin in TEE mode (§5.6), whole-committee restart (§7.11). The specs use MALFORMED, DEALER_FAULT, PIN_SPENT and RESTART.",
     "alternatives": ["adopt the four codes in DESIGN §5.1", "fold them into one code"],
     "affected": ["RQ-014", "RQ-015", "RQ-041", "RQ-048", "RQ-065"],
     "reason": "Codes are wire values; models need distinct values to trace refusals. Safety does not depend on the names."},
    {"id": "Q-002", "blocks_readiness": False, "decision_owner": "lead",
     "question": "Which reason a VOID tombstone carries when its f + 1 posts name different reasons. The specs take the reason of the completing post.",
     "alternatives": ["reason of the completing post", "reason of the first post", "a fixed priority order"],
     "affected": ["RQ-045"], "reason": "The outcome (VOID or RELEASED) does not depend on the reason.",
     "status": "resolved",
     "resolution": {"decision": "The tombstone reason is the reason that at least f + 1 of the counted posts carry; if none reaches f + 1 the reason is MIXED (RQ-045, RQ-072), and no rule reads MIXED as STALLED, SLOT_TAKEN or REVOKED (RQ-071, RQ-063, AU-019, AU-021).",
                    "reason": "Item 14 finding F2: with the completing post's reason a corrupt member chose the reason, REVOKED in a P1 charter and STALLED on a request that released, against C13 and C20. With f + 1 posts every named reason has an honest post.",
                    "authority": "lead decision, DECISIONS 61", "requirement_refs": ["RQ-045", "RQ-072", "RQ-071", "RQ-065", "RQ-063", "AU-019", "AU-021"]}},
    {"id": "Q-003", "blocks_readiness": False, "decision_owner": "lead",
     "question": "A node judges a header's committee slot precedence only after every earlier-ordered live envelope has opened or ended. DESIGN §4.1 orders precedence by board position and is silent on the wait.",
     "alternatives": ["wait for earlier headers (specs)", "judge at open and revise on SLOT_TAKEN"],
     "affected": ["SL-004", "CON-001"], "reason": "Without the wait two nodes can judge one slot differently; impl/ refuses with EarlierHeader, which matches."},
    {"id": "Q-004", "blocks_readiness": False, "decision_owner": "lead (merge of branch quint-split)",
     "question": "DECISIONS 53 and 54 and their DESIGN hunks exist only on branch quint-split. The specs follow them.",
     "alternatives": ["merge quint-split into main", "rewrite the specs to the main text"],
     "affected": ["D-053", "D-054", "RQ-052", "SL-006", "SL-007", "SL-011", "EN-015", "SH-018"],
     "reason": "DESIGN on main still burns ECDSA slots of an unauthorized namer and settles a restart end VOID. The lead decided both on quint-split; main must catch up before the oracle is accepted."},
    {"id": "Q-005", "blocks_readiness": False, "decision_owner": "lead (measurement, DESIGN §11)",
     "question": "Values of the reservation window B, the ECDSA window B_slot and the session size bound S_max.",
     "alternatives": ["measure under heavy-slot --exclusive"],
     "affected": ["SL-012", "CON-004"], "reason": "The specs and models use the symbols; the deployment picks the numbers."},
    {"id": "Q-006", "blocks_readiness": False, "decision_owner": "lead",
     "question": "DECISIONS 53 lacks Drivers and Considered options fields; its D item carries them from the entry text until the record is completed on merge.",
     "alternatives": ["add the fields on the quint-split merge"],
     "affected": ["D-053"], "reason": "Documentation only; the obligations and confirmation of 53 are stated."},
]

QUESTIONS += [
    {"id": "Q-007", "blocks_readiness": False, "decision_owner": "lead",
     "question": "DESIGN §4.2 says the actor 'may refuse' a request. OpenSpec strict needs SHALL or MUST, so SH-023 states a SHALL refusal conditioned on the actor's own policy and names the code policy_refused, which DESIGN does not name.",
     "alternatives": ["keep the SHALL-on-policy form, with the policy as a free model input", "state the MAY cell outside the OpenSpec capability"],
     "affected": ["SH-023"], "reason": "The models take the policy as a free input either way; the code is a wire value.",
     "status": "resolved",
     "resolution": {"decision": "Keep SH-023 as a SHALL refusal conditioned on the actor's own policy, with the policy a free model input and the code policy_refused.",
                    "reason": "OpenSpec strict needs SHALL or MUST; the condition on the actor's own policy keeps the 'may refuse' meaning of DESIGN §4.2.",
                    "authority": "lead decision, LOOP item 12", "requirement_refs": ["SH-023"]}},
    {"id": "Q-008", "blocks_readiness": False, "decision_owner": "lead",
     "question": "DESIGN §5.6 and §7.11 say a whole-committee restart also ends again a request that ended after the latest landed checkpoint, and DECISIONS 53 settles every request the restart ends as FINAL or RELEASED. RQ-048 sets restart_end only for a live request whose slot the restart burns, and RQ-005 refuses events on a terminal request, so the re-end of an already terminal request has no requirement.",
     "alternatives": ["add a requirement that re-settles a terminal request whose slot the restart burns and whose settlement no landed root covers", "state that CP-030 and CP-033 settle those requests directly"],
     "affected": ["RQ-005", "RQ-048", "RQ-052", "RQ-068", "D-053"], "reason": "C11 across a restart depends on it; the oracle and the model must pick one form before item 13 freezes the transitions.",
     "status": "resolved",
     "resolution": {"decision": "Add RQ-068: when a whole-committee restart burns a slot of a request that ended after the latest landed checkpoint, the restart ends that request again and its outcome follows the restart settlement rule of RQ-052 (DECISIONS 53). RQ-005 excepts this re-end.",
                    "reason": "DESIGN §5.6 and §7.11 say the restart ends such a request again; without the rule a VOID settlement in the lost board tail can return a released record to unspent and break claim C11.",
                    "authority": "lead decision, LOOP item 12", "requirement_refs": ["RQ-068", "RQ-005", "RQ-048", "RQ-052", "RQ-054"]}},
]

ASM = [
    {"id": "ASM-001", "version": 1, "state": "provisional", "basis": "explicit", "source_refs": ["SRC-001"],
     "statement": "Non-TEE slot rules hold for |C| ≤ f, or for |C| < t with slot_anchor (DECISIONS 42).",
     "rationale": "Nonce agreement rests on board safety.", "affected": ["INV-005", "INV-012", "INV-020", "D-042"],
     "validation": "Quint model (item 14) with a forking board adversary", "if_false": "x_f leaks from three slot equations"},
    {"id": "ASM-002", "version": 1, "state": "provisional", "basis": "explicit", "source_refs": ["SRC-001"],
     "statement": "TEE mode: enclaves intact and at most n − 1 − 2f operators roll back or clone (DESIGN §7.7).",
     "rationale": "The peer witness bound.", "affected": ["INV-006", "INV-012", "INV-016"],
     "validation": "seald Sessions model (Veritee item 22)", "if_false": "the whole-committee restart rules apply instead"},
    {"id": "ASM-003", "version": 1, "state": "provisional", "basis": "explicit", "source_refs": ["SRC-001"],
     "statement": "An honest initiator for C18 secrecy (DECISIONS 40).",
     "rationale": "An actor cannot check P_{v,g} without κ_0.", "affected": ["INV-018", "D-040"],
     "validation": "stated premise in the Quint and Lean claims", "if_false": "the initiator reads its actors' scalars and gains no signature"},
]

# ---------------------------------------------------------------- emit baseline
# Item versions above 1: items changed in baseline revision 2.
VERSION = {"RQ-005": 2, "RQ-048": 2, "RQ-054": 2, "SH-023": 2, "JNY-003": 2,
           # revision 3: DECISIONS 59 to 63
           "RQ-003": 2, "RQ-006": 2, "RQ-030": 2, "RQ-045": 2, "RQ-050": 2, "RQ-051": 2, "RQ-063": 2, "RQ-065": 2,
           "AU-019": 2, "AU-021": 2, "AU-023": 2, "AU-025": 2, "SL-005": 2, "EN-021": 2, "CON-005": 2,
           # revision 4: DECISIONS 64
           "RQ-047": 2, "RQ-072": 2,
           # revision 6: DECISIONS 71
           "CP-014": 2,
           # revision 7: DECISIONS 79 to 85
           "CP-006": 2, "CP-003": 2}
VERSION.update({"RQ-045": 3, "AU-021": 3})


def item(**k):
    return {"version": VERSION.get(k.get("id"), 1), "state": "provisional", "basis": k.pop("basis", "proposed"), **k}

base = {
    "protocol": "spec-refinement/v1",
    "project_id": "mpcexperiments-split-line-dealing",
    "artifact_id": "BASE-001",
    "revision": 7,
    "revision_note": "Revision 1: Architecture and Technical Decisions stage of LOOP item 12 on mpcexperiments 4a20ccc with DECISIONS 53 and 54 from quint-split. Revision 2: lead resolves Q-007 (SH-023 form kept) and Q-008 (new RQ-068, RQ-005 excepts the restart re-end, RQ-048 points to RQ-068, RQ-054 lets the restart leaf supersede a leaf that Midnight does not hold, DECISIONS 58). Revision 3: fixes for the item 14 Quint findings, DECISIONS 59 to 63: RQ-069 RELEASE before send in NON_TEE mode (F1, D-059); AU-029 and AU-025 keep a LOCKED record LOCKED after a VOID settlement (F5, D-060); RQ-045, RQ-072, RQ-071 tombstone reason by f + 1 posts or MIXED, Q-002 resolved (F2, D-061); EN-023 public check exp_c < exp (F3, D-062); SL-005 state-driven lapse (F4, D-063). Revision 4: owner ruling on finding F6 of the revision 3 run, DECISIONS 64: RQ-073 no reason STALLED with any_release = true, RQ-074 no STALLED reason post after a RELEASE, RQ-045 and RQ-072 count reason posts, late admission stays allowed (D-064). Revision 5: lead rulings on the replay of the item 14 Quint traces through the Lean oracle, DECISIONS 70: RQ-075 refuses a frame for an OPENED or ADMITTED target with late_contribution, RQ-076 keeps any_release and released across a restart that loses the board tail, its note says that RQ-020 also refuses the ORDERED hold above exp_c (D-070). Revision 6: owner ruling on finding F7 of the item 14c run, DECISIONS 71: CP-014 lists only the committee slots at or above the pending_min of the previous landed checkpoint, so a precedence below the landed floor (SL-004) no longer makes CP-040 refuse the honest checkpoint; SL-004 unchanged (D-071). Revision 7: committee handoff, LOOP item 41, DECISIONS 79 to 86: new capability split-handoff (HO-001 to HO-068, MOD-007, CTX-008, CON-008); CP-006 puts EKS_e into the activation record in place of a separate Key Registry write (D-083); CP-003 counts t checkpoint signers (D-086).",
    "sources": SRC,
    "outcomes": [
        item(id="G1", basis="derived", source_refs=["SRC-001"], statement_ref="DESIGN §1", success="No spend without an admitted signing set and the committee (claims C4, C5, C17)."),
        item(id="G2", basis="derived", source_refs=["SRC-001"], statement_ref="DESIGN §1", success="Requests stay sealed to fewer than t nodes until order and to operators in TEE mode (C8 to C10, C21)."),
        item(id="G3", basis="derived", source_refs=["SRC-001", "SRC-005"], statement_ref="DESIGN §7.13, DECISIONS 52", success="One spend per record state and one nonce use, across restarts, with Midnight writes per checkpoint only (C11, C12, C16)."),
    ],
    "actors": [
        {"id": "ACT-001", "name": "committee node", "role": "Orders, opens, votes, releases and checkpoints (Fenrir member)."},
        {"id": "ACT-002", "name": "initiator wallet", "role": "Builds the envelope and its own contribution."},
        {"id": "ACT-003", "name": "outside actor", "role": "Holds a shard and contributes from its nonce pool."},
        {"id": "ACT-004", "name": "Midnight FenrirAssets contract", "role": "Holds records, authorizations and checkpoints."},
        {"id": "ACT-005", "name": "recovery group E", "role": "Holds the backup of x_f and reprovisions after Δ_rec."},
        {"id": "ACT-006", "name": "guardian group G", "role": "Escrow branch of P2 seizure."},
    ],
    "scope": {
        "included": ["split-line request state machine", "committee and ECDSA slot pools", "Midnight authorization ledger rules", "checkpoints and whole-committee restart", "envelope frame and keys", "shard-holder birth and contribution rules"],
        "excluded": ["the cryptographic instantiation of F_presig and F_mul (O1, O2, O19)", "rotation (C14, O5) and the exit leaf", "the seald Sessions store itself (CTX-007, specified in SRC-007)", "the ticket proof circuit (DECISIONS 30)"],
    },
    "glossary": [
        {"id": "GLO-001", "term": "half", "context": "CTX-001", "meaning": "One (variant, generation, input) signature share of a request."},
        {"id": "GLO-002", "term": "slot", "context": "CTX-002", "meaning": "A committee nonce pair (Schnorr) or a presignature (ECDSA) used once."},
        {"id": "GLO-003", "term": "anchor", "context": "CTX-001", "meaning": "The board block whose OBS reports fix the selected variant of a generation."},
        {"id": "GLO-004", "term": "seat log", "context": "CTX-004", "meaning": "Per-seat board log of binds and puts, covered by a root per checkpoint."},
        {"id": "GLO-005", "term": "pool pair", "context": "CTX-006", "meaning": "An actor's two-nonce commitment (D, E) used for one half."},
    ],
    "contexts": [item(id=c[0], source_refs=["SRC-001"], name=c[1], purpose=c[2], model_owner=(c[3] and next(m[1] for m in MOD if m[0] == c[3])) or "Veritee seald",
                      module_refs=[c[3]] if c[3] else [], glossary_refs=[g for g, cx in (("GLO-001", "CTX-001"), ("GLO-002", "CTX-002"), ("GLO-003", "CTX-001"), ("GLO-004", "CTX-004"), ("GLO-005", "CTX-006")) if cx == c[0]],
                      relationships=c[4], boundary=c[5]) for c in CTX],
    "aggregates": [item(id=a[0], source_refs=["SRC-001"], name=a[1], context=a[2], module=a[3], root_identity=a[4], holds=a[5],
                        invariant_refs=[f"INV-{c:03d}" for c in a[6] if c in cited_claims], atomic_scope=a[7], consistency_assumptions=["ASM-001", "ASM-002"],
                        decision_refs=[f"D-{n:03d}" for n in a[8] if n in consumed]) for a in AGG],
    "requirements_note": "Each entry references one EARS requirement of the change's capability specs. The statement and scenarios stay in the spec.",
    "modules": [item(id=m[0], source_refs=["SRC-001"], name=m[1], context=m[2], purpose=m[4], capability=f"{CHANGE}/specs/{m[3]}/spec.md",
                     responsibilities=[m[4]], exclusions=[], owned_concepts=[a[0] for a in AGG if a[3] == m[0]],
                     dependency_ids=sorted({cn[0] for cn in CON if m[0] in cn[3] or cn[2] == m[0]})) for m in MOD],
    "contracts": [item(id=c[0], basis="explicit", source_refs=["SRC-001"], name=c[1], producer=c[2], consumers=c[3], contexts=c[4], meaning=c[5],
                       requirement_refs=c[6], unresolved=c[7]) for c in CON],
    "invariants": [item(id=f"INV-{c:03d}", basis="explicit", source_refs=["SRC-001"], claim=f"C{c}", rule=CLAIM[c],
                        scope="system-wide", owner=AGG_OF_CLAIM.get(c, "MOD-001"), participants=[],
                        requirement_refs=[r["id"] for r in reqs if c in r["claims"]],
                        verification="Quint model (LOOP item 14) invariant; Lean oracle (LOOP item 13) theorem where the claim is a state property") for c in cited_claims],
    "journeys": [
        item(id="JNY-001", basis="explicit", source_refs=["SRC-001"], actor="ACT-002", trigger="A single-user spend is posted", handoffs=["MOD-005", "MOD-001", "MOD-002", "MOD-003"], success="FINAL after two board commits past finality", failure="VOID or EXPIRED with the codes of RQ-065", requirement_refs=["RQ-003", "RQ-006", "RQ-009", "RQ-023", "RQ-026", "RQ-027", "RQ-030", "RQ-044"]),
        item(id="JNY-002", basis="explicit", source_refs=["SRC-001"], actor="ACT-003", trigger="A collecting request names an outside actor", handoffs=["MOD-001", "MOD-006", "MOD-002"], success="ADMITTED after every position fills", failure="VOID STALLED at exp_c, reissue on fresh slots", requirement_refs=["RQ-016", "RQ-017", "RQ-018", "RQ-047", "SH-015", "SH-021", "EN-018"]),
        item(id="JNY-003", basis="explicit", source_refs=["SRC-001", "SRC-003"], actor="ACT-001", trigger="A whole-committee restart", handoffs=["MOD-004", "MOD-002", "MOD-001", "MOD-003"], success="Burns once per pool, restart ends settle FINAL or RELEASED", failure="ledger_unverified keeps the node down", requirement_refs=["CP-017", "CP-018", "CP-020", "CP-021", "RQ-048", "RQ-068", "RQ-052"]),
        item(id="JNY-004", basis="explicit", source_refs=["SRC-001"], actor="ACT-002", trigger="Address birth", handoffs=["MOD-006", "MOD-003"], success="Record admitted with a birth certificate", failure="no_birth_certificate", requirement_refs=["SH-006", "SH-007", "SH-009", "SH-011", "SH-016"]),
    ],
    "assumptions": ASM,
    "questions": QUESTIONS,
    "requirements": [item(id=r["id"], basis="explicit", source_refs=["SRC-001"] + (["SRC-003", "SRC-004"] if set(r["decisions"]) & {53, 54} else []),
                          title=r["title"], kind="quality" if re.search(r"\bClaims? C\d", r["body"]) else "functional",
                          statement_ref=f"{CHANGE}/specs/{r['cap']}/spec.md#{r['id']}", module=r["module"], context=r["context"],
                          contributors=[], acceptance_ref=f"scenarios of {r['id']}", dependencies=r["deps"],
                          **({"unresolved": r["questions"]} if r["questions"] else {}),
                          **({"open_items": r["opens"]} if r["opens"] else {})) for r in reqs],
    "decisions": decisions,
}

trace = {
    "protocol": "spec-refinement/v1",
    "project_id": base["project_id"],
    "artifact_id": "TRACE-001",
    "revision": 7,
    "baseline_ref": {"artifact_id": "BASE-001", "revision": 7},
    "spec_ref": f"{CHANGE}/specs",
    "status_note": "Every check is planned. Item 14 (Quint model) ran against revision 2 and found F1 to F5, which revision 3 fixes (DECISIONS 59 to 63); the revision 3 run found F6, which revision 4 fixes (DECISIONS 64); the item 14c run found F7, which revision 6 fixes (DECISIONS 71); its reruns are recorded in formal/quint-spec, not here. Item 13 (Lean oracle) and item 11 (impl/ adoption) have not run against these specs. The test vectors named in DECISIONS confirmations ran before this change and are evidence for the choice, not checks of these specs.",
    "check_items": {"item-11": "impl/ adopts DECISIONS 54 and the specs", "item-13": "Lean oracle", "item-14": "Quint model"},
    "requirements": [{"id": r["id"], "source_refs": base["requirements"][i]["source_refs"], "owner": r["module"],
                      "anchor": f"{CHANGE}/specs/{r['cap']}/spec.md#{r['id']}", "acceptance": f"scenarios of {r['id']}",
                      "checks": [{"item": 13, "kind": "conformance", "status": "planned"}]} for i, r in enumerate(reqs)],
    "invariants": [{"id": i["id"], "claim": i["claim"], "requirement_refs": i["requirement_refs"],
                    "checks": [{"item": 14, "kind": "outcome", "ref": f"Quint invariant for {i['claim']}", "status": "planned"}]} for i in base["invariants"]],
    "decisions": [{"id": d["id"], "state": d["state"], "record_ref": d["record_ref"], "driver_refs": d["driver_refs"],
                   "affected_ids": d["affected_ids"], "binding": True, "obligation_refs": d["obligation_refs"],
                   "checks": [
                       {"kind": "conformance", "item": 13, "ref": "Lean oracle transitions and refusals", "claim": f"obligations of {d['id']}", "target_refs": d["obligation_refs"], "status": "planned"},
                       {"kind": "outcome", "item": 14, "ref": "Quint model", "claim": "invariants of the claims named by the obligations", "target_refs": d["confirmation"][1]["target_refs"], "status": "planned"},
                   ] + ([{"kind": "conformance", "item": 11, "ref": "impl/ adoption", "claim": "impl/ follows the obligations", "target_refs": d["obligation_refs"], "status": "planned"}]
                        if d["id"] in ("D-051", "D-052", "D-053", "D-054", "D-057") else []),
                   **({"unresolved": d["unresolved"]} if d.get("unresolved") else {})} for d in decisions],
}

for d in decisions:
    d.pop("drivers_text", None) if d["drivers_text"] is None else None

hdr = "# Generated by specs/refinement/tools/gen.py. Edit the generator or the specs, not this file.\n"
(REF / "baseline.yaml").write_text(hdr + yaml.safe_dump(base, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
(REF / "traceability.yaml").write_text(hdr + yaml.safe_dump(trace, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
print(f"{len(reqs)} requirements, {len(decisions)} D items ({', '.join(d['id'] for d in decisions)}), {len(base['invariants'])} invariants")
