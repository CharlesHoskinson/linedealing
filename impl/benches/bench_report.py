"""Derive the BENCHMARKS.md scale tables from the criterion and size outputs.

Run from impl/ after the timing run:
  python3 -I benches/bench_report.py target/criterion LOGDIR > LOGDIR/derived.json
LOGDIR holds split-sizes.txt. Prints one JSON object: medians per row and n,
the derived per-request figures, the scale table and the Midnight counts.
"""
import json
import math
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
logs = pathlib.Path(sys.argv[2])
SIZES = [5, 9, 17, 33]


def faults(n):
    return (n - 1) // 3


def med(n, row):
    p = root / f"split_n{n}" / row / "new" / "estimates.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())["median"]["point_estimate"] / 1e6  # ms


rows = sorted(
    {
        "/".join(p.relative_to(root).parts[1:-2])
        for p in root.glob("split_n*/**/new/estimates.json")
    }
)
medians = {r: {n: med(n, r) for n in SIZES} for r in rows}

# split_sizes: frame rows and slot rows.
sizes_txt = (logs / "split-sizes.txt").read_text()
frame = {}
for m in re.finditer(r"^\| (\d+) \| BIP340 \| K=8, L=2 \| (\d+) \|", sizes_txt, re.M):
    frame[int(m.group(1))] = int(m.group(2))
slots4 = {}
for m in re.finditer(r"^\| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$", sizes_txt, re.M):
    slots4[int(m.group(1))] = int(m.group(4))

derived = {}
for n in SIZES:
    m = {r: medians[r][n] for r in rows}
    if m.get("pi_check") is None:
        continue
    t = n - faults(n)
    q = math.ceil((n + faults(n) + 1) / 2)
    header_key = m["header_partial"] + m["header_combine_open"]
    path = (
        m["pi_check"]
        + m["outer_share_check"]
        + header_key
        + m["release_ticket_checks"]
        + m["own_signature_partials"]
        + m["header_partial"]
        + m["open_body_reconstruct_combine_bip340_actors0"]
    )
    path_hi = path + m["vote_batch_verify_q_single_verify_strict"]
    slot = (t / n) * m["slot_deal_message"] + (t - t / n) * m["slot_batch_verify"]
    derived[n] = {
        "f": faults(n),
        "t": t,
        "q": q,
        "header_key": header_key,
        "path": path,
        "path_hi": path_hi,
        "failure_extra": m["combine_failure_path"]
        - m["open_body_reconstruct_combine_bip340_actors0"],
        "slots": slot,
        "slot_share": slot / (path + slot),
        "total": path + slot,
        "total_hi": path_hi + slot,
        "rate_lo": 1000 / (path_hi + slot),
        "rate_hi": 1000 / (path + slot),
        "combiner": m["open_body_reconstruct_combine_bip340_actors0"],
        "frame_used": frame.get(n),
        "slot_bytes": slots4.get(n),
        "board_bytes_measured": 16384 + slots4[n] if n in slots4 else None,
    }

# Midnight writes: one committee checkpoint transaction per 60 s interval,
# whatever the number of requests in it (DESIGN 11.6). Requests run at the
# per-core rate of one node core (lower end).
midnight = {}
for n, d in derived.items():
    rate = d["rate_lo"]
    per_cp = rate * 60
    midnight[n] = {
        "rate": rate,
        "requests_per_checkpoint": per_cp,
        # DESIGN 11.6 field list at P = 2 pools; not an encoder measurement.
        "checkpoint_payload_formula": 88 + 52 * 2 + 64 + 8 * n + 8 + 32 * n + 64 * d["q"],
        "rows": [
            {
                "requests": N,
                "checkpoints": math.ceil(N / per_cp),
                "committee_tx": math.ceil(N / per_cp),
                "user_tx_midnight_first": N,
                "user_tx_board_first": 0,
            }
            for N in (10**3, 10**5, 10**7)
        ],
    }

print(
    json.dumps(
        {"medians_ms": medians, "derived": derived, "midnight": midnight},
        indent=1,
    )
)
