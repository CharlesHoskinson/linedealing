#!/usr/bin/env bash
# Generates the ITF corpus for impl/tests/quint_conformance.rs.
# usage: gen_traces.sh [JOBS_FILE] [OUT_DIR]   (default: jobs.txt, traces/)
# Job line: INSTANCE MAIN INIT STEP MAX_STEPS SAMPLES N_TRACES SEED [INVARIANT]
#   INSTANCE is the corpus subdirectory (n4, n7, broken_prevote, broken_rule4).
#   Without INVARIANT the run checks the five safety invariants (cNoNonceReuse ...)
#   and writes N_TRACES sampled traces. With INVARIANT (mutant rows) it writes the
#   counterexample of that invariant.
# Every run goes through heavy-run (heavy.slice). The log of each run is
# OUT_DIR/logs/<instance>_<init>_<step>_<seed>.log.
set -euo pipefail
# The corpus also holds scripted traces (n4/scripted_*.itf.json) exported with
# quint test --out-itf from the runs in linedealing_mbt.qnt; see CONFORMANCE.md.
cd "$(dirname "$0")"
jobs=${1:-jobs.txt}
out=${2:-traces}
mkdir -p "$out/logs"
INV="cNoNonceReuse cAtMostOneExecution cLockBeforeShare cNoTransientTombstone cFreezeSafety"
one() {
  read -r inst main init step steps samples ntr seed inv <<< "$1"
  mkdir -p "$out/$inst"
  tag="${init}_${step}_s${seed}"
  log="$out/logs/${inst}_${tag}.log"
  if [ -n "${inv:-}" ]; then
    args=(--invariant="$inv")
  else
    args=(--invariants $INV)
  fi
  { echo "# quint run --main=$main --init=$init --step=$step --max-steps=$steps --max-samples=$samples --n-traces=$ntr --seed=$seed --mbt ${args[*]}"; } > "$log"
  heavy-run --mem 8G --name "mbt-$inst-$seed" -- quint run linedealing_mbt.qnt --main="$main" --init="$init" \
    --step="$step" --max-steps="$steps" --max-samples="$samples" --n-traces="$ntr" --seed="$seed" --mbt \
    --out-itf="$out/$inst/${tag}_{seq}.itf.json" "${args[@]}" >> "$log" 2>&1 || true
  echo "$inst $tag: $(grep -E '^\[(ok|violation)\]|error' "$log" | head -2 | tr '\n' ' ')"
}
export -f one; export out INV
grep -v -e '^\s*$' -e '^#' "$jobs" | xargs -P "${PAR:-4}" -I{} bash -c 'one "$@"' _ {}
# Drop the per-step nondet picks: the replay derives each step from the state diff.
python3 - "$out" <<'PY'
import json, pathlib, sys
for p in pathlib.Path(sys.argv[1]).glob("*/*.itf.json"):
    d = json.loads(p.read_text())
    for s in d["states"]:
        s.pop("mbt::nondetPicks", None)
    d["vars"] = [v for v in d["vars"] if v != "mbt::nondetPicks"]
    p.write_text(json.dumps(d, separators=(",", ":")))
PY
# Keep the command and the verdict of each log; the traces themselves are the ITF files.
for f in "$out"/logs/*.log; do
  { head -1 "$f"; echo "# (trace printout removed; the trace is ../<instance>/<tag>_<n>.itf.json)"
    grep -E '^\[(ok|violation)\]|^error|^Trace length|witnessed' "$f"; } > "$f.tmp" && mv "$f.tmp" "$f"
done
# Fail loudly: every job must end with a verdict, and every mutant row must violate.
bad=0
for f in "$out"/logs/*.log; do
  grep -qE '^\[(ok|violation)\]' "$f" || { echo "NO VERDICT: $f"; bad=1; }
  case "$(basename "$f")" in broken_*) grep -q '^\[violation\]' "$f" || { echo "MUTANT NOT VIOLATED: $f"; bad=1; };; esac
  # A directed row that ends [ok] did not reach its target; its trace is an ordinary sample.
  case "$(basename "$f")" in broken_*) ;; *)
    head -1 "$f" | grep -q -- '--invariant=' && grep -q '^\[ok\]' "$f" && echo "DIRECTED TARGET NOT REACHED: $f";;
  esac
done
exit $bad
