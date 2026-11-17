#!/bin/sh
# drwatt stage gates of the split-line pipeline (LOOP item 16). Each requirement of the
# repo-root requirements.json runs one gate of this script from the repo root. A gate exits 0
# only when it holds. Every gate reads only files inside the repo, so it holds in the private
# copy where drwatt runs it; the tools (python3, openspec, lake, quint, cargo) come from PATH.
#
#   gate.sh ears | openspec | refinement           the spec stage
#   gate.sh oracle CAP | trace CAP | ids           the Lean oracle stage (formal/lean-split)
#   gate.sh quint-typecheck | quint-test MODULE | quint-kills
#                                                  the Quint model from the spec (formal/quint-spec)
#   gate.sh impl-test | impl-clippy | impl-fmt     the discovery prototype (impl/)
#   gate.sh reference-suite                        the k-rust reference suite (formal/krs-split)
#   gate.sh replay                                 Quint traces through five oracles
#
# Run `dw verify` itself under heavy-run or heavy-slot; the gates do not call heavy-run.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
change=openspec/changes/add-split-line-dealing
qs=formal/quint-spec

# quint test of one module: the passing count must equal the number of `run ...Test` in the
# module and nothing may fail, so an empty match fails the gate.
quint_test() {
  m=$1
  want=$(awk -v m="$m" '$0 ~ "^module "m" " {p=1; next} /^module / {p=0} p && /^  run [A-Za-z0-9_]+Test =/ {c++} END {print c+0}' "$qs/splitspec_test.qnt")
  [ "$want" -gt 0 ] || { echo "quint-test: module $m has no run ...Test" >&2; exit 1; }
  log=$(mktemp)
  rc=0
  (cd "$qs" && quint test splitspec_test.qnt --main "$m" --match 'Test$' --max-samples 1) >"$log" 2>&1 || rc=$?
  got=$(grep -oE "^  [0-9]+ passing" "$log" | grep -oE "[0-9]+" || true)
  failed=$(grep -cE "^  [0-9]+ failed" "$log" || true)
  if [ "$rc" = 0 ] && [ "${got:-0}" = "$want" ] && [ "$failed" = 0 ]; then
    echo "quint-test: $m: $got/$want tests pass"
    rm -f "$log"
  else
    cat "$log" >&2
    rm -f "$log"
    echo "quint-test: $m: exit $rc, ${got:-0}/$want passing, $failed failed lines" >&2
    exit 1
  fi
}

case ${1:?usage: gate.sh GATE [ARG]} in
  ears)
    python3 -I formal/drwatt/scripts/ears_lint.py --require-ids --strict -q "$change"/specs/*/spec.md ;;
  openspec)
    openspec validate add-split-line-dealing --strict ;;
  refinement)
    python3 -I specs/refinement/tools/check.py . ;;
  oracle)
    sh formal/lean-split/gates.sh oracle "${2:?CAP}" ;;
  trace)
    sh formal/lean-split/gates.sh trace "${2:?CAP}" ;;
  ids)
    python3 -I formal/lean-split/scripts/count_ids.py formal/lean-split ;;
  quint-typecheck)
    for f in splitspec.qnt splitspec_test.qnt; do (cd "$qs" && quint typecheck "$f"); echo "quint-typecheck: $f ok"; done ;;
  quint-test)
    quint_test "${2:?MODULE}" ;;
  quint-kills)
    # Every mutant instance m_* of splitspec.qnt has a kill module test_m_* whose scripted
    # schedule violates the mutated rule; each must pass.
    inst=$(grep -oE "^module m_[a-z0-9_]+" "$qs/splitspec.qnt" | sed 's/module //' | sort)
    kills=$(grep -oE "^module test_m_[a-z0-9_]+" "$qs/splitspec_test.qnt" | sed 's/module test_//' | sort)
    if [ "$inst" != "$kills" ]; then
      echo "quint-kills: mutant instances and kill modules differ" >&2
      echo "instances: $inst" >&2; echo "kill modules: $kills" >&2; exit 1
    fi
    n=0
    for m in $inst; do quint_test "test_$m"; n=$((n + 1)); done
    echo "quint-kills: $n of $n mutants killed by their schedules" ;;
  impl-test)
    (cd impl && cargo test --offline --release -j 4) ;;
  impl-clippy)
    (cd impl && cargo clippy --offline --all-targets -j 4 -- -D warnings) ;;
  impl-fmt)
    (cd impl && cargo fmt --check) ;;
  reference-suite)
    # LOOP item 15: for each capability, the locked k-rust compare against the Lean oracle
    # (gates.sh oracle-equal builds the oracle first) and the golden-vector check.
    for c in envelope authorization shard-holders checkpoint slots request; do
      sh formal/krs-split/gates.sh oracle-equal "$c"
      sh formal/krs-split/gates.sh golden "$c"
    done
    echo "reference-suite: six capabilities equal to the oracle under kink.lock, golden vectors current" ;;
  replay)
    # The committed traces of the Quint model (traces-sample/) through the --step mode of the
    # request, authorization, slots, envelope and shard-holders oracles, one lane each
    # (formal/lean-split/replay/README.md). The negative control must disagree where the
    # README says. Exit 0 only when every other trace agrees on every transition of every lane.
    for c in request authorization slots envelope shard-holders; do (cd formal/lean-split/$c && lake build oracle >/dev/null); done
    ts=$qs/traces-sample
    lb=formal/lean-split
    python3 -I $lb/replay/replay.py --oracle $lb/request/.lake/build/bin/oracle \
      --auth-oracle $lb/authorization/.lake/build/bin/oracle --slots-oracle $lb/slots/.lake/build/bin/oracle \
      --envelope-oracle $lb/envelope/.lake/build/bin/oracle --shard-oracle $lb/shard-holders/.lake/build/bin/oracle \
      --traces $ts/tee_p2_initArmed $ts/nontee_p2_initArmed $ts/tee_p2_refusals \
        $ts/tests_test_tee_p2 $ts/tests_test_tee_p1 $ts/tests_test_nontee_p2 \
      --expect-disagree "$ts/mutant_stalled_after_release_tee_p1@post_void@reason: model STALLED, oracle MIXED" ;;
  *)
    echo "gate.sh: unknown gate $1" >&2; exit 2 ;;
esac
