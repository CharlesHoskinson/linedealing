#!/usr/bin/env bash
# Checks of formal/quint/splitline_binding.qnt (DECISIONS 72, finding E1) and export of its
# scripted traces to tests/quint-regressions/splitline/binding/.
# Each job is: NAME|EXPECT|quint arguments. EXPECT: ok, violation, testfail or exit0.
# The jobs are kept out of jobs.txt: a change of jobs.txt changes MODEL.sha256 and clears
# every log of run_all.sh. Run under heavy-run:
#   heavy-run --mem 8G -- formal/quint/runs/split/run_binding.sh
set -u
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../.."
logs="$here/binding"; mkdir -p "$logs"; rm -f "$logs"/*.log
out=../../tests/quint-regressions/splitline/binding; mkdir -p "$out"
m=splitline_binding.qnt
run="--init dinit --step dstep --max-steps 12 --max-samples 5000 --seed 7"
fail=0
job() {
  local name=$1 expect=$2 log="$logs/$1.log" got; shift 2
  quint "$@" > "$log" 2>&1; local code=$?
  if [ "$expect" = exit0 ]; then got=$([ $code = 0 ] && echo exit0 || echo "exit$code")
  elif [ "$expect" = testfail ]; then got=$(grep -q ' failed' "$log" && echo testfail || echo ok)
  elif grep -q '\[violation\]' "$log"; then got=violation
  elif grep -q '\[ok\]' "$log"; then got=ok
  elif grep -q ' passing' "$log" && ! grep -q ' failed' "$log"; then got=ok
  else got=error; fi
  local mark=PASS; [ "$got" = "$expect" ] || { mark=FAIL; fail=1; }
  printf '%-36s %-9s %-9s %s %s\n' "$name" "$expect" "$got" "$mark" \
    "$(grep -E '\[ok\]|\[violation\]| passing| failed' "$log" | head -1 | cut -c1-70)"
}
# shellcheck disable=SC2086
{
job tc_splitline_binding exit0 typecheck $m
job binding_design ok run $m --main dl_design $run --invariant BindingInvariants --witnesses TwoInitiatorsReached AnswerReached
job binding_design_rollback ok run $m --main dl_design_rollback $run --invariant BindingInvariants --witnesses SecondAnswerReached
job binding_m_no_initiator violation run $m --main dm_no_initiator $run --invariant C19_BindingFixesWeight
job binding_m_no_initiator_guard ok run $m --main dm_no_initiator $run --invariant "C19_OneNonceOneWeight and C19_OneAnswerPerPair"
job binding_m_no_initiator_rollback violation run $m --main dm_no_initiator_rollback $run --invariant C19_OneNonceOneWeight
job test_dt_design ok test $m --main dt_design --match '.*Holds'
job test_dt_no_initiator ok test $m --main dt_no_initiator --match '.*Broken|secondAnswerRefusedHolds'
job neg_dt_design_broken testfail test $m --main dt_design --match '.*Broken'
job neg_dt_no_initiator_holds testfail test $m --main dt_no_initiator --match 'twoInitiatorsHolds|restoredPoolHolds'
}
t() {  # module run
  rm -f "$out/$1__$2.itf.json"
  quint test $m --main "$1" --match "^$2\$" --out-itf "$out/$1__$2.itf.json" 2>&1 | grep -q ' 1 passing' \
    || { echo "FAIL export $1 $2"; fail=1; }
  [ -s "$out/$1__$2.itf.json" ] || { echo "MISSING $1__$2"; fail=1; }
}
for r in twoInitiatorsHolds secondAnswerRefusedHolds restoredPoolHolds; do t dt_design $r; done
for r in twoInitiatorsBroken restoredPoolBroken; do t dt_no_initiator $r; done
quint run $m --main dm_no_initiator $run --invariant C19_BindingFixesWeight \
  --out-itf "$out/e1_dm_no_initiator_sampled.itf.json" > /dev/null 2>&1
[ -s "$out/e1_dm_no_initiator_sampled.itf.json" ] || { echo "MISSING sampled trace"; fail=1; }
exit $fail
