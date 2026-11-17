#!/bin/sh
# Quint model runs of the Passport shard model (LOOP item 39, lane passport-quint).
#
#   run_quint.sh check     typecheck, assignment lint, refusal tests
#   run_quint.sh inv       every invariant on every instance and step, 10000 samples
#   run_quint.sh mutants   every mutant against its invariant; each must be violated
#   run_quint.sh traces    export replay traces (mixed step) under quint/traces/
#   run_quint.sh replay    replay the traces through the oracle, with negative controls
#   run_quint.sh all       the five above
#
# Logs go to quint/runs/. Run under heavy-run.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
q="$here/quint"
spec="$q/passportShard.qnt"
runs="$q/runs"
QUINT=${QUINT:-quint}
SAMPLES=${SAMPLES:-10000}
STEPS=${STEPS:-40}
SEED=${SEED:-20261116}
NTRACES=${NTRACES:-200}
ORACLE=${ORACLE:-$here/lean/.lake/build/bin/oracle}
FACTORY=${FACTORY:-$HOME/Projects/software-factory/plugins/formal}
mkdir -p "$runs"

INSTANCES="webSynced mixed allNative d0Two"
STEPS_ACTIONS="stepPass stepMostlyHonest step"
INVARIANTS="inv_PS001_cfgFixed inv_PS058_accessStructure inv_PS059_committeeNeedsAuthorization
inv_PS060_userVerifiedUnlock inv_noUserCoalitionWithoutCommittee inv_recoveryNoWholeKey
inv_PS019_assertionBindsIntent inv_PS064_oneIntentPerNf inv_authorizationSource
inv_PS066_hijackWebOnly inv_cfgDomain inv_PS067_enrolledNeverAdvSuccessor"
WITNESSES="w_honestFinalise w_advFinalise w_viaOrigin w_viaRecovery w_viaTheft w_viaProvider
w_viaQuorum w_wholeKey w_releaseSig w_advSig w_hijackAuth w_sigAfterReprovision w_refused
w_ant058 w_ant059 w_ant060 w_ant060exception w_antCoalition w_ant058corrupt w_wholeKeyViaQuorum
w_twoAuthorizations w_ant067 w_pendingSuccessorRefused"

check() {
  "$QUINT" typecheck "$spec" || return 1
  "$QUINT" typecheck "$q/passportShard_test.qnt" || return 1
  python3 -I "$FACTORY/scripts/quint_assignment_lint.py" "$spec" || return 1
  if "$QUINT" test "$q/passportShard_test.qnt" --main passportShardTest \
       --match '^(t|od[0-9]+)_' > "$runs/test.log" 2>&1
  then tail -n 2 "$runs/test.log"
  else tail -n 20 "$runs/test.log"; return 1; fi
}

inv() {
  fail=0
  : > "$runs/inv-summary.txt"
  for m in $INSTANCES; do
    for st in $STEPS_ACTIONS; do
      # witnesses once per instance and step, with the conjunction
      log="$runs/inv-$m-$st-all.log"
      if "$QUINT" run "$spec" --main "$m" --step "$st" --invariant inv \
           --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$SEED" \
           --witnesses $WITNESSES > "$log" 2>&1; then r=ok; else r=VIOLATED; fail=1; fi
      echo "$m $st inv $r" | tee -a "$runs/inv-summary.txt"
      for i in $INVARIANTS; do
        log="$runs/inv-$m-$st-$i.log"
        if "$QUINT" run "$spec" --main "$m" --step "$st" --invariant "$i" \
             --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$SEED" > "$log" 2>&1
        then r=ok; else r=VIOLATED; fail=1; fi
        echo "$m $st $i $r" | tee -a "$runs/inv-summary.txt"
      done
    done
  done
  return $fail
}

# mutant module : invariant that must fail (mut11 is expected to survive)
MUTANTS="mut1_noAssertion:inv_PS059_committeeNeedsAuthorization
mut1_noAssertion:inv_PS019_assertionBindsIntent
mut2_nfReuse:inv_PS064_oneIntentPerNf
mut3_noAuthorization:inv_PS059_committeeNeedsAuthorization
mut4_noContribution:inv_PS058_accessStructure
mut5_noCommitteeHalf:inv_noUserCoalitionWithoutCommittee
mut6_eHoldsRoot:inv_recoveryNoWholeKey
mut7_reprovisionDropsXf:inv_recoveryNoWholeKey
mut8_unlockNoPrf:inv_PS058_accessStructure
mut9_advAssertNoCred:inv_authorizationSource
mut10_originNative:inv_PS066_hijackWebOnly
mut4_noContribution:inv_PS060_userVerifiedUnlock
mut8_unlockNoPrf:inv_PS060_userVerifiedUnlock
mut12_theftNoPrf:inv_PS060_userVerifiedUnlock
mut13_enrollPendingSucc:inv_PS067_enrolledNeverAdvSuccessor
mut11_corruptRelease:inv"

mutants() {
  fail=0
  mkdir -p "$q/mutants"
  : > "$runs/mutant-summary.txt"
  for row in $MUTANTS; do
    m=${row%%:*}; i=${row#*:}
    log="$runs/mut-$m-$i.log"
    if "$QUINT" run "$spec" --main "$m" --step stepMostlyHonest --invariant "$i" \
         --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$SEED" \
         --out-itf "$q/mutants/$m-$i.itf.json" > "$log" 2>&1
    then r=SURVIVED; [ "$m" = mut11_corruptRelease ] || fail=1
    else r=KILLED; fi
    echo "$m $i $r" | tee -a "$runs/mutant-summary.txt"
  done
  rm -f "$q/mutants/mut11_corruptRelease-inv.itf.json"  # a survivor has no violating trace
  return $fail
}

traces() {
  for m in $INSTANCES; do
    rm -rf "$q/traces/$m"; mkdir -p "$q/traces/$m"
    "$QUINT" run "$spec" --main "$m" --step step --invariant inv \
      --max-samples "$NTRACES" --n-traces "$NTRACES" --max-steps 40 --seed "$SEED" \
      --out-itf "$q/traces/$m/t_{seq}.itf.json" > "$runs/traces-$m.log" 2>&1 || return 1
    "$QUINT" run "$spec" --main "$m" --step stepMostlyHonest --invariant inv \
      --max-samples "$NTRACES" --n-traces "$NTRACES" --max-steps 40 --seed "$SEED" \
      --out-itf "$q/traces/$m/h_{seq}.itf.json" >> "$runs/traces-$m.log" 2>&1 || return 1
  done
}

# Replay through the oracle (build it first: cd lean && lake build).
replay() {
  fail=0
  rp="python3 -I $here/scripts/passport_replay.py --oracle $ORACLE"
  $rp --probe-domain > "$runs/replay-domain.log" || fail=1
  tail -n 1 "$runs/replay-domain.log"
  for m in $INSTANCES; do
    $rp --traces "$q/traces/$m" --keep-going --census --regressions "$q/regressions" \
      > "$runs/replay-$m.log" 2>&1 || fail=1
    echo "$m: $(tail -n 1 "$runs/replay-$m.log")"
  done
  # Negative controls: a wrong cfg must change the behaviour the oracle computes.
  for ctl in "mixed native=[]" "webSynced quorum=1" "webSynced synced=[0]" "allNative native=[0]"; do
    m=${ctl%% *}; kv=${ctl#* }
    if $rp --traces "$q/traces/$m" --perturb-cfg "$kv" > "$runs/replay-neg.log" 2>&1; then
      echo "negative control $m $kv: AGREED (replay cannot fail)"; fail=1
    else echo "negative control $m $kv: DISAGREE (ok)"; fi
  done
  # Mutant traces: the specified oracle must disagree with each broken model.
  for t in "$q"/mutants/*.itf.json; do
    d=$(mktemp -d); cp "$t" "$d/"
    if $rp --traces "$d" > "$runs/replay-neg.log" 2>&1; then
      echo "mutant trace $(basename "$t"): AGREED"; fail=1
    else echo "mutant trace $(basename "$t"): DISAGREE (ok)"; fi
    rm -rf "$d"
  done
  # Kept counterexample traces (COUNTEREXAMPLES.md) replay as named tests.
  for t in "$q"/regressions/*.itf.json; do
    [ -e "$t" ] || continue
    d=$(mktemp -d); cp "$t" "$d/"
    if $rp --traces "$d" > "$runs/replay-reg.log" 2>&1; then r=agree; else r=DISAGREE; fail=1; fi
    echo "regression $(basename "$t"): $r"
    rm -rf "$d"
  done
  return $fail
}

case ${1:?usage: run_quint.sh check|inv|mutants|traces|replay|all} in
  check) check ;;
  inv) inv ;;
  mutants) mutants ;;
  traces) traces ;;
  replay) replay ;;
  all) check || exit 1; inv || exit 1; mutants || exit 1; traces || exit 1; replay || exit 1 ;;
  *) echo "unknown: $1" >&2; exit 2 ;;
esac
