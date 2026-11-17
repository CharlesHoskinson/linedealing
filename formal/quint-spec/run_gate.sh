#!/usr/bin/env bash
# Gate for formal/quint-spec (LOOP item 14). Resumable: every finished check writes one line to
# logs/ledger.tsv and a rerun skips the checks already in the ledger. Delete a line to rerun it.
# Revision 3 (specs with DECISIONS 59 to 63): the revision-2 ledger is logs/ledger-rev2.tsv.
# Revision 5 (item 14 replay rulings A to E, DECISIONS 70): the revision-4 ledger is logs/ledger-rev4.tsv.
# Revision 6 (design corrections, DECISIONS 65 to 69): the revision-5 ledger is logs/ledger-rev5.tsv.
# Revision 7 (F7 fix, DECISIONS 71): the revision-6 ledger is logs/ledger-rev6.tsv.
#
#   ./run_gate.sh            # every tier
#   ./run_gate.sh TIER...    # typecheck tests design c11 c20 mutants traces testtraces
#
# Long runs belong in a systemd user unit with a persistent log, for example
#   systemd-run --user --unit=quint-spec-14 --working-directory="$PWD" \
#     -p StandardOutput=append:"$PWD/logs/unit.log" -p StandardError=append:"$PWD/logs/unit.log" ./run_gate.sh
# Every quint call goes through heavy-run.
set -u
cd "$(dirname "$0")"
mkdir -p logs traces
LEDGER=logs/ledger.tsv
touch "$LEDGER"
Q() { heavy-run --mem 8G -- quint "$@"; }
done_already() { grep -qF -- "$1	" "$LEDGER"; }
record() { printf '%s\t%s\t%s\n' "$1" "$2" "$(date -Is)" >> "$LEDGER"; echo "LEDGER $1 $2"; }

SAMPLES=${SAMPLES:-10000}
STEPS=${STEPS:-80}
SEEDS=${SEEDS:-"0x14 0x2a3"}
WITNESSES=$(grep -oE "^  val w_[A-Za-z0-9_]+" splitspec.qnt | sed 's/  val //' | tr '\n' ' ')
DESIGN="tee_p2 tee_p1 nontee_p2 nontee_p1"

tier_typecheck() {
  for f in splitspec.qnt splitspec_test.qnt; do
    key="typecheck:$f"; done_already "$key" && continue
    if Q typecheck "$f" > "logs/typecheck_$f.log" 2>&1; then record "$key" ok; else record "$key" FAIL; fi
  done
}

tier_tests() {
  for m in $(grep -oE "^module test_[a-z0-9_]+" splitspec_test.qnt | sed 's/module //'); do
    key="test:$m"; done_already "$key" && continue
    want=$(awk -v m="$m" '$0 ~ "^module "m" " {p=1; next} /^module / {p=0} p && /^  run [A-Za-z0-9_]+Test =/ {c++} END {print c+0}' splitspec_test.qnt)
    Q test splitspec_test.qnt --main "$m" --match 'Test$' --max-samples 1 > "logs/test_$m.log" 2>&1
    got=$(grep -oE "^  [0-9]+ passing" "logs/test_$m.log" | grep -oE "[0-9]+")
    failed=$(grep -cE "^  [0-9]+ failed" "logs/test_$m.log")
    if [ "${got:-0}" = "$want" ] && [ "$failed" = 0 ]; then record "$key" "ok $got/$want"; else record "$key" "FAIL ${got:-0}/$want"; fi
  done
}

# Design instances: inv_gate, which is every invariant since revision 3 (F1 to F5 fixed; F6 by
# DECISIONS 64 in revision 4).
tier_design() {
  for inst in $DESIGN; do for init in init initArmed; do for seed in $SEEDS; do
    key="design:$inst:$init:$seed:$SAMPLES:$STEPS"; done_already "$key" && continue
    log="logs/design_${inst}_${init}_${seed}.log"
    Q run splitspec.qnt --main "$inst" --init "$init" --step stepRestart --invariant inv_gate \
      --max-samples "$SAMPLES" --max-steps "$STEPS" --seed "$seed" --n-threads 10 --witnesses $WITNESSES > "$log" 2>&1
    if grep -q "^\[ok\]" "$log"; then record "$key" ok; else record "$key" "VIOLATION $(grep -oE 'Use --seed=[0-9a-fx]+' "$log" | tail -1)"; fi
  done; done; done
}

# C11 spend invariants on the design instances. Revision 2 broke them (F1, F5); with DECISIONS 59
# and 60 a violation is a failure.
tier_c11() {
  for inst in $DESIGN; do
    key="c11:$inst:initArmed:0x14:$SAMPLES:$STEPS"; done_already "$key" && continue
    log="logs/c11_${inst}.log"
    Q run splitspec.qnt --main "$inst" --init initArmed --step stepRestart \
      --invariants inv_AU024_C11_oneSpendPerRecordState inv_AU025_C11_releasedNeverUnspent \
      --max-samples "$SAMPLES" --max-steps "$STEPS" --seed 0x14 --n-threads 10 > "$log" 2>&1
    if grep -q "^\[ok\]" "$log"; then record "$key" ok; else record "$key" "VIOLATION $(grep -oE 'Use --seed=[0-9a-fx]+' "$log" | tail -1)"; fi
  done
}

# C20 read on the tombstone reason on tee_p1 and nontee_p2 (corrupt member 1 in every epoch).
# Revision 2 broke it (F2); with DECISIONS 61 a violation is a failure.
tier_c20() {
  for inst in tee_p1 nontee_p2; do
    key="c20:$inst:initArmed:0x2a3:$SAMPLES:$STEPS"; done_already "$key" && continue
    log="logs/c20_${inst}.log"
    Q run splitspec.qnt --main "$inst" --init initArmed --step stepRestart --invariant inv_C20_stalledReleasedNothing \
      --max-samples "$SAMPLES" --max-steps "$STEPS" --seed 0x2a3 --n-threads 10 > "$log" 2>&1
    if grep -q "^\[ok\]" "$log"; then record "$key" ok; else record "$key" "VIOLATION $(grep -oE 'Use --seed=[0-9a-fx]+' "$log" | tail -1)"; fi
  done
}

# Mutants: the named invariant on random runs (the scripted kill runs are in tier_tests).
tier_mutants() {
  while read -r inst inv; do
    [ -z "$inst" ] && continue
    key="mutant:$inst:$inv"; done_already "$key" && continue
    log="logs/mutant_${inst}.log"
    Q run splitspec.qnt --main "$inst" --init initArmed --step stepRestart --invariant "$inv" \
      --max-samples 2000 --max-steps "$STEPS" --seed 0x14 --n-threads 10 > "$log" 2>&1
    if grep -q "^\[ok\]" "$log"; then record "$key" "survived-random"; else record "$key" "KILLED $(grep -oE 'Use --seed=[0-9a-fx]+' "$log" | tail -1)"; fi
  done <<'EOF'
m_ecdsa_prec_at_open inv_SL007_C13_ecdsaPrecOnlyInForce
m_committee_burn_reserved_only inv_SL010_committeeBurnAtPrecEnd
m_ecdsa_burn_by_namer inv_SL011_SL028_ecdsaBurnOnlyByReserver
m_d058_b inv_RQ068_C11_reEnded
m_d058_b_nontee inv_RQ068_C11_reEnded
m_replace_held inv_RQ054_C11_heldLeafNeverReplaced
m_restart_void_unspent inv_RQ052_RQ068_C11_restartEndNeverVoid
m_settle_per_request inv_CP005_batchedWrites
m_root_omit inv_CP013_AU020_settledByRoot
m_no_jump inv_CP007_CP008_CP009_landedChain
m_cross_epoch inv_RQ042_C13_voidNeedsHonestPost
m_ignore_revoke inv_RQ059_C7_noReleaseAfterRevoke
m_any_variant inv_RQ058_C9_oneVariantPerGeneration
m_send_before_record inv_RQ069_C11_sentNeverVoid
m_locked_void_unlocks inv_AU025_C11_releasedNeverUnspent
m_completing_reason inv_RQ045_RQ072_C13_C20_reasonHasHonestPost
m_exp_c_unchecked inv_EN023_expCBelowExp
m_lapse_once inv_SL005_SL010_lapsedPrecBurned
m_stalled_after_release inv_RQ073_C20_noStalledAfterRelease
m_stalled_after_release_nontee inv_RQ073_C20_noStalledAfterRelease
m_late_expiry inv_RQ046_urgentExpiry
m_restart_clears_release inv_RQ076_C11_releaseMonotone
m_auth_refused_before_force inv_RQ025_SL016_admissionChecksInForce
m_taken_before_force inv_RQ025_SL016_admissionChecksInForce
m_pending_min_unchecked inv_CP040_pendingMinForward
m_ack_without_pop inv_SH031_SH036_C1_ackedOnlyRightEc
m_ack_cert_short inv_SH031_SH036_C1_ackedOnlyRightEc
m_pay_before_ack inv_SH035_payOnlyAcked
m_pending_unwindowed inv_CP014_CP040_honestFloorKept
EOF
}

# Replay traces: 50 protocol traces per design instance (step only, no refusals) and 20
# refusal traces, flattened for quint_replay.py.
tier_traces() {
  for inst in $DESIGN; do for init in init initArmed; do
    key="traces:$inst:$init"; done_already "$key" && [ -d "traces/${inst}_${init}" ] && continue
    raw="traces/raw/${inst}_${init}"; flat="traces/${inst}_${init}"
    rm -rf "$raw" "$flat"; mkdir -p "$raw"
    Q run splitspec.qnt --main "$inst" --init "$init" --step stepRestart --invariant inv_gate \
      --max-samples 300 --n-traces 50 --max-steps 60 --seed 0x1f0 --n-threads 4 \
      --out-itf "$raw/t_{seq}.itf.json" > "logs/traces_${inst}_${init}.log" 2>&1
    python3 -I tools/flatten_itf.py "$raw" "$flat" >> "logs/traces_${inst}_${init}.log" 2>&1
    record "$key" "$(ls "$flat" | wc -l) traces"
  done
  key="traces:$inst:refusals"; done_already "$key" && [ -d "traces/${inst}_refusals" ] && continue
  raw="traces/raw/${inst}_refusals"; flat="traces/${inst}_refusals"
  rm -rf "$raw" "$flat"; mkdir -p "$raw"
  Q run splitspec.qnt --main "$inst" --init initArmed --step stepAll --invariant inv_gate \
    --max-samples 100 --n-traces 20 --max-steps 60 --seed 0x1f1 --n-threads 4 \
    --out-itf "$raw/t_{seq}.itf.json" > "logs/traces_${inst}_refusals.log" 2>&1
  python3 -I tools/flatten_itf.py "$raw" "$flat" >> "logs/traces_${inst}_refusals.log" 2>&1
  record "$key" "$(ls "$flat" | wc -l) traces"
  done
  rm -rf traces/raw
}

# Scripted schedules as ITF traces: every test of the design modules, including the finding
# schedules f1/f2/f5, flattened for quint_replay.py (traces/tests_<module>/).
tier_testtraces() {
  for m in test_tee_p2 test_nontee_p2 test_tee_p1; do
    key="testtraces:$m"; done_already "$key" && [ -d "traces/tests_$m" ] && continue
    raw="traces/raw/tests_$m"; flat="traces/tests_$m"
    rm -rf "$raw" "$flat"; mkdir -p "$raw"
    Q test splitspec_test.qnt --main "$m" --match 'Test$' --max-samples 1 \
      --out-itf "$raw/{test}_{seq}.itf.json" > "logs/testtraces_$m.log" 2>&1
    python3 -I tools/flatten_itf.py "$raw" "$flat" >> "logs/testtraces_$m.log" 2>&1
    record "$key" "$(ls "$flat" | wc -l) traces"
  done
  rm -rf traces/raw
}

# Replay of the revision 3 random F6 traces (replay_f6.qnt, DECISIONS 64).
tier_replay() {
  for m in replay_f6_base replay_f6_stalled_after_release; do
    key="replay:$m"; done_already "$key" && continue
    want=$(awk -v m="$m" '$0 ~ "^module "m" " {p=1; next} /^module / {p=0} p && /^  run [A-Za-z0-9_]+Test =/ {c++} END {print c+0}' replay_f6.qnt)
    Q test replay_f6.qnt --main "$m" --match 'Test$' --max-samples 1 > "logs/test_$m.log" 2>&1
    got=$(grep -oE "^  [0-9]+ passing" "logs/test_$m.log" | grep -oE "[0-9]+")
    failed=$(grep -cE "^  [0-9]+ failed" "logs/test_$m.log")
    if [ "${got:-0}" = "$want" ] && [ "$failed" = 0 ]; then record "$key" "ok $got/$want"; else record "$key" "FAIL ${got:-0}/$want"; fi
  done
}

# Mutants that need more than 2000 random samples: 10000 samples, both seeds.
tier_mutants10k() {
  while read -r inst inv; do
    [ -z "$inst" ] && continue
    for seed in $SEEDS; do
      key="mutant10k:$inst:$inv:$seed"; done_already "$key" && continue
      log="logs/mutant10k_${inst}_${seed}.log"
      Q run splitspec.qnt --main "$inst" --init initArmed --step stepRestart --invariant "$inv" \
        --max-samples 10000 --max-steps "$STEPS" --seed "$seed" --n-threads 10 > "$log" 2>&1
      if grep -q "^\[ok\]" "$log"; then record "$key" "survived-random"; else record "$key" "KILLED $(grep -oE 'Use --seed=[0-9a-fx]+' "$log" | tail -1)"; fi
    done
  done <<'EOF2'
m_stalled_after_release_nontee inv_RQ073_C20_noStalledAfterRelease
m_stalled_after_release inv_RQ073_C20_noStalledAfterRelease
m_pending_unwindowed inv_CP014_CP040_honestFloorKept
EOF2
}

tiers=${*:-"typecheck tests replay design c11 c20 mutants mutants10k traces testtraces"}
for t in $tiers; do echo "== tier $t $(date -Is)"; "tier_$t"; done
echo "== gate done $(date -Is)"
grep -cE "FAIL|VIOLATION" "$LEDGER" | sed 's/^/ledger lines with FAIL or VIOLATION: /'
