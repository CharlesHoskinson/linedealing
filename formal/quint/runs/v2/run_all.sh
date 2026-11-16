#!/usr/bin/env bash
# Runs every simulation in runs/v2/jobs.txt on the current linedealing.qnt, 5 in parallel.
# Job line: NAME MAIN INIT STEP MAX_STEPS MAX_SAMPLES SEED TARGET
#   TARGET = SAFETY -> the five safety invariants (--invariants) plus depth witnesses
#   TARGET = other  -> a single invariant (witness negation or mutant check)
cd "$(dirname "$0")/../.."
W="ArmedReached LockCertReached OpenPartialReached HonestPartialReached SpendExecuted Gen2PartialReached Gen2SpendReached ReshareDoneReached HandoverWithOldPartialReached Epoch2PartialReached RollbackAfterPrevoteReached RollbackAfterPartialReached FinalReached VoidReached ExpiredReached"
INV="NoNonceReuse AtMostOneExecution LockBeforeShare NoTransientTombstone FreezeSafety"
one() {
  read -r name main init step steps samples seed target <<< "$1"
  if [ "$target" = SAFETY ]; then
    runs/v2/q.sh "$name" 8G run --main="$main" --init="$init" --step="$step" --max-steps="$steps" \
      --max-samples="$samples" --seed="$seed" --invariants $INV --witnesses $W \
      --out-itf="runs/v2/$name.itf.json" linedealing.qnt
  elif [ "$target" = SAFETYNOWIT ]; then   # positive control for the --invariants list form
    runs/v2/q.sh "$name" 8G run --main="$main" --init="$init" --step="$step" --max-steps="$steps" \
      --max-samples="$samples" --seed="$seed" --invariants $INV \
      --out-itf="runs/v2/$name.itf.json" linedealing.qnt
  elif [ "$target" = SAFETYRESHARE ]; then
    runs/v2/q.sh "$name" 8G run --main="$main" --init="$init" --step="$step" --max-steps="$steps" \
      --max-samples="$samples" --seed="$seed" --invariants $INV \
      --witnesses ReshareDoneReached HandoverWithOldPartialReached Epoch2PartialReached LockCertReached OpenPartialReached \
      --out-itf="runs/v2/$name.itf.json" linedealing.qnt
  else
    runs/v2/q.sh "$name" 8G run --main="$main" --init="$init" --step="$step" --max-steps="$steps" \
      --max-samples="$samples" --seed="$seed" --invariant="$target" \
      --out-itf="runs/v2/$name.itf.json" linedealing.qnt
  fi
}
export -f one; export W INV
sha256sum linedealing.qnt > runs/v2/MODEL.sha256
grep -v '^\s*$' runs/v2/jobs.txt | xargs -P 5 -I{} bash -c 'one "$@"' _ {} | tee runs/v2/SUMMARY.txt
