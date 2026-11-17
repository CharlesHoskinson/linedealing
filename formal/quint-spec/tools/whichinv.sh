#!/usr/bin/env bash
# whichinv.sh MAIN INIT STEP SEED STEPS: replay one reported seed (one sample) once per
# invariant and print the invariants it violates. Quint names no invariant in its report.
set -u
cd "$(dirname "$0")/.."
main=$1 init=$2 step=$3 seed=$4 k=$5
for i in $(grep -oE "^  val inv_[A-Za-z0-9_]+" splitspec.qnt | sed 's/  val //'); do
  case $i in inv|inv_gate|inv_C11_spend) continue;; esac
  if heavy-run --mem 8G -- quint run splitspec.qnt --main "$main" --init "$init" --step "$step" --invariant "$i" \
       --max-samples 1 --max-steps "$k" --seed "$seed" --n-threads 1 2>&1 | grep -q "Invariant violated"; then
    echo "VIOLATED $i"
  fi
done
