#!/usr/bin/env bash
# Runs the batched_checkpoint model: tests, the design, the witnesses and the mutants.
# Usage: heavy-run -- ./run-batched.sh   (logs go to runs/batched-*.log)
set -u
cd "$(dirname "$0")"
M=batched_checkpoint.qnt
S=${SAMPLES:-50000}
quint typecheck $M > runs/batched-typecheck.log 2>&1; echo "typecheck exit $?"
quint test --main=tests $M > runs/batched-test.log 2>&1; echo "test exit $?"
quint run --main=design --invariant=allInvariants --max-samples=$S --max-steps=40 --seed=0x1 $M > runs/batched-design.log 2>&1; echo "design exit $?"
for w in W_restartWithPending W_bindAfterLoss W_reissueEarly W_spendAfterFinal W_dupDropped; do
  quint run --main=witnesses --invariant=$w --max-samples=$S --max-steps=40 --seed=0x1 $M > runs/batched-witness-$w.log 2>&1; echo "witness $w exit $?"
done
quint run --main=boardLoss --invariant=C11_bfNoDupInForce --max-samples=$S --max-steps=40 --seed=0x1 --out-itf=runs/batched-boardLoss.itf.json $M > runs/batched-boardLoss.log 2>&1; echo "boardLoss C11_bfNoDupInForce exit $?"
quint run --main=boardLoss --invariant=C11_bfOneHostSpend --max-samples=$S --max-steps=40 --seed=0x1 $M > runs/batched-boardLoss-hostspend.log 2>&1; echo "boardLoss C11_bfOneHostSpend exit $?"
for m in mut1_windowOnly mut2_highestPending mut3_noCarryCheck mut4_doubleSign mut5_spentNf mut6_partialRoot mut7_replayVoid mut8_boardDupNf mut9_noLandedCheck mut10_noSignerCheck mut11_proofBelowPendingMin; do
  quint run --main=$m --invariant=allInvariants --max-samples=$S --max-steps=40 --seed=0x1 --out-itf=runs/batched-$m.itf.json $M > runs/batched-$m.log 2>&1; echo "mutant $m exit $? $(grep -o 'violation\] Found an issue' runs/batched-$m.log | head -1)"
done
# Each mutant against the named invariant it targets.
while read -r m inv; do
  r=$(quint run --main=$m --invariant=$inv --max-samples=$S --max-steps=40 --seed=0x1 $M 2>&1 | grep -o 'Found an issue\|No violation' | head -1)
  echo "target $m $inv: $r"
done <<'LIST'
mut1_windowOnly C12_C16_oneTicketPerSlot
mut2_highestPending C12_C16_oneTicketPerSlot
mut3_noCarryCheck C11_oneOutcomePerAuth
mut4_doubleSign C11_oneOutcomePerAuth
mut5_spentNf C11_oneAuthorizePerState
mut6_partialRoot C11_settledByCheckpoint
mut7_replayVoid C11_noLostSuccessor
mut8_boardDupNf C11_bfNoDupInForce
mut9_noLandedCheck C11_bfNoDupInForce
mut10_noSignerCheck C11_bfLandedDisjoint
mut11_proofBelowPendingMin C12_C16_oneTicketPerSlot
LIST
