#!/usr/bin/env bash
cd "$(dirname "$0")/.."
run() { name=$1; shift; echo "=== $name: quint $*"; timeout 3000 quint "$@" > runs/$name.log 2>&1; echo "exit $?"; grep -E 'No violation|violation|Found an issue|error|\[ok\]|\[violation\]|samples' runs/$name.log | tail -3; }
for inv in NoNonceReuse AtMostOneExecution LockBeforeShare NoTransientTombstone FreezeSafety; do
  run $inv run --main=linedealing --max-steps=30 --max-samples=10000 --invariant=$inv linedealing.qnt
done
run witness run --main=linedealing --max-steps=30 --max-samples=10000 --invariant=NoSpendExecuted linedealing.qnt
run n7 run --main=linedealing_n7_f2 --max-steps=30 --max-samples=3000 --invariant=AllSafetyInvariants linedealing.qnt
run broken_prevote run --main=linedealing_broken_prevote --max-steps=30 --max-samples=10000 --invariant=NoNonceReuse linedealing.qnt
run broken_rule4 run --main=linedealing_broken_rule4 --max-steps=30 --max-samples=10000 --invariant=NoNonceReuse linedealing.qnt
