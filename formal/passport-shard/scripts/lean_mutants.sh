#!/bin/sh
# Lean oracle mutants of the Passport shard (LOOP item 39, lane passport-od1).
#
# Each mutant edits PassportShard/Spec.lean in place (the lakefile needs the
# relative path ../../lean-split/codec), runs `lake build --wfail`, and must
# FAIL the build. The source is restored and the oracle is rebuilt afterwards,
# also when the script stops early.
#
#   lean_mutants.sh        run every mutant; rc 0 when every mutant is killed
#
# Log: lean/mutants.log. Run under heavy-run.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
lean="$here/lean"
spec="$lean/PassportShard/Spec.lean"
log="$lean/mutants.log"
bak=$(mktemp)
cp "$spec" "$bak"
restore() { cp "$bak" "$spec"; rm -f "$bak"; }
trap restore EXIT INT TERM

# name | text to remove from Spec.lean (must occur exactly once)
MUTANTS="lmut1_noPendingSuccessorGuard| ++ chk (notPendingSucc s d) .pendingSuccessor"

fail=0
: > "$log"
old_ifs=$IFS
IFS='
'
for row in $MUTANTS; do
  name=${row%%|*}; cut=${row#*|}
  cp "$bak" "$spec"
  n=$(grep -cF -- "$cut" "$spec" || true)
  if [ "$n" != 1 ]; then echo "$name: mutation text found $n times" | tee -a "$log"; fail=1; continue; fi
  python3 -I -c 'import sys,pathlib; p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text().replace(sys.argv[2], "", 1))' "$spec" "$cut"
  if (cd "$lean" && LEAN_ABORT_ON_PANIC=1 lake build --wfail) > "$lean/mutant-$name.log" 2>&1
  then r=SURVIVED; fail=1
  else r="KILLED ($(grep -E '^error: [^ ]+\.lean' "$lean/mutant-$name.log" | sed 's/^error: //; s/:.*//' | sort -u | tr '\n' ' '))"
  fi
  echo "$name $r" | tee -a "$log"
done
IFS=$old_ifs

restore
trap - EXIT INT TERM
if (cd "$lean" && LEAN_ABORT_ON_PANIC=1 lake build --wfail) > "$lean/mutant-restore.log" 2>&1
then echo "restored build: ok" | tee -a "$log"
else echo "restored build: FAILED" | tee -a "$log"; fail=1; fi
exit $fail
