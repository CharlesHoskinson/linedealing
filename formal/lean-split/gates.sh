#!/bin/sh
# Stage gates of the formal pipeline for split-line dealing, the Lean oracle stage.
# One Lake package per capability, all depending on ../codec. Each gate exits 0
# when it holds. The gates follow the formal plugin's token-bucket example.
#
#   gates.sh oracle CAP   build, audit, word search, codec and refusal cases,
#                         Spec mutants, ambiguity ledger
#   gates.sh trace CAP    the README requirement table equals the spec sentences
#   gates.sh all          oracle and trace for every capability
#
# CAP is one of: envelope request slots authorization checkpoint shard-holders handoff
# Run under heavy-run: the mutant check builds a copy of the package per mutant.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
export LEAN_ABORT_ON_PANIC=1
caps="envelope request slots authorization checkpoint shard-holders handoff"

oracle() {
  pkg="$here/$1"
  (cd "$here/codec" && lake build --wfail >/dev/null)
  # --wfail fails on a `sorry` in any module (every module of the spec library is a
  # default target); Tests pins answers in the kernel and the compiled code; Audit
  # pins `#print axioms` of each theorem and `#audit_ns` at [].
  (cd "$pkg" && lake build --wfail)
  python3 -I "$here/scripts/oracle_checks.py" words "$pkg"
  python3 -I "$here/scripts/oracle_checks.py" cases "$pkg"
  python3 -I "$here/scripts/oracle_checks.py" mutants "$pkg"
  python3 -I "$here/scripts/oracle_checks.py" ledger "$pkg"
  echo "oracle: $1: build, pins, audit, words, codec, refusal codes, Spec mutants and ledger hold"
}

trace() {
  python3 -I "$here/scripts/req_table.py" --check "$here/$1"
}

case ${1:?usage: gates.sh oracle|trace CAP, or gates.sh all} in
  oracle) oracle "${2:?CAP}" ;;
  trace) trace "${2:?CAP}" ;;
  all)
    total=0
    for c in $caps; do oracle "$c"; trace "$c"; done
    python3 -I "$here/scripts/count_ids.py" "$here" ;;
  *) echo "usage: gates.sh oracle|trace CAP, or gates.sh all" >&2; exit 2 ;;
esac
