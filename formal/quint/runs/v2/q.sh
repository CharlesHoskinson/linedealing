#!/usr/bin/env bash
# usage: q.sh NAME MEM quint-args...   (run from formal/quint)
# Logs the exact command, then quint output, to runs/v2/NAME.log
name=$1; mem=$2; shift 2
log=runs/v2/$name.log
{ echo "# command: quint $*"; echo "# started: $(date -Is)"; } > "$log"
start=$(date +%s)
heavy-run --mem "$mem" --name "quint-$name" -- quint "$@" >> "$log" 2>&1
rc=$?
echo "# exit: $rc  wall: $(( $(date +%s) - start ))s" >> "$log"
echo "$name exit=$rc $(grep -E '^\[(ok|violation)\]|witnessed|error:' "$log" | head -3 | tr '\n' ' ')"
