#!/usr/bin/env bash
# Resumable runner for the split-line model checks.
# Each line of jobs.txt is: NAME|EXPECT|quint arguments, or SH followed by a shell command.
# EXPECT: ok, violation, testfail (a quint test run that must fail) or exit0.
# A job whose log already ends with an "exit" line is skipped, so a rerun after a
# crash or reboot resumes at the first unfinished job. Delete a log to rerun it.
# Each job runs inside heavy.slice through heavy-run (8G cap). Start the whole
# runner as a systemd user unit:
#   systemd-run --user --unit=quint-split --collect -p WorkingDirectory=$PWD formal/quint/runs/split/run_all.sh
# The model hash in MODEL.sha256 is checked; a changed model clears old logs.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../.."
logs="$here/logs"; mkdir -p "$logs"
hash=$(cat splitline.qnt splitline_instances.qnt splitline_test.qnt splitline_pools.qnt splitline_pools_test.qnt splitline_birth.qnt \
  ../../design/enhancement/quint/batched_checkpoint.qnt ../../design/enhancement/vectors/quint_counterexamples.py \
  "$here/jobs.txt" "$here/export_traces.sh" "$0" | sha256sum | cut -d' ' -f1)
if [ "$(cat "$here/MODEL.sha256" 2>/dev/null)" != "$hash" ]; then
  rm -f "$logs"/*.log; echo "$hash" > "$here/MODEL.sha256"
fi
par=${PAR:-3}
runjob() {
  local name=$1 expect=$2 args=$3 log="$logs/$1.log"
  grep -q '^exit ' "$log" 2>/dev/null && return 0
  { echo "job $name expect $expect"; echo "quint $args"; date -Is; } > "$log"
  # shellcheck disable=SC2086
  # a quoted --match pattern stays one argument
  if [ "${args#SH }" != "$args" ]; then
    timeout 7200 heavy-run --mem 8G --name "qs-$name" -- bash -c "${args#SH }" >> "$log" 2>&1
  else
    eval "set -- $args"
    timeout 7200 heavy-run --mem 8G --name "qs-$name" -- quint "$@" >> "$log" 2>&1
  fi
  echo "exit $?" >> "$log"
}
export -f runjob; export logs
grep -v '^#' "$here/jobs.txt" | grep -v '^$' | while IFS='|' read -r name expect args; do
  printf '%s\0%s\0%s\0' "$name" "$expect" "$args"
done | xargs -0 -n3 -P "$par" bash -c 'runjob "$0" "$1" "$2"'
# summary
{
  echo "model $hash  $(date -Is)"
  printf '%-34s %-9s %-9s %s\n' JOB EXPECT GOT DETAIL
  grep -v '^#' "$here/jobs.txt" | grep -v '^$' | while IFS='|' read -r name expect args; do
    log="$logs/$name.log"
    code=$(grep '^exit ' "$log" | tail -1 | cut -d' ' -f2)
    if [ "$expect" = exit0 ]; then got=$([ "$code" = 0 ] && echo exit0 || echo "exit$code")
    elif [ "$expect" = testfail ]; then got=$(grep -q ' failed' "$log" && grep -q 'Tests failed' "$log" && echo testfail || echo ok)
    elif grep -q '\[violation\]' "$log"; then got=violation
    elif grep -q '\[ok\]' "$log"; then got=ok
    elif grep -q ' passing' "$log" && ! grep -q ' failed' "$log"; then got=ok
    else got=error; fi
    mark=PASS; [ "$got" = "$expect" ] || mark=FAIL
    detail=$(grep -E '\[ok\]|\[violation\]| passing| failed' "$log" | head -1 | cut -c1-70)
    printf '%-34s %-9s %-9s %s %s\n' "$name" "$expect" "$got" "$mark" "$detail"
  done
} > "$here/SUMMARY.txt"
cat "$here/SUMMARY.txt"
