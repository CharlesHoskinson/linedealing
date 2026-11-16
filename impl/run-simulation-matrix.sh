#!/usr/bin/env bash
set -euo pipefail
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
if [[ "${LD_SKIP_BUILD:-0}" != 1 ]]; then
  heavy-run --mem 16G --name ld-rust -- cargo build --offline --release --bin committee-sim
fi
for suite in ecdsa bip340 ed25519; do
  for mode in open sealed; do
    for threshold in 3 7; do
      for latency in 0 25 50; do
        for batch in 1 16; do
          "$CARGO_TARGET_DIR/release/committee-sim" --requests 16 --suite "$suite" --mode "$mode" --threshold "$threshold" --latency-ms "$latency" --batch-size "$batch" --board-ms 1 --seed 42
        done
      done
    done
  done
done
