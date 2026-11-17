#!/bin/sh
# krs-in.sh CAP KRS-ARGS...: run `krs KRS-ARGS --package <CAP's package> --definition main`
# in formal/krs-split/CAP under heavy-run, writing the facade patch first. The output
# also goes to ~/.cache/loop-verify/krs-split-CAP.log.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cap=$1; shift
KRUST_DIR=${KRUST_DIR:-$HOME/formal-kits/k-rust}
pkg=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$here/$cap/Cargo.toml" | head -1)
mkdir -p "$here/$cap/.cargo" "$HOME/.cache/loop-verify"
cat > "$here/$cap/.cargo/config.toml" <<EOF
[patch."https://github.com/midnightntwrk/k-rust"]
krs = { path = "$KRUST_DIR/krs/crates/krs" }
EOF
cd "$here/$cap"
export LEAN_ABORT_ON_PANIC=1
rc=0
heavy-run --mem 16G --name "krs-$cap" -- "$KRUST_DIR/target/release/krs" "$@" \
  --package "$pkg" --definition main > "$HOME/.cache/loop-verify/krs-split-$cap.log" 2>&1 || rc=$?
cat "$HOME/.cache/loop-verify/krs-split-$cap.log"
echo "krs-in: exit $rc"
exit $rc
