#!/bin/sh
# Reference-suite gates (k-rust) for the split-line Lean oracles in ../lean-split.
# One KRS package, one flow and one lock per capability. Each gate exits 0 when it
# holds; exit 3 (no verdict) fails every gate.
#
#   gates.sh emit CAP        definition.k is current
#   gates.sh coverage CAP    lock current and 0 open obligations (MC/DC on)
#   gates.sh mutations CAP   lock current; every mutation has `expect`, every survivor is
#                            argued, no rule is untargeted, every EARS ID is named or a gap
#   gates.sh oracle-equal CAP  every compare row against the Lean oracle is `equal`
#   gates.sh golden CAP      golden/vectors.json is current (exportable cases only)
#   gates.sh all CAP         the five gates in order
#
# CAP is one of: envelope request slots authorization checkpoint shard-holders
# Environment: KRUST_DIR, a k-rust checkout at the UPSTREAM.md revision with
# target/release/krs built. Run under heavy-run or heavy-slot.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
KRUST_DIR=${KRUST_DIR:-$HOME/formal-kits/k-rust}
krs="$KRUST_DIR/target/release/krs"
export LEAN_ABORT_ON_PANIC=1

pkg_of() {
  sed -n 's/^name = "\(.*\)"$/\1/p' "$here/$1/Cargo.toml" | head -1
}

# The KRS crate depends on the krs facade by git revision; point it at the checkout
# the krs binary was built from (krs refuses a facade from another build).
krs_patch() {
  mkdir -p "$here/$1/.cargo"
  cat > "$here/$1/.cargo/config.toml" <<EOF
[patch."https://github.com/midnightntwrk/k-rust"]
krs = { path = "$KRUST_DIR/krs/crates/krs" }
EOF
}

build_oracle() {
  (cd "$here/../lean-split/codec" && lake build --wfail >/dev/null)
  (cd "$here/../lean-split/$1" && lake build --wfail oracle >/dev/null)
}

kink() {
  cap=$1; shift
  krs_patch "$cap"
  (cd "$here/$cap" && "$krs" kink "$@" --package "$(pkg_of "$cap")" --definition main)
}

coverage() {
  kink "$1" emit --check
  kink "$1" coverage --lock kink/kink.lock --locked --output json > "$here/$1/.kink-cov.json"
  python3 -I - "$here/$1/.kink-cov.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["summary"]
print(f"coverage: {s}")
sys.exit("coverage: open obligations remain" if s["open"] != 0 else 0)
PY
}

mutations() {
  kink "$1" run --full --lock kink/kink.lock --locked --output json > "$here/$1/.kink-run.json"
  python3 -I "$here/scripts/check_mutations.py" "$here/$1"
}

oracle_equal() {
  build_oracle "$1"
  kink "$1" compare --only lean-oracle --lock kink/kink.lock --locked --output text
}

# Golden vectors: the cases under kink/cases/ (never kink/held/), each with the oracle's
# end through the adapter, so inputs and cells are both in the KRS typed encoding.
# The header pins the oracle's Spec.lean, the schema and the adapter by sha256.
# GOLDEN_WRITE=1 writes the file instead of checking it.
golden() {
  build_oracle "$1"
  check=--check
  [ "${GOLDEN_WRITE:-0}" = 1 ] && check=
  (cd "$here/$1" && spec=$(ls ../../lean-split/"$1"/Split*/Spec.lean) && \
    python3 -I ../scripts/export_golden.py --cases 'kink/cases/*/case.toml' \
    --base kink --oracle ../scripts/oracle_adapter.py schema.json ../../lean-split/"$1"/.lake/build/bin/oracle \
    --source "$spec" --source schema.json --source ../scripts/oracle_adapter.py \
    --toolchain ../../lean-split/"$1"/lean-toolchain \
    --out golden/vectors.json $check)
}

case ${1:?usage: gates.sh GATE CAP} in
  emit) kink "${2:?CAP}" emit --check ;;
  coverage) coverage "${2:?CAP}" ;;
  mutations) mutations "${2:?CAP}" ;;
  oracle-equal) oracle_equal "${2:?CAP}" ;;
  golden) golden "${2:?CAP}" ;;
  all) c=${2:?CAP}; coverage "$c"; mutations "$c"; oracle_equal "$c"; golden "$c" ;;
  *) echo "usage: gates.sh emit|coverage|mutations|oracle-equal|golden|all CAP" >&2; exit 2 ;;
esac
