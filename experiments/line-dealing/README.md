# Line dealing: deterministic checks

Pure-Python checks (no dependencies) for `design/SCHEME.md`.

    python3 -I checks.py   # 37 assertions on secp256k1: equations, attacks, fixes
    python3 -I costs.py    # cost figures of SCHEME.md section 7

Each test maps to a check D1..D15 in `design/FINDINGS-LEDGER.md`. Not yet covered: the board state machine, Ed25519 arithmetic, HASH160/Keccak address checks, real sighash encodings.
