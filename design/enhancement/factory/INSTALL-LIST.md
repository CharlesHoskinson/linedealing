# Install list: software-factory formal pipeline

Goal: run the IO software-factory formal pipeline (OpenSpec + EARS -> Lean oracle -> Quint check -> k-rust reference suite -> drwatt gates) for split-line dealing. Factory: ~/Projects/software-factory, plugins/formal (DEPENDENCIES.md, scripts/check-deps.sh).

Already present (check-deps.sh): elan, Lean 4.35.0, node 26, quint 0.32, rust 1.99, cc, cmake, python 3.14, git, dw (drwatt), java 21, apalache 0.56, just. k-rust checkout at the pinned revision 8aaaac1 exists at ~/formal-kits/k-rust with krs, krust, krust-fuzz built in target/release.

Proposed:
1. Build `kink-flow` from the local k-rust checkout: `cargo build --release --locked -p kink-flow --no-default-features` (listed in DEPENDENCIES.md as optional; used for K-text corpora flows). No system package.
2. Set `KRUST_DIR=$HOME/formal-kits/k-rust` persistently (~/.config/environment.d/krust.conf and ~/.bashrc), because check-deps.sh and the example gates.sh read it.
3. Install the factory's Claude Code plugins from the local marketplace at user scope: `claude plugin marketplace add ~/Projects/software-factory`, then `claude plugin install formal@io-software-factory`, `quint-llm-kit@io-software-factory`, `lean4@io-software-factory`. User-level lean4 and quint skills already exist under ~/.claude/skills; the plugin copies are the factory's pinned versions (UPSTREAM.md) and the formal plugin's skills (formal, formal-oracle, formal-quint-check, formal-reference-suite, formal-refine) exist nowhere else.

Question for the voter: for each item, is it needed for the stated goal? Answer APPROVE or REJECT per item with one line of reason.

## Round 2 (owner: "including openspec skill")

4. Install the OpenSpec CLI for the active Node (26.13.1): `npm install -g @fission-ai/openspec@latest`. It was installed earlier under Node 26.13.0 only, so the mise shim fails now. The factory pipeline starts from "OpenSpec specs and EARS requirements"; the CLI validates and manages the specs (`openspec validate`, change proposals).
5. Run `openspec init --tools claude,codex` in ~/Projects/mpcexperiments. It writes the project's `openspec/` folder and the OpenSpec skills and commands under `.claude/skills/openspec-*`, `.claude/commands/opsx/` and the Codex equivalent, scoped to that repo only.

Question for the voter: APPROVE or REJECT items 4 and 5, one line each.
