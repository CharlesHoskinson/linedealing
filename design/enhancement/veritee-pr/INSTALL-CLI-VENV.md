# Install request: test venv for the Veritee CLI

Purpose: let the lead rerun the Veritee CLI pytest suite (258 tests) on branch committee-signing-mode in /home/hoskinson/Projects/veritee/wt-merge, to verify the integration agent's claim before the item counts as done. The system Python lacks the CLI's runtime dependencies (typer, requests, cryptography, and others); the venv the agent used no longer exists.

Proposal: one throwaway virtualenv at /tmp/claude-1000/-home-hoskinson/bee643b4-08f5-4340-b29d-1a5130e7b1e5/scratchpad/veritee-cli-venv, created with `uv venv` (uv is already installed), filled from PyPI with exactly the versions pinned in cli/poetry.lock for the main and dev groups (rich, pyyaml, pydantic 2.6.3, pyopenssl, inquirer, typer[all], importlib-metadata, requests, sseclient, click, cryptography, pytest and their locked transitive dependencies), exported with the lock's hashes. No system packages, nothing global, no changes to the repo. Deleted after the run.

Alternative: skip the lead rerun and record the agent's pytest result (258 passed, 1 skipped) as unverified.

Answer: NEEDED or NOT NEEDED, with one paragraph of reasons.
