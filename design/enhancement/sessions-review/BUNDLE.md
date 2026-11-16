# Sessions review bundle

Source: commit 8c8981b of `~/Projects/veritee/wt-sessions` (branch `committee-sessions`) and `design/enhancement/DESIGN.md` of this repository at 613b330. Each reviewer read the copy below, outside both repositories, with no git history.

| File in the bundle | Source | SHA-256 |
|---|---|---|
| change/proposal.md | openspec/changes/add-seald-sessions/proposal.md | cbcac4f465b8620a… |
| change/design.md | openspec/changes/add-seald-sessions/design.md | 0f097d0840bf88f9… |
| change/specs/seald-sessions/spec.md | openspec/changes/add-seald-sessions/specs/seald-sessions/spec.md | d1f7e268b4c58803… |
| docs/committee-signing-mode.md | docs/committee-signing-mode.md | 53777d8e5ddbfad3… |
| docs/committee-mode.md | docs/committee-mode.md | b14c012182899d51… |
| seald/Cargo.toml, seald/src/*.rs | server/seald | listed in `MANIFEST.sha256` |
| split-line/DESIGN.md | design/enhancement/DESIGN.md | 9a5b1c09bb6e2f56… |

`MANIFEST.sha256` in this folder holds the full hash of every file sent.

## Blinding

The files went to the reviewers byte for byte. They name no author, model or lane. `tasks.md` of the change was left out, because it names the review and QA lanes of later stages. The prompt (`PROMPT.md`, with the bundle path and output path filled in) names no model, vendor, author or lane and gives no history of the design. The filled-in paths hold the host account name, as every local path does. It marks the four "Decisions" of design.md as fixed choices that a reviewer may challenge.

| Prompt sent | SHA-256 |
|---|---|
| Reviewer A (returns the report as its final message) | c092fa9421b2506b61f1ec617b490d0a6bb6df000a215554ae7cea4a4b677713 |
| Reviewer B (writes the report to a file) | 99c2d5fb04d3eeb3cd510a31a1479dd0e6b35b624d97e047006fd289048b3580 |

## Reviewers

| Reviewer | Run | Report |
|---|---|---|
| A | GPT-6 Astra through `codex exec -m gpt-6-astra -c model_reasoning_effort=xhigh -s read-only --ephemeral --skip-git-repo-check` | `reviewer-a.md` |
| B | Gemini 4 Carbon through `argon-run --model gemini-4-carbon-high` (the herdr agy pane was busy with another lane) | `reviewer-b.md` |

## Runs

Both lanes ran as systemd user units with logs on disk. The first runs stopped with no report after about 15 minutes. Reviewer A ran again from the start. Reviewer B continued its first conversation (the bundle reads were in it) and wrote its report. The logs show model `gpt-6-astra` and `gemini-4-carbon-high`. Reviewer A ran shell reads only inside the bundle, plus the skill files that its own agent setup loads from the host. Reviewer B read and listed only bundle files and wrote only its report. Its first run tried to read one host skill file and was denied. Neither reviewer read a repository, the other report or a log. After both runs, every bundle file matched `MANIFEST.sha256`.

The copies of the reports in this folder replace the absolute bundle paths with `bundle/`. The text is otherwise unchanged.
