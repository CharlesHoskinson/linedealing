# Blinded review bundle: paper-split

## Bundle

- Built from branch `paper-split` at commit 8504b1d.
- Hash of the manifest `bundle/SHA256`: `35cd9a5c01aa2cd2b9608cfbbeea39d84944d4db7bd4add701326eb901450751`.
- `main.pdf`: `dafda1bf320f20b167703201f97411c68f3b829b3231746831365a9391ee5d2d`.
- `PROMPT.md`: `8af455880ba7c006c60135f28633fe76e479a55e331640f7a61effdb36fd694c`.

Contents:

| Path | What it is |
|---|---|
| `main.pdf` | The paper, built with an empty author field and an empty PDF Author entry. |
| `src/` | The LaTeX sources. The line-dealing companion entry names its author "Anonymous". |
| `lean/*.lean` | KeySplit, Access, Slots and Profiles with comments stripped. |
| `lean/axioms-output.txt` | `#print axioms` output for the 58 declarations of a clean build. |
| `spec/DESIGN.md` | The design specification. The local path and the decision-log reference are removed. |
| `spec/sizes.py` | The byte-budget script. |
| `PROMPT.md` | The reviewer prompt, with `BUNDLE_DIR` as a placeholder. |

Blinding check: a case-insensitive grep of the bundle for the author name, the e-mail address, `/home/`, meeting names, loop and lane terms and model names returns no hits.
No internal meeting content is in the bundle.

## Reviewer runs

| Lane | Model | Run | Raw output |
|---|---|---|---|
| Astra | GPT-6 Astra, reasoning effort xhigh | `codex exec`, read-only sandbox, ephemeral, in systemd user unit `paper-split-astra`, timeout 5400 s, on a copy of the bundle at `~/.cache/paper-split-review/astra/bundle` | `astra-raw.md`, log `~/.cache/paper-split-review/astra.log` |
| Carbon | Gemini 4 Carbon (high) | interactive agy in herdr pane `carbon-paper` in the local default session, on a copy of the bundle at `~/.cache/paper-split-review/carbon/bundle`; report written to that copy as `REPORT.md`; pane closed after the run | `carbon-raw.md` |

Each copy of the bundle was checked against `bundle/SHA256` before the run. The Carbon prompt is `PROMPT.md` plus one line that names the report path (`REPORT.md` in its copy of the bundle).
Only `SHA256` and `PROMPT.md` of the bundle are committed. The full bundle stays in this worktree's `review/bundle/` and in the two copies under `~/.cache/paper-split-review/`.
Triage of the findings is in `TRIAGE.md`.
