# Review 3 bundle

Source: commit 1166333 of this repository, files under `design/enhancement/`.

| File | SHA-256 at 1166333 |
|---|---|
| DESIGN.md | 9a5b1c09bb6e2f56b5c09143fa7f9ad828c751aa51fb6538f1c371f8c28b5017 |
| DECISIONS.md | 6e3765003beaa104479023f1e0aea34f813e436d45e213c240708dc58b7a33ac |
| vectors/check.py | 2e2fef7fbf392d8ecad8ece5cf0a9df10563749ee8b415f473ecc0560fe8e968 |
| vectors/ed.py | 97dbd17a135f9698df3766a15eb3ba2f4e9553f3b1f98c2a27231b8983e136fd |
| vectors/sizes.py | 8ee3a58a92346a21fd0a8f2d9188917725ffebe4804a0db0025abde542e8cb32 |

## Blinding

DESIGN.md and vectors/ went to the reviewers byte for byte. DECISIONS.md names the source proposals by their lane names and cites one internal meeting line, so the reviewers received a blinded copy: lane names replaced by "proposal A/B/C", the input list replaced by one neutral line, the source-trace sentence of the seizure ruling removed, and dates removed from headings. The decisions and their numbers are unchanged.

| File sent | SHA-256 |
|---|---|
| DECISIONS.md (blinded copy) | 4f93822486c388de6f668963a05c89dabe67d435fea474c3494509cae7b1cb43 |

Each reviewer worked on a copy of the bundle outside the repository, with no git history and no other repository file. The prompt (`PROMPT.md`, with the bundle path filled in) names no model, vendor, author or lane and gives no history of the design.

## Reviewers

| Reviewer | Run | Raw output |
|---|---|---|
| A | GPT-6 Astra: `codex exec -m gpt-6-astra -c model_reasoning_effort=xhigh -s read-only --ephemeral --skip-git-repo-check -C ~/.cache/review3-bundle/blind`, as systemd user unit `review3-astra` | `astra-raw.md` |
| B | Gemini 4 Carbon (`gemini-4-carbon-high`), interactive agy in its own herdr pane `carbon-review3`, working folder `~/.cache/review3-bundle/lane-c` | `carbon-raw.md` |

The bundle copies sit in `~/.cache/review3-bundle/` (`blind/` for A, `lane-c/bundle/` for B), with the hashes above. The bundle path shows the local user name to the reviewers; it carries no project history. A first Carbon run through headless `argon-run` stalled after reading the bundle and was stopped; its output was empty and is not kept.

## Reads outside the bundle

Reviewer A read the bundle files and the global agent skill files that its CLI loads at start (`~/.agents/skills/`); it read no repository file. Reviewer B's pane reported seven files explored: PROMPT.md, the five bundle files and one SKILL.md of its own skill set; it read no repository file.
