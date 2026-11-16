# Blinded review: pen-and-paper security proofs

You are an independent reviewer of a cryptographic proof document. Do not edit any file except your report. Do not run git.

Bundle (frozen copies; read from here): `design/proofs-review/bundle/`
- `PROOFS.md`: the document under review.
- `SCHEME.md`: the protocol it proves things about.
- `PROOF-CHECK.md`: an earlier check that listed gaps the proofs try to close.
- `groth-shoup-2021-1330.pdf` (ePrint 2021/1330) and `2022-506.pdf` (ePrint 2022/506): the papers the reductions use.

## Question
Are the theorems in PROOFS.md correct as stated, and do the proofs establish them? Priority targets: Theorem B (single-signer two-nonce Schnorr under AOMDL in the ROM, with its forking lemma) and Lemma 5 (the EC-GGM symbolic-simulation extension used for claim 6, open ECDSA). Then Theorem A (black-box reduction to 2021/1330 Theorem 3: check each stated condition against the paper's actual theorem statement and page), Theorem C (share encryption, repeating the 2022/506 Theorem 2 game sequence), Theorem D, Theorem E, and the associated-data fix (`SHA-256(ct)` inside the hash-to-curve input).

## Rules
- A finding is BLOCKING if a theorem is false as stated, a proof step does not follow, a cited theorem does not say what is claimed, or an assumption is missing. Give the location (section, theorem, line) and a concrete reason; a counterexample or a quoted page from the paper where possible.
- Do not count style or wording issues as blocking.
- If you cannot judge a part, say "insufficient evidence" for that part, not approval.

## Output
Write the report as your final answer with this shape:
VERDICT: approved | changes_requested | insufficient_evidence
then a numbered list of findings, each: severity (BLOCKING / NON-BLOCKING), location, claim, reason, suggested fix.
