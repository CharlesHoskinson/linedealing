# Council review: one owner move, then a committee spends

You are an independent cryptographic reviewer. Two candidate protocol designs answer the brief at design/BRIEF.md (read it first; its acceptance criteria are the bar). The candidates:

- cand-3c91: ~/.cache/council-mpc/blind/cand-3c91.md
- cand-a7e2: ~/.cache/council-mpc/blind/cand-a7e2.md

Background the candidates were given: research/REPORT.md and the papers under research/sources/ (more ePrint PDFs may have arrived in sources/oneshot/ and sources/eprint/). Check claims against the local papers where you can. Do not read anything else under ~/.cache/council-mpc/ or design/ except the files named here. Do not edit any file except your output.

Try hard to BREAK each candidate. In order of importance:
1. Soundness: can a coalition below the stated threshold learn the key, or get a signature on anything the owner did not authorize? Nonce reuse, ROS/Wagner, related-key, replay, rollback, malleability, rogue dealing.
2. Do the equations hold? Check every signing and verification equation and every implied commitment; do small numeric checks if you can.
3. Does it meet each acceptance criterion in the brief? Is the existing-address claim real for ECDSA, BIP340/Taproot and Ed25519?
4. Are the cost numbers derived correctly for n = 16, 64, 256?
5. Are citations honest (marked read-in-full vs from memory)?

For EACH candidate, output this block:

## <candidate id>
VERDICT: approved | changes_requested | insufficient_evidence
(approved = no blocking flaw; changes_requested = at least one concrete flaw that must be fixed; insufficient_evidence = you could not decide, say why)
### Blocking findings
Numbered. Each: the claim or section, the flaw, a concrete attack or counterexample or failing equation, and the required fix.
### Non-blocking findings
### Strongest idea worth keeping
One paragraph.

Then a final section:
## Head-to-head
Which candidate is the better base design and why, in under 200 words.

Your final message IS the review: return the complete review as your final answer.
