# Blinded review: research paper "Line Dealing: One-Move Spend from Existing Addresses"

You are an independent reviewer (program-committee standard, cryptography/security venue). Do not edit any file except your report. Do not run git.

Paper: `paper/review/main.pdf` (sources in `src/`; read the .tex if the PDF is hard to parse).
Supporting material the paper must agree with (read as needed):
- `design/SCHEME.md` (protocol), `design/PROOFS.md` (proofs; section 8 is the open list)
- `research/PRIOR-ART.md`, `research/prior-art-review/REPORT.md`
- `formal/lean/REPORT.md`, `formal/natural/REPORT.md`, `formal/quint/REPORT.md`
- `impl/BENCHMARKS.md`
Benchmark numbers in the paper come from macros that will be refreshed after one more measurement run; do not count stale numbers against the paper, but do flag any number that is inconsistent with BENCHMARKS.md or with the paper itself.

## Question
Is the paper correct and honest? A finding is BLOCKING if: a theorem or claim in the paper is false, or stronger than what PROOFS.md / the formal reports support (overclaiming); a construction step is ambiguous enough that an implementer would build something insecure; a related-work statement misrepresents a cited work or claims novelty that the prior-art material contradicts; a formal-verification or evaluation claim does not match its report; or the paper is internally inconsistent. Style, length and presentation issues are NON-BLOCKING.

## Output
Write the report to paper/review/review-cand-c.md.
VERDICT: approved | changes_requested | insufficient_evidence
then a numbered list of findings, each: severity (BLOCKING / NON-BLOCKING), location (section, page or .tex file and line), claim, reason with evidence (quote the supporting file), suggested fix.
