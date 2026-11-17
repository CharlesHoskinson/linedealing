# Blinded review: Veritee change "Add committee-signing mode"

You are an independent security reviewer of a code change to Veritee, a system that runs applications in AMD SEV-SNP confidential VMs on Azure with vTPM attestation. The change adds an opt-in mode in which a VM runs one node of a threshold-signing committee (n = 9, f = 2, t = 7). Review adversarially. Do not edit any file except your report. Do not run git. Do not use the network.

The bundle (BUNDLE_DIR):
- BUNDLE_DIR/PR.md: the change description, its gates, test evidence, mocks, review checklist and open items.
- BUNDLE_DIR/committee-signing-mode.md: the design document of the mode (mechanism, lifecycle, residual risks, recommendations).
- BUNDLE_DIR/veritee.diff: the unified diff against the base branch. Cargo.lock files, PEM roots and binary test fixtures are left out; DIFFSTAT.txt lists every changed file.
- BUNDLE_DIR/tree/: the full post-change text of every added or modified file, at the same paths, for context.

## Question
Is the change correct, secure and honestly described? A finding is BLOCKING if:
- the code lets an attacker in the stated threat model (node operator, network attacker, a corrupt minority of peers, a restored disk or cloned VM) obtain a secret, produce committee-class evidence from the public route, sign twice for one slot, roll back sealed state, or bypass a gate the documents claim;
- default (non-committee) Veritee behavior changes in a way PR.md does not state;
- a security claim in PR.md or committee-signing-mode.md is false or stronger than the code supports, or the documents contradict each other or the code;
- a cryptographic step is wrong (domain separation, transcript binding, DLEQ checks, nonce or key reuse, HKDF inputs, PCR policy, certificate-chain or TCB checks, replay or freshness);
- a test claims to check something it does not check.
Known open items listed in PR.md are not blocking unless the code or documents state them wrongly. Style and naming are NON-BLOCKING.

## Output
Write your report in English. Start with
VERDICT: approved | changes_requested | insufficient_evidence
then a numbered list of findings, each with: severity (BLOCKING / NON-BLOCKING), location (file and line in tree/ or the diff), claim, reason with evidence (quote the code), suggested fix. Then a short list of what you checked and found sound.
