# Design brief: one owner move, then a committee spends

## The question

Invent an efficient protocol for this pattern:

1. An **owner** holds the secret of an account or cryptocurrency address.
2. The owner makes **one non-interactive move**: one message, posted once (to a chain, a bulletin board or the committee), and then the owner goes offline.
3. That move **bootstraps an interactive session** among a **committee of MPC nodes**. The nodes may interact as much as they need.
4. The committee **builds the spending transaction and threshold-signs it**, so that the result is a valid spend from the owner's address.

The primary target is an **existing address**: a plain secp256k1 key (ECDSA for Bitcoin/Ethereum, BIP-340 Schnorr for Taproot) or an Ed25519 key that the owner already controls. A design that only works for addresses created for the committee is allowed, but it must say so in its first line, and it must say what it would take to cover existing addresses.

## Required reading

- `research/REPORT.md`: our state-of-the-art report. Its sections 1 (Form A and Form B), 3 (comparison tables) and 5.1 (six open gaps) frame the problem.
- `research/lanes/`: the detailed lane findings that the report rests on.
- `research/sources/`: the downloaded papers and their text. More ePrint PDFs are arriving in `sources/oneshot/` while you work; read what is there.

Rule: cite a paper only after you have read it in full from the local copy. Mark anything you know only from memory or an abstract as "from memory, not checked".

## What the design must answer

The design must close as many of the six gaps in REPORT.md section 5.1 as it can, and say plainly which ones it leaves open:

1. **Address-bound key import in one message**: the committee ends up holding a sharing of exactly the address key, with a public proof of that.
2. **Dealt shares to signing state**: no conversion step that needs the owner again.
3. **A single-transaction capability**: the committee cannot sign a second spend, or any other transaction, without a new owner move. If this is only policy, say so and say why the cryptographic version is out of reach.
4. **Committee-side transaction construction**: fee, nonce or UTXO selection and change, built deterministically from agreed chain state.
5. **A formal model**: an ideal functionality or game that joins the owner's authorization, the binding to the transaction, freshness and an offline owner.
6. **Requests across a committee change**: what happens to an owner message when the committee rotates.

## Acceptance criteria

- One owner message, and no owner action afterwards.
- A coalition below the threshold learns nothing about the key and cannot produce a signature.
- The committee cannot sign anything the owner did not authorize (state exactly how far this holds: cryptographic, or honest-threshold policy).
- No replay: one owner message gives at most the spends it names.
- Liveness: an honest threshold finishes the spend without the owner. Name the network model (synchronous, partially synchronous, asynchronous).
- Name the corruption model (static or adaptive) and every assumption.
- Give concrete costs: the owner's message size, the owner's computation, committee rounds (offline and online), communication per node and computation per node. Give numbers for n = 16, 64 and 256 and say how you derived them.
- Compare against Form A and Form B from REPORT.md.

## Response shape

Write one Markdown document with these sections, in order:

1. **Scheme in one paragraph**: the central idea, stated with conviction.
2. **Setting and assumptions**: parties, network, corruption model, setup (public parameters, committee keys, any trusted setup).
3. **Protocol**: the owner's message (every field), committee steps by round, signing, and output. Use pseudocode where it helps.
4. **Transaction construction**: how the committee builds the transaction and agrees on it.
5. **Committee change**.
6. **Security**: the ideal functionality or game, the security claims, and a proof sketch for each claim.
7. **Costs**: the table for n = 16, 64 and 256, with derivations.
8. **Gaps closed and left open**: against REPORT.md section 5.1, one line each.
9. **Comparison** with Form A and Form B.
10. **Risks and attacks you considered**, including the ones the design does not stop.
11. **Experiment plan**: what to build first in this repo to test the design, and what would prove it wrong.
12. **References**: each marked "read in full (local path)" or "from memory, not checked".
