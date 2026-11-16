# Brief: extend line dealing to Fenrir co-custody and operator blindness

You are one of three independent design lanes. Search the web for prior art, brainstorm, then deliver one concrete protocol enhancement. Work alone; other lanes do the same task and a lead merges the results.

## Background you must read

- `design/SCHEME.md`: the current protocol, "line dealing". Read §1, §2, §3.2–3.10, §4, §5, §6 (claim statements), §8, §10 in full.
- `requirements/catalogue/FACTS.md`: checked facts about line dealing.
- `~/Projects/veritee/veritee-vm/`: Veritee, the in-house TEE system (Azure Confidential VMs, AMD SEV-SNP, vTPM, dm-verity measured images, in-guest attestation server, attested key exchange in `server/akx`, measured egress proxy, registration of measurements on Midnight through a "Warden"). Read `README.md`, `docs/attested-channel-implementation-plan.md`, `docs/tls-channel-binding.md`, `server/akx/src`, `server/azure_attestation_server/src`, `veritee-os/measured_setup`. If `design/enhancement/VERITEE-MODEL.md` exists, read it too. The companion repos (warden, spec, contracts) are not available; state any assumption you make about them.

Line dealing in one paragraph: the owner of an existing address holds its whole key x. The owner sends one message and goes offline. In sealed mode the message is a publicly checkable Shamir dealing of finished signatures on a grid of conflicting transactions spending one pinned input; a committee of n ≥ 3f+1 (launch n = 9, f = 2, board quorum q = 6, key threshold t = 7) selects and releases one when an on-chain trigger holds. In open mode the owner deals the signature line itself and the committee builds the transaction from chain state. Output is a native single-key ECDSA or BIP340 signature. Requests, headers and lock digests sit on a public BFT bulletin board. Midnight is the settlement and authorization chain; its contracts are written in Compact and prove predicates in zero knowledge.

## The two problems to solve

**Problem 1. The owner holds the whole key.** The product requires all of the following at once:

- R1 (keep). If any set of Fenrir nodes, up to all of them, tries to spend without an authorization the asset's rules admit, no valid spend results. The committee never holds a piece the user holds.
- R2. While an asset is under Fenrir control, every spend needs the Fenrir network's participation. No single party, device, scheme or network can move the asset alone, and no single party holds the private key of the controlling address.
- R3. Addresses are created by the network under multi-party control. No committee member holds the private key. The user receives, securely, the element the user needs to start spends, and the address is then controlled only jointly with that element. A new or change address gets a fresh user element; the user's wallet may supply its own key share for a new address.
- R4. Covenants bind the holder. Every spend of a covenanted asset, including one by the holder or by a thief of the holder's wallet, obeys the asset's charter and regulator guardrails, with no bypass. The covenant follows the asset to the next holder, account or chain. Fenrir can freeze, blacklist and reverse stolen funds. The admitted authorization sources for a payment are exactly three: (a) an effect admitted by the intent of every principal, (b) a seizure backed by a legal order or default terms, (c) a sweep to the owner's standing exit record. A live legal hold blocks the owner's route. Named approvers (issuer, regulator, KYC check) can hold a veto.
- R5. The launch shape is a two-key custody: one user key and one Fenrir key, a third key where a third party is added. Funds are never trapped: the user has a recovery or exit path if Fenrir disappears.

Note the tension between R1 and R4(b): a seizure moves funds without the owner. Take a position on how R1 must be read (for example "no spend without an authorization source the charter admits, proved on Midnight") and make the design enforce exactly that.

**Problem 2. The public board breaks operator blindness.** Requirements:

- B1. The content, owner identity, intent and covenant terms of every request stay hidden from node operators.
- B2. An operator who wants to censor or select requests learns nothing to select by.
- B3. A pending request stays sealed; the committee decrypts only after a quorum certificate fixes its order, and fewer than the threshold of corrupt members cannot decrypt earlier.
- B4. For v1, each operator runs its node, mempool and secure erasure inside a TEE that hides content from the operator. Long term a cryptographic mechanism replaces or supplements the TEE, provably, and layers on the TEE design without a redesign.
- B5. Observers cannot link an egress to the deposit that funded it, cannot tell which user owns a foreign address or started a transaction, and cannot tell a customer-initiated from an institution-initiated egress.
- B6. The host transaction itself may be public. Before host inclusion only the signing set sees the message.

Covenant checks still need someone to evaluate predicates. Blindness and enforcement must coexist (for example: Midnight proves the predicate in zero knowledge, and the committee checks only a proof and a commitment).

## Hard constraints

- Two modes, both specified in full: **TEE mode** (built on Veritee as it exists, with its real attestation and key exchange; name what Veritee lacks and how you add it) and **non-TEE mode** (cryptography only: threshold encryption, DKG, threshold signing, ZK, MPC). The non-TEE mode must layer on the TEE mode without a redesign (B4).
- The owner still acts once, offline, with no interactive round per spend. One-time setup interaction at address creation is allowed if you say so.
- Prefer a native single-key output on the target chain (Bitcoin P2TR/P2WPKH, Ethereum EOA, Solana). If you choose an on-chain multisig or contract account anywhere, say where and why.
- Chains: Bitcoin, Ethereum (EVM), Solana first.
- Committee n = 9, f = 2 at launch, n = 17, f = 5 later. Rotation must not move coins.
- Keep line dealing where it still serves (the user's leg, sealed variants, the one-move channel). Do not drop its sealed-mode guarantee for the user's half.
- No Sherlock-style circuit above 2^21 rows if you propose a ZK circuit for the committee; prefer small-field STARKs for heavy proofs with one BLS12-381 wrap.

## Research

Search online for prior art and read what you cite. Candidates, not a limit: two-party and threshold ECDSA/Schnorr with a privileged party (e.g. DKLs23, CGGMP21, FROST, ROAST, MuSig2, "2PC + threshold" wallet designs, Fireblocks MPC-CMP, Coinbase/ZenGo 2-of-2), Ika/dWallets (2PC-MPC, user share + network share), NEAR chain signatures, Lit, threshold encryption mempools (Shutter, Ferveo, batched threshold encryption, "TrX"), sealed-bid and encrypted mempools, TEE-based signers (Flashbots SUAVE/TDX, Secret Network, Oasis Sapphire, Phala dstack), key policy and freeze in tokenized assets (ERC-3643 forced transfer, Solana token-2022 permanent delegate, Taproot covenants and vaults), Bitcoin key-path blinding and adaptor signatures, blind threshold signing, threshold FHE. For every source you rely on, give its URL and say what you took from it. Do not cite a paper you did not open.

## Deliverable

Write one Markdown document (the path is in your launch message) with these sections:

1. **Summary** (one page): the enhancement, the two modes, the one idea that makes it work.
2. **Key and address model**: who holds what, how a network-created address is born (DKG, tweak, user share), what the target chain sees, recovery and exit if Fenrir disappears.
3. **Spend flow** in both modes: the owner's one move, what the committee receives, how covenant predicates and approvers gate signing, how seizure/freeze/hold work and who authorizes them, how line dealing's sealed variants fit.
4. **Blindness** in both modes: what each operator sees at each step, how the board stays public enough for ordering and slashing but blind in content, threshold decryption after ordering, unlinkability.
5. **Veritee integration** (TEE mode): exactly which Veritee components are used (attestation, akx channel, measured egress, Warden registration on Midnight), what must be added (sealed key storage, rollback protection, key provisioning across redeploys, secure erasure), and what an operator who controls the Azure host can still do.
6. **Security claims** in both modes: each claim stated precisely, its adversary (number of corrupt nodes, TEE broken or not), and a proof sketch or reduction. Say what fails when the TEE is broken in TEE mode.
7. **Requirement table**: R1–R5 and B1–B6, each with MET / PARTIAL / NOT MET per mode and one line why.
8. **Costs**: rounds, message sizes, latency, per-request CPU estimate, what breaks in SCHEME, new assumptions.
9. **Changes to SCHEME.md**: a list of section-level changes.
10. **Sources**: URL and what each contributed.

Take positions. State the mechanism in the present tense. No hedged survey.
