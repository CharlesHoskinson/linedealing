# Review 17a: Veritee committee-signing mode and the split-line paper

Two blinded bundles, each reviewed by two model families, with every finding triaged here.

## Bundles

| Bundle | Contents | Manifest `SHA256` hash | Key file hash |
|---|---|---|---|
| `veritee` | `veritee.diff` (wt-merge `committee-signing-mode` at 12b51cf against its merge base a14d735 with `main`, Cargo.lock, PEM and binary fixtures left out), `tree/` (post-change text of every added or modified file), `committee-signing-mode.md`, `PR.md`, `DIFFSTAT.txt`, `PROMPT.md` | `e6d435a4e54bc48d24d726091efb0c697eecd5e89512d88111dc9c06ff6162ef` | `veritee.diff` `ca7aadeb02bb01551650301abf44c7d84602a021884713c2bb764950582741fd` |
| `paper` | sources of mpcexperiments `main` at 4a20ccc: `main.pdf` (built with an empty author), `src/` (LaTeX, byline and the line-dealing author entry blanked), `spec/DESIGN.md` (from `main`, local path line removed, one decision-log reference replaced by its section), `spec/sizes.py`, `measure/BENCH.md`, `lean/` (KeySplit, Access, Slots, Profiles without comments, and the axioms output of a clean build; the modules have not changed since that build), `PROMPT.md` | `54899065a4fc3e487dabada5534f0d93453c487f784ff3afd52a024791e23b59` | `main.pdf` `ebd4484a17cd5805182df1a6c267517ace2131400d0a058aa1088a0138c5362b` |

Blinding: no commit metadata, no author name or e-mail address, no loop, lane or model terms, no meeting content. Three code comments that cite the design log by item number (`fence.rs`, `harden.rs`, `store.rs`) read "design decision N" in the bundle. Two comments that say "shared interface item 2/3" stayed. Limit: the reviewer prompts give the bundle copy paths, which sit under the owner's home folder, so the user name reached the reviewers as a path component.

The prompts, the manifests and the raw reports are in `review-17a/`. Each reviewer worked on its own copy of the bundle, and each copy was checked against the manifest before the run.

## Reviewer runs

| Family | Model | Run |
|---|---|---|
| OpenAI | GPT-6 Astra, reasoning effort xhigh | `codex exec`, read-only sandbox, ephemeral, systemd user units `r17a-astra-veritee` and `r17a-astra-paper` |
| Google | Gemini 4 Carbon (high) | the owner's agy pane `w1:p1C`, lane folder `lane-17a-review` inside the pane's working folder |

The Carbon pane ran the two bundles one after the other, the Veritee bundle first, after its previous lane ended and the pane was idle. Each prompt is the bundle's `PROMPT.md` with the bundle path and one line that names the report path.

## Veritee: Astra

Verdict `changes_requested`: 12 findings, 11 marked BLOCKING.

| Id | Finding | Verdict | Fix | Check |
|---|---|---|---|---|
| VA1 | Repair masks travel in plaintext over a transport that authenticates a committee epoch key but not the helper index, so a corrupt peer in the network path reads them and recovers helper PRF shares. | Admissible, blocking. Confirmed: `RepairMask.delta` plaintext, `PeerIdentity` carries no node index, `danger_accept_invalid_certs`. | A helper fetches the other helper's `BootClaim`, class 0x03 evidence and per-boot `NodeKeys` (`PeerRequest::RepairIdentity`), checks them with the requester gate plus `claim.node_index == k`, and seals the mask with `SealedToNode` under a context that binds committee, epoch, session, requester, helpers, sender, sender boot counter and recipient. | `repair_masks_wrong_helper_sends_nothing`, `repair_masks_wire_has_no_plaintext_scalar`, `repair_masks_bind_every_context_field`, `repair_masks_receiver_refuses_wrong_recipient_ciphertext`, `repair_masks_nine_node_repair_recovers_share` |
| VA2 | `put` keeps the store generation, so an older copy of one sealed entry opens after a reboot. | Admissible, blocking as a documentation claim. The code has no per-entry version; a version bound to the ledger is a design change. | Docs state the limit (LUKS section, limits list), recommendation 13 (store root in each checkpoint), PR.md open item 14. | Doc text matches `store.rs` `put`. |
| VA3 | `maintain` repairs the share that `close_epoch` destroyed. | Admissible, blocking. Confirmed in `node.rs` `maintain`. | `close_epoch` records the epoch as closed in tier 0 first. Install, repair, cold start, maintenance and the partial and repair handlers refuse a closed epoch. | `closed_epoch_stays_closed_after_maintenance_and_restart`; `closed_epoch_share_no_longer_answers` still passes |
| VA4 | The follower snapshot has no freshness bound, so a cut-off old instance keeps serving on its own ticket. | Admissible, blocking as a documentation claim. A freshness bound needs the follower, which is not in the repository. | The `ledger_file.rs` comment, the boot-ticket section and the limits list state the limit. Recommendation 1 adds the freshness bound. PR.md open item 13. | Doc text matches `fence.rs` `check`. |
| VA5 | The TPM gate accepts `/dev/tpm0`, `/dev/./tpmrm0` and bind mounts of `/dev`. | Admissible, blocking. | Both validators normalize device and bind sources, refuse `/dev` and `/dev/tpm*` outside `guest-attestation`, and refuse `privileged` and `device_cgroup_rules`. | `test_tpm_sources_and_device_access_bypasses_are_refused` and `test_allowed_device_sources_and_shipped_template` in both suites |
| VA6 | Measured setup does not repeat the Key Vault check, and packaging checks only `environment`. | Admissible, blocking. | Both validators refuse `vault.azure.net` in any string of a service, in any case. | `test_key_vault_strings_anywhere_in_service_are_refused` in both suites |
| VA7 | The doc says the HPKE private key stays in `attestation_server`; `node_keys_export` hands it to the app uid. | Admissible, blocking. | Doc states the export and points to recommendation 9. PR.md open item 12 names it. | Doc text matches `committee.rs` `NodeKeysExport`. |
| VA8 | The template does not pass `VERITEE_COMMITTEE_MODE` to the attestation helper, so its quotes carry no evidence binding. | Admissible, blocking. Confirmed in the full repository: no file sets it for the container. | `run.d/main` writes `VERITEE_COMMITTEE_MODE=1` to `.guest-attestation.env`. | `test_template_hook_emits_committee_mode_in_guest_environment` |
| VA9 | `RepairMask` derives `Debug` and prints the mask. | Admissible, blocking. | Manual redacting `Debug` on every type that holds a mask. | `repair_masks_debug_is_redacted` |
| VA10 | The peer-side witness conflict test refetches first, so the local guard refuses and the peer check is never reached. | Admissible, blocking. | The test sends a signed conflicting witness to a peer directly, before and after that peer restarts. | Fails with the peer conflict branch removed, passes with it. |
| VA11 | `measured-setup.service` timeout rises from 300 s to 900 s for every image, not disclosed. | Admissible, blocking as a disclosure. The first committee boot formats the volume in that unit, so the timeout stays. | PR.md "Default behavior" states the change. | PR.md text |
| VA12 | The attestation server reads the proxy policy once, before committee phase 2 installs it, so app routes stay forbidden. | Admissible, non-blocking (fails closed). Confirmed: `attestation_server.service` starts before `measured-setup-committee.service`. | A policy file that is absent at startup is loaded on the first request after it appears and then kept. | `measured_policy_installed_after_startup_is_loaded_and_retained` |

Commit 8d07b95 on `committee-signing-mode`.

Checks run after the fixes:

| Crate or suite | Result |
|---|---|
| `server/seald` | `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings` clean, default and `--features tpm`; `cargo test` 35 and 31 pass, default and `--features tpm` |
| `server/azure_attestation_server` | fmt clean; clippy clean, default and `--features committee`; `cargo test` 27 pass 2 fail (default), 43 pass 2 fail (`committee`). The two failures are `tpm::test_get_ak_pub` and `tpm::test_get_ak_cert`, which need a TPM device and fail the same way on `main` |
| `pytest cli/tests veritee-os/measured_setup` | 336 passed, 1 skipped |
| `pytest server/guest_attestation/tests` | 35 passed |

## Veritee: Carbon

10 findings: 6 marked blocking (C1 to C6), 4 non-blocking (C7 to C10).

| Id | Finding | Verdict | Fix | Check |
|---|---|---|---|---|
| C1 | A selection that omits `vmpl` accepts a report from any VMPL. | Admissible, blocking. | An omitted `vmpl` requires 0. Both Python builders write `vmpl: 0` and refuse other values; the CLI verifier policy builder does the same. | `omitted_vmpl_requires_zero`; CLI `test_vmpl_zero_is_explicit_in_config`, `test_nonzero_vmpl_is_rejected`, `test_verifier_policy_vmpl_zero`; guest `test_vmpl_zero_is_explicit_in_config_and_policy`, `test_nonzero_vmpl_is_rejected_in_config_and_policy` |
| C2 | Repair blames a helper for another helper's refused mask, and one sender can flood masks, so two corrupt nodes stall repair. | Admissible, blocking. | Repair blames only direct failures and marks an indirect mask refusal ambiguous. The helper-set search stops at 64 sets; each sender has a quota of 256 masks. | `repair_retry_does_not_blame_selectively_refused_mask_sender`, `repair_retry_does_not_blame_missing_mask_recipient`, `repair_mask_sender_quota_preserves_honest_capacity`, `repair_helper_search_is_bounded_at_seventeen_nodes`, `repair_start_marks_indirect_mask_refusal_as_ambiguous` |
| C3 | Witness refetch takes unsigned entries from peers, so one peer poisons a future slot. | Admissible, blocking. | Witness entries are signed. A refetched entry counts only when it verifies under the node's own historical boot ticket, found through the new ledger lookup `try_boot_ticket`. | `fabricated_future_entry_does_not_poison_later_digest`, `broken_real_witness_signature_is_ignored`, `signed_witness_survives_store_restart`, `historical_snapshot_failure_leaves_refetch_pending`, `rolled_back_node_relearns_its_entries_from_peers` |
| C4 | Follower: (a) a missing snapshot mints boot counter 1; (b) the outbox record lacks the ticket, claim and evidence; (c) permissions and placement are not stated. | (a) and (b) admissible, blocking. (c) admissible as documentation. | (a) A missing snapshot mints no ticket. (b) The outbox keeps a `boot_registration` record with ticket, claim and class 0x03 evidence. (c) The doc states that the follower is a host service that creates `/run/veritee/midnight`. | `unavailable_snapshot_does_not_mint_a_ticket`, `boot_outbox_contains_ticket_claim_and_verifiable_evidence`, `failed_boot_evidence_does_not_submit_a_ticket` |
| C5 | A replayed hello changes the session id, evidence is checked before the hello proof, and one peer fills the session store. | Admissible, blocking. | The signed hello is checked before evidence. A pending session id is refused. Each peer has at most 8 pending and 32 established sessions, and a full store replaces only the same peer's session. | `g5_replayed_hello_cannot_change_sid`, `g5_invalid_hello_proof_rejected_before_evidence`, `g5_established_peer_cap_preserves_other_peer`, `g5_full_session_store_replaces_only_same_peer`, `g5_pending_peer_cap_and_duplicate_preserve_other_peer`, `g5_rejected_hello_does_not_store_pending` |
| C6 | Certificate checks miss CA basic constraints, key usage, unknown critical extensions, the PSS MGF1 hash and salt, an FMC floor without an FMC field, and validity during chain selection. | Admissible, blocking. | All six checks added. Chain selection checks root, ASK and VCEK validity per candidate, so an expired first candidate does not hide a valid one. | `non_ca_intermediate_is_rejected`, `issuer_constraints_are_enforced`, `pss_uses_declared_salt_length`, `pss_rejects_mismatched_mgf_hash`, `fmc_floor_requires_report_field`, `expired_vcek_before_valid_candidate_is_skipped` |
| C7 | The Caddyfile has no routes for `/enclave-key` and `/session`. | Rejected. `handle_path /tee_attestation*` strips the prefix and forwards both paths; `attested-prove` takes a base URL. | None. | Caddyfile text |
| C8 | CI does not build or test the committee features. | Admissible, non-blocking. | `.github/workflows/ci.yml`: akx committee clippy and test, a new seald job, azure_attestation_server `raw-report,committee` build and `cargo test --locked --features committee 'committee'`, and a step for `cli/tests/test_committee.py`. | YAML parses; commands match the local runs |
| C9 | `lagrange_at` accepts duplicate indices, labels lack a prefix rule, and `--amd-roots` overrides the roots. | Rejected. Internal callers check distinct indices before the call, the labels are prefix-free, and the operator tool needs a root override for test chains. | None. | Call sites of `lagrange_at` |
| C10 | Two image-level changes are not disclosed: the 900 s timeout for every image, and the new stop of a default boot when `/mnt/persist` is not mounted. | Admissible, non-blocking, as disclosure. The timeout was already disclosed (VA11). | PR.md "Five image-level changes" states both. | PR.md text |

The session store TTL test (`session_store_complete_and_with_records_respect_ttl`) failed 3 of 5 runs on `main` as a timing flake. Its TTL is now 300 ms and its sleep 400 ms; it passed 5 of 5 runs.

Commit 92eeee8 on `committee-signing-mode`.

Checks run after the second set:

| Crate or suite | Result |
|---|---|
| `server/seald` | fmt clean; clippy clean, default and `--features tpm`; `cargo test` 47 and 31 pass, default and `--features tpm` |
| `server/akx` | fmt clean; clippy clean, default and `--features committee`; 25 pass (default), 53 pass (`committee`) |
| `server/azure_attestation_server` | fmt clean; clippy clean, default and `--features committee`; 27 pass 2 fail (default), 45 pass 2 fail (`committee`), the same two TPM tests |
| `server/veritee_verify` | fmt clean; clippy clean; 85 unit and 4 CLI tests pass |
| `pytest cli/tests veritee-os/measured_setup` | 341 passed, 1 skipped |
| `pytest server/guest_attestation/tests` | 35 passed |

## Paper: Astra

Verdict `changes_requested`: 7 findings, all marked BLOCKING.

| Id | Finding | Verdict | Fix | Check |
|---|---|---|---|---|
| PA1 | C11 claims "any" adversary, but the settlement argument needs two quorums to share an honest node. | Admissible, blocking. Two quorums of `q = ⌈(n+f+1)/2⌉` share `2q − n ≥ f + 1` nodes. DESIGN C11 has the same error. | C11 adversary: host chain any, by the pinned input; settlement `|C| ≤ f`. §Finish states the bound and that a larger coalition can sign two outcomes while the pinned input still lets one spend confirm. | `2·6 − 9 = 3`, `2·12 − 17 = 7`, both `> f`. |
| PA2 | C2 at `|C| < q` conflicts with the paper's own board-fork recovery of `x_f` at `n = 17`, `|C| = 10`. | Admissible, blocking. DESIGN C2 has the same gap. | C2 adversary adds: in non-TEE mode without a slot anchor `|C| ≤ f`, because a larger coalition recovers `x_f` by forking the board. C1 does not depend on the secrecy of `x_f` and is unchanged by this finding. | `3(12 − 10) = 6 ≤ 7`; at `n = 9` the attack needs `|C| ≥ 6 = q`. |
| PA3 | The offline-holder birth proof binds `X_u` but not `E_c`, so a creator can certify a shard that the holder cannot derive. | Admissible, blocking. DESIGN §3.1 step 1 has the same proof. | §Address birth states the exposure: the holder detects it when it first opens the record, and until then a payer relies on the creator for that shard. C1 states what the birth proofs show for such a shard. The missing rule goes to the design (below). | Text matches DESIGN §3.1 step 1 and step 3. |
| PA4 | ECDSA precedence in the paper disagrees with DESIGN §4.1. | Not admissible. The bundle carries DESIGN from `main`. The rule and O38 are DECISIONS 54 on `quint-split`, whose DESIGN §4.1 line 308 matches the paper sentence by sentence. | None. | Compared with `git show quint-split:design/enhancement/DESIGN.md`. |
| PA5 | The slot formula `2t(33t + 32n)` omits the dealer context, ephemeral key and proof. | Admissible, blocking. | The formula is named as the commitments and share ciphertexts, and the measured one-slot (8,351 B and 24,612 B) and four-slot batch (30,317 B and 92,580 B) posts follow. | BENCH.md slot table. |
| PA6 | The latency counts acknowledged rounds as one peer hop each. | Admissible, blocking as a definition. The formulas count one `h` per batched round, as DESIGN §11.2 does. | `h` is defined as one peer round (a message and its reply or acknowledgement); the five rounds are listed. Estimates unchanged. | Every `h` in the formulas is a round. |
| PA7 | An OR escrow does not mark P2, because P1 admits OR gates. | Admissible, blocking. | The view row says the escrow marks an address with an OR gate, every P2 address among them. | DESIGN §3.8 OR gates. |

## Paper: Carbon

Verdict `changes_requested`: 9 findings, 5 marked BLOCKING.

| Id | Finding | Verdict | Fix | Check |
|---|---|---|---|---|
| PG1 | ECDSA precedence disagrees with DESIGN and O38 does not exist; the opening checks require precedence and an authorization in force before the authorization finalizes; the described race cannot happen. | Divergence and O38: not admissible, as PA4. Opening checks: admissible, blocking; the same list is in DESIGN §4.7. Race: admissible, blocking; the requests of one source spend one nullifier and the two P2 sources open disjoint slot roots. | Order and open: structure, distinct points and TEE recomputation at opening; authorization and precedence once the authorization is in force. The race sentence in §ECDSA slots and in Limits is replaced by the statement that two requests on one ECDSA slot never both come into force. | Matches the nullifier rule of §Authorization and the slot roots of §ECDSA slots. |
| PG2 | The frame size, the actor growth and the signing set `7` at `n = 9` non-TEE do not add up (`11,422 + 495 + 6·790 = 16,657 > 16,384`); TEE counts omit the TEE header fields. | Admissible, blocking. The frame-capacity test in `impl/tests/split_envelope.rs` uses the reference capsule of 481 bytes per variant from `sizes.py`; the measured P2TR capsules are 4,134 bytes, 286 more for eight. The test header has no TEE fields. | The caption states the reference capsule, that the measured capsules lower the first count at `n = 9` non-TEE to 6, and that the TEE counts leave out the TEE header fields. | `16,384 − 11,422 − 495 = 4,467 = 5·790 + 517`. |
| PG3 | `K = L = 1` row names Solana, but the measured rows are ECDSA and BIP340. | Admissible, blocking. | Row reads "Ethereum or P2TR". | BENCH.md signing-set table. |
| PG4 | Slot formula omits overhead; board totals unmarked although they hold a vote estimate. | Formula: as PA5, fixed. Marking: admissible, blocking. | `\estBoardNine` and `\estBoardSeventeen` carry the estimate mark. | Macro text. |
| PG5 | "One PLONK circuit at 2^18 rows" is stated as fact; O4 drops the limit of 2^21. | Admissible, blocking. | §Ticket proof: target 2^18, limit 2^21, row count with all three suites open (O4). O4 row names the limit. | DESIGN O4 and §11.4. |
| PG6 | Slot replenishment 14.49 ms against BENCH 14.483 ms, so the parts do not sum to 17.41 ms. | Admissible, non-blocking. | 14.48 ms. | `2.93 + 14.48 = 17.41`. |
| PG7 | "Two board commits after its authorization is in force" contradicts ordering during finality. | Admissible, non-blocking. | The ordering commit can land while the authorization finalizes; the admission commit follows it. | Matches §Latency. |
| PG8 | Salt derivation, body-key label and TEE header fields left out. | Admissible, non-blocking. | `salt = H(salt_v ‖ g ‖ j)`, `k_{v,g} = KDF(Z_{v,g} ‖ body)`, TEE header lists the intent, `X`, leaf root, commitment randomness and salt seeds. | DESIGN §4.2, §4.6. |
| PG9 | A cold start burns free and bound ECDSA slots; C18 secrecy omits the other actors; "58 declarations" counts only results. | Admissible, non-blocking. | All three changed as proposed. | DESIGN §7.11, C18; the Lean files. |

Build after all paper fixes: `latexmk -pdf` exit 0, 32 pages, no undefined or multiply defined references, no overfull boxes; one underfull box (badness 1259) that the build had before these fixes. Commit fa87351 on mpcexperiments `main` (paper-split/ only).

## Findings for the design specification

The paper is fixed for these. DESIGN.md is outside this item; the lead records each with a DECISIONS entry.

1. C11 adversary column says "any". It holds for the host chain by the pinned input; settlement needs `|C| ≤ f` (PA1).
2. C1 and C2 at `|C| < q`: C2 also needs `x_f` secret, so in non-TEE mode without a slot anchor it holds for `|C| ≤ f` only (PA2).
3. §3.1 step 1 and step 3: the creator's proof for an offline holder binds `X_u` and not `E_c`. A rule is missing, for example a proof that `E_c` decrypts to the `e_c` behind `δ`, or a holder acknowledgement before a payer funds the address (PA3).
4. §11.2 defines `h` as "one peer hop" and counts one `h` per acknowledged round. It should read "one peer round" (PA6).

5. §4.7 checks after the header opens list precedence (item 3) and the authorization in force (item 5), but the header opens during finality, and ECDSA precedence needs the authorization in force. Split the opening checks from the admission checks (PG1).
6. §11.1 signing sets rest on `sizes.py` capsules of 481 bytes per variant, smaller than the measured P2TR capsules, and leave out the TEE header fields; `sizes.py` uses the non-TEE header for TEE mode (PG2). The fix is in `impl/tests/split_envelope.rs` and `sizes.py`: one fixture for the sizes and the capacity test.
7. §11.3 slot replenishment at `n = 17` reads 14.49 ms; BENCH.md measures 14.483 ms (PG6).
8. DECISIONS 54 and O38 are on `quint-split` and not yet in `main`'s DESIGN (PA4, PG1).

## Quint checks owed

Six Veritee fixes change protocol state. The Veritee committee model is in another worktree, so the lead extends it:

- Share repair: a mask reaches only the helper that the sender checked as index `k` (VA1).
- Epoch closure: no transition reinstalls a share of a closed epoch, through maintenance, repair, cold start or restart (VA3).
- Repair liveness: with at most `f` corrupt nodes, repair finishes when `t` honest holders answer; a node is blamed only for its own failure (C2).
- Witness recovery: a recovered entry always verifies under the node's own boot ticket for that slot, so no peer fills a slot the node did not sign (C3).
- Boot tickets: no ticket is minted without a snapshot, and every submitted ticket carries its claim and evidence (C4).
- Session setup: a hello opens at most one session id, and one peer cannot take another peer's pending or established slots (C5).

The other fixes change validators, framing or documentation and are covered by their unit tests.
