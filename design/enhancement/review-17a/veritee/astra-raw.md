VERDICT: changes_requested

1. **BLOCKING — Share repair can reveal the group PRF secret to one corrupt peer.**

   **Location:** [tree/server/seald/src/group.rs:525](BUNDLE_COPY/veritee/tree/server/seald/src/group.rs:525), `tree/server/seald/src/peer.rs:402`, `tree/server/azure_attestation_server/src/committee/peer_client.rs:159`.

   **Claim:** Repair reveals only the requester’s share, and peer traffic remains confidential.

   **Evidence:** Masks contain plaintext secret scalars, `delta: delta.to_bytes()`, and are sent with `transport.call(k, ...)`. The transport passes only a URL:
   `{"op": "peer_call", "peer": url, "body": body}`.
   TLS certificate validation is disabled with `.danger_accept_invalid_certs(true)`. The AKX handshake verifies an attested epoch key, but never binds it to the intended helper index. It then discards the peer identity:
   `let ... MutualKeys { i2r, r2i, .. } = keys;`.

   Within the stated corrupt-peer model, a malicious requester possessing one legitimate peer’s keys can intercept helper-to-helper connections, authenticate using that identity, read the masks, and forward the original signed messages to their intended recipients. Sender-signature checks still succeed.

   Each helper subsequently returns:
   `s = lambda[pos] * share.k + sent_masks - received_masks`,
   encrypted to the requester. Knowing the masks lets the requester recover each helper’s scalar share. Seven helpers reveal the complete PRF secret. An offline scalar-field calculation confirmed this algebra.

   **Suggested fix:** Authenticate the intended committee member and boot during channel establishment, binding that identity to the AKX key. Alternatively, encrypt each mask separately to the authenticated intended helper. Add a test that substitutes another valid committee identity at a helper’s URL.

2. **BLOCKING — Ordinary sealed-value updates are replayable.**

   **Location:** [tree/server/seald/src/store.rs:430](BUNDLE_COPY/veritee/tree/server/seald/src/store.rs:430), `tree/server/seald/src/node.rs:352`.

   **Claim:** Boot tickets, witnesses and checkpoints provide rollback protection for node state.

   **Evidence:** `put` reuses the existing generation and filename:
   ```
   let gen = live.state.gen;
   let blob = Self::seal_entry(live.k_seal.as_slice(), gen, name, value);
   fsutil::write_atomic(&self.entry_path(name, gen), &blob)?;
   ```
   `get` authenticates against that same generation and key. No externally authenticated version advances on an overwrite.

   An operator can save the ciphertext for value A, allow `put` to replace it with B, then restore only A’s ciphertext. The current tier-0 state and witness logs can remain intact. On reboot, a valid new boot ticket obtains the same epoch’s `K_grp`, and A authenticates successfully. The PRF input explicitly remains stable across boots.

   This requires neither `destroy` nor epoch closure, so it extends beyond PR open item 7’s acknowledged erasure limitation. The only `latest_checkpoint` occurrence in seald is the ledger adapter implementation; unlock and storage reads do not enforce a checkpoint floor.

   **Suggested fix:** Bind sealed-state versions or authenticated roots to an external monotonic commitment and verify freshness before accepting restored state. Document separately what witness permits protect and what storage rollback protection actually exists.

3. **BLOCKING — Maintenance automatically undoes `close_epoch`.**

   **Location:** [tree/server/seald/src/node.rs:481](BUNDLE_COPY/veritee/tree/server/seald/src/node.rs:481), `tree/server/seald/src/node.rs:554`, `tree/server/seald/src/group.rs:214`.

   **Claim:** Closing an epoch destroys its share and stops the node answering for that epoch.

   **Evidence:** Closure only removes a map entry:
   ```
   pub fn close_epoch(&self, epoch: u64) -> bool {
       self.shares.destroy(epoch)
   }
   ```
   The maintenance loop subsequently executes:
   ```
   if !self.has_share(epoch) {
       if let Err(e) = self.repair_share(epoch) {
   ```
   Repair reinstalls the share with `self.shares.install(epoch, share)`. Maintenance runs every ten seconds.

   Closing the currently sealed epoch while seven other holders remain therefore causes automatic reconstruction. Sequential closure can report success on each node while maintenance replenishes previously destroyed shares. The documented retirement sequence permits closing the current epoch. There is no closed-epoch marker checked by repair or installation.

   `closed_epoch_share_no_longer_answers` checks immediately after closure and never runs maintenance, so it misses this behavior.

   **Suggested fix:** Give closure an irreversible lifecycle state that recovery and installation respect. Reject closing the active storage epoch until migration is complete, and enforce any snapshot-resistant closure through external state. Test closure across maintenance, repair requests and restart.

4. **BLOCKING — A stale follower snapshot permits indefinite service by a superseded boot.**

   **Location:** [tree/server/seald/src/ledger_file.rs:23](BUNDLE_COPY/veritee/tree/server/seald/src/ledger_file.rs:23), `tree/server/seald/src/fence.rs:83`.

   **Claim:** A node serves only while its ticket is latest; stale ledger data merely delays service.

   **Evidence:** The snapshot contains records without freshness or lease information. `latest_boot_ticket` chooses the largest counter in the local file, and the fence accepts:
   `Some(t) if t == self.own => Ok(())`.

   After a boot’s ticket becomes visible, an operator can isolate its follower while a clone obtains a newer ticket elsewhere. The isolated node continues accepting its old snapshot indefinitely. Peer authorization using that snapshot likewise treats superseded requester tickets as current.

   Verifying finality establishes that a recorded ticket existed, not that no later finalized ticket exists. This contradicts the “latest ticket” guarantees and the adapter’s assertion that a stale snapshot “delays service.” The finding concerns the interface and stated guarantee even if the separately acknowledged follower is implemented.

   **Suggested fix:** Define and enforce a freshness or lease protocol across the ledger, follower and seald. Qualify fencing guarantees with the applicable propagation bounds, and test an isolated old instance while a clone registers a newer ticket.

5. **BLOCKING — The exclusive-TPM-access gate accepts alternate TPM devices and paths.**

   **Location:** [tree/cli/veritee/committee.py:256](BUNDLE_COPY/veritee/tree/cli/veritee/committee.py:256), `tree/veritee-os/measured_setup/main.py:515`.

   **Claim:** Only `guest-attestation` can access the TPM, as stated in the validator documentation and committee Compose template.

   **Evidence:** Both validators compare source strings against the single literal `/dev/tpmrm0`:
   `if TPM_DEVICE in sources and name != TPM_SERVICE`.

   Direct execution of both validators accepted an ordinary service exposing `/dev/tpm0`, the raw interface to the same TPM. Both also accepted `/dev/./tpmrm0`. The general isolation validator blocks `/dev/net/tun`, but supplies no equivalent TPM restriction.

   **Suggested fix:** Validate normalized, resolved device identities and cover both raw and resource-manager TPM interfaces, including supported mount forms. Add equivalent packaging and guest tests for these bypasses.

6. **BLOCKING — Guest setup does not repeat the claimed Key Vault checks.**

   **Location:** [tree/veritee-os/measured_setup/main.py:506](BUNDLE_COPY/veritee/tree/veritee-os/measured_setup/main.py:506), `tree/cli/veritee/committee.py:283`.

   **Claim:** Packaging rejects Compose values naming `vault.azure.net`, and measured setup repeats those checks so a modified disk cannot skip them (`committee-signing-mode.md:222–224`).

   **Evidence:** Packaging scans service environment values:
   `if isinstance(value, str) and "vault.azure.net" in value`.
   The guest Compose validator ends after core-limit and TPM checks; it performs no corresponding scan.

   Direct execution with `environment: {VAULT_URL: "https://x.vault.azure.net"}` produced packaging rejection and guest acceptance. Putting that URL in `command` was accepted by both, contradicting the broader “Compose value” claim.

   **Suggested fix:** Apply equivalent validation to the effective Compose configuration at both stages, covering the documented fields. Add shared adversarial cases, or narrow the documentation precisely to the enforced restriction.

7. **BLOCKING — The documented HPKE private-key boundary contradicts the export API.**

   **Location:** [tree/server/azure_attestation_server/src/committee.rs:467](BUNDLE_COPY/veritee/tree/server/azure_attestation_server/src/committee.rs:467), `tree/docs/committee-signing-mode.md:212`.

   **Claim:** “The HPKE private key stays in `attestation_server`.”

   **Evidence:** `NodeKeysExport` serializes `held.secrets.export()` into a `"secrets"` response. `NodeKeySecrets::export` explicitly includes:
   ```
   out.extend_from_slice(&self.hpke_x25519);
   ...
   out.extend_from_slice(&self.provision_x25519);
   ```
   The socket admits the configured app UID, without an operation-specific export restriction.

   Recommendation 9 already acknowledges that export hands private keys to the app. The blocking issue is the contradictory security boundary elsewhere in the document, rather than the acknowledged existence of two key sets.

   **Suggested fix:** Remove export from the app-visible interface, or consistently describe the app as receiving and protecting these private keys. Do not claim exclusive possession by `attestation_server`.

8. **BLOCKING — The committee template does not enable committee binding in the static attestation helper.**

   **Location:** [tree/projects/committee-node/run.d/main:70](BUNDLE_COPY/veritee/tree/projects/committee-node/run.d/main:70), `tree/server/guest_attestation/veritee_attestation/document.py:308`.

   **Claim:** Committee vTPM quotes carry the evidence digest as qualifying data, including the Python helper named in PR.md.

   **Evidence:** The helper switches behavior only through:
   `os.getenv("VERITEE_COMMITTEE_MODE", "")`.
   Its generated `.guest-attestation.env` contains TLS settings but never this variable, and its Compose service adds no corresponding environment entry.

   Consequently, the shipped template selects:
   `attestation_payload["quote"] = get_quote()`,
   rather than `get_quote(bytes.fromhex(binding["digest"]))`, and omits `quote_binding`. The host attestation server’s systemd environment does not populate a container’s environment.

   The helper test explicitly patches `VERITEE_COMMITTEE_MODE=1`, so it does not validate template wiring.

   **Suggested fix:** Pass the measured committee-mode setting into the helper container and test the effective template configuration through quote construction.

9. **BLOCKING — Repair secrets have unredacted `Debug` output.**

   **Location:** [tree/server/seald/src/group.rs:278](BUNDLE_COPY/veritee/tree/server/seald/src/group.rs:278).

   **Claim:** Secret types have redacted `Debug` output (`committee-signing-mode.md:246`; PR checklist item 131).

   **Evidence:**
   ```
   #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
   pub struct RepairMask {
       ...
       pub delta: [u8; 32],
   }
   ```
   Derived formatting prints the secret mask bytes. `SignedRepairMask` also derives `Debug`, propagating the disclosure. Zeroizing the field on drop does not redact formatting.

   These masks protect helper shares, as finding 1 demonstrates. The established defect is unredacted `Debug` output; production log emission was not demonstrated.

   **Suggested fix:** Remove the implementation or provide explicitly redacted formatting, including enclosing request types. Add a formatting regression check.

10. **BLOCKING — The “without refetch” witness test does not exercise peer conflict rejection.**

    **Location:** [tree/server/seald/tests/committee.rs:661](BUNDLE_COPY/veritee/tree/server/seald/tests/committee.rs:661), `tree/server/seald/src/witness.rs:367`.

    **Claim:** `peers_refuse_a_second_digest_even_without_the_refetch` tests independent rejection by peers.

    **Evidence:** Immediately before the conflict attempt, the test successfully refetches:
    ```
    n2.sync_witness().unwrap();
    assert!(n2.witness(slot(7), [2; 32]).is_err());
    ```
    Refetch restores the original digest locally. `WitnessClient::witness` then calls:
    `self.own_store.record(...)?`
    before sending any peer request.

    The attempted conflict therefore fails locally. This test would still pass if peer-side conflict rejection were removed.

    **Suggested fix:** Send a correctly signed conflicting request directly to a peer holding the first digest, bypassing the requester’s local guard. Assert the specific refusal and that the peer handler was reached; repeat after restarting that peer.

11. **BLOCKING — Default-mode setup timeout changes without disclosure.**

    **Location:** [tree/veritee-os/mkosi/rootfs/mkosi.extra/etc/systemd/system/measured-setup.service:17](BUNDLE_COPY/veritee/tree/veritee-os/mkosi/rootfs/mkosi.extra/etc/systemd/system/measured-setup.service:17), `veritee.diff:21500`.

    **Claim:** Non-committee DApps retain the default boot behavior described in PR.md.

    **Evidence:** The shared unit changes unconditionally from:
    `TimeoutStartSec=300`
    to:
    `TimeoutStartSec=900`.

    A stalled non-committee setup now runs for fifteen minutes before timeout instead of five, changing failure and retry behavior. PR.md’s default-behavior exceptions do not disclose this. Committee phase 2 already has its own 900-second timeout.

    **Suggested fix:** Retain the original timeout in the shared unit and place committee-specific timing in the committee unit, or explicitly disclose and justify the default-mode change.

12. **NON-BLOCKING — Two-phase startup can permanently cache an empty application proxy policy.**

    **Location:** [tree/server/azure_attestation_server/src/main.rs:1182](BUNDLE_COPY/veritee/tree/server/azure_attestation_server/src/main.rs:1182), `tree/server/azure_attestation_server/src/proxy_routes.rs:519`, `tree/veritee-os/measured_setup/main.py:1007`.

    **Claim:** Successful committee startup makes the configured application tunnel routes available.

    **Evidence:** The attestation server reads the policy once through `DappUpstream::from_env()`. A missing file yields:
    `Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HashSet::new())`.

    Phase 1 removes the policy file; phase 2 installs it only after starting the application. The attestation server starts before phase 2 completes, and there is no policy reload. If initialization reads the file before installation, ordinary application tunnel routes remain forbidden until the server restarts.

    **Suggested fix:** Install the validated policy before server initialization, or implement an authenticated, atomic reload after phase 2. Test the actual service ordering.

Checked and found sound by source inspection:

- The public attestation handler fixes the evidence class to `0x00`; it does not accept a caller-selected committee class.
- Evidence verification rejects empty PCR policies and checks the configured debug, migration and TCB restrictions.
- TPM sealing binds PCRs 4, 14 and 15; the cap precedes admin-socket service, and volume-key access checks root credentials.
- PRF partial verification uses commitment-bound DLEQ checks and canonical scalar/point decoding.
- Witness records omit the boot counter from the conflict key, persist before acknowledgement, and require distinct verified acknowledgement signers when supplied with current ledger state.

Validation comprised local source/diff review, syntax parsing of the 14 supplied Python files, direct execution of the extracted Compose validators, and an offline repair-algebra check. The published Rust suites and Azure/vTPM integration paths were not rerun. No network or git commands were used.