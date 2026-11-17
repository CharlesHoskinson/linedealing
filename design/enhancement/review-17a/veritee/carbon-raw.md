VERDICT: changes_requested

## Findings

### 1. Missing `VMPL == 0` enforcement in `SnpPolicy`, policy builders, and documentation allows guest-OS (`VMPL 2`) evidence forgery on Azure CVMs

- **Severity**: BLOCKING
- **Location**:
  - `tree/server/veritee_verify/src/snp.rs:365-367, 384-388`
  - `tree/docs/committee-signing-mode.md:86-95` (also `committee-signing-mode.md:86-95`)
  - `tree/cli/veritee/committee.py:119-141, 324-355`
  - `tree/veritee-os/measured_setup/main.py:418-425, 710-727`
  - `tree/projects/committee-node/metadata.json:27-32`
- **Claim**: Raw SEV-SNP + Azure HCL verification ensures that vTPM quotes and evidence digests originate from the Azure HCL paravisor (`VMPL 0`) rather than an untrusted guest kernel, and `bundle::verify_evidence` enforces VMPL policy.
- **Reason with evidence**:
  On Azure SEV-SNP confidential VMs, the SEV-SNP launch `MEASUREMENT` measures only the Microsoft HCL paravisor IGVM image (shared across all Azure CVMs on that paravisor release), while the Veritee OS (`PCR 4`), committee role (`PCR 14`), and app disk (`PCR 15`) are measured only inside the paravisor's vTPM. The HCL paravisor executes at `VMPL = 0`, whereas the Linux guest kernel executes at `VMPL = 2` and has direct access to `/dev/sev-guest` (`SNP_GET_REPORT`) to request hardware-signed `ATTESTATION_REPORT` structures at `VMPL = 2` with arbitrary 64-byte `REPORT_DATA` under the **identical** launch `MEASUREMENT`, `CHIP_ID`, `POLICY`, and `REPORTED_TCB`, signed by the genuine AMD VCEK.

  `tree/docs/committee-signing-mode.md:86-91` states unconditionally:
  ```markdown
  `bundle::verify_evidence` runs these checks, and one failure rejects the evidence:
  ...
  4. The report meets the policy: debug off, migration agent off, VMPL, allowed launch measurement, TCB floor.
  ```
  However, `SnpPolicy` makes `vmpl` optional (`None` by default) and skips the VMPL check whenever `self.vmpl` is `None` (`tree/server/veritee_verify/src/snp.rs:365-367, 384-388`):
  ```rust
    /// Required VMPL, if any. The Azure HCL report is produced at VMPL 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmpl: Option<u32>,
  ...
        if let Some(vmpl) = self.vmpl {
            if report.vmpl() != vmpl {
                return fail(format!("VMPL {} is not {vmpl}", report.vmpl()));
            }
        }
  ```
  Furthermore, `bundle::verify_evidence` (`tree/server/veritee_verify/src/bundle.rs`) does not require or verify an Azure vTPM AK certificate (`hcl::verify_ak_cert` is unused in bundle verification), relying solely on `REPORT_DATA[0..32] == SHA-256(hcl_runtime_data)` to authenticate `HCLAkPub` and `user-data`. Neither `cli/veritee/committee.py` (`_validate_verify_snp` at lines `119-141`, `build_verify_policy` at lines `324-355`), `veritee-os/measured_setup/main.py` (`peer_verify_policy` at lines `710-727`), `projects/committee-node/metadata.json` (`lines 27-32`), nor the configuration examples in `docs/committee-signing-mode.md:488-491` set or require `"vmpl": 0`.

  Consequently, a malicious node operator (explicitly within the threat model) booting any standard Azure CVM on the same Azure paravisor release where they have guest root (`VMPL = 2`) can generate an arbitrary software RSA keypair as `HCLAkPub`, construct synthetic HCL `runtime_data` and `TPMS_ATTEST` structures claiming arbitrary `PCR 4/14/15` values and any `evidence_digest`, bind `SHA-256(runtime_data)` into a genuine VCEK-signed `VMPL = 2` SNP report, and pass `PolicyVerifier`, `BundleVerifier`, and `veritee-verify`. If the operator controls a node slot's ticket submission, they can impersonate an attested enclave to wallets (`NodeKeys` class `0x02`) and honest peers (`AkxEpoch` class `0x01` and `BootClaim` class `0x03`), obtaining `K_grp` PRF partials and repaired `PrfShare` (`\sigma_i`) values in cleartext outside any TEE.
- **Suggested fix**:
  Hard-enforce `report.vmpl() == 0` in `SnpPolicy::check` (or default `SnpPolicy::vmpl` to `0` via `#[serde(default = "default_vmpl_zero")]` as `u32` rather than `Option<u32>` so callers cannot omit it), reject non-zero `vmpl` in `_validate_verify_snp` (`cli/veritee/committee.py`) and `committee_config_from_metadata` (`veritee-os/measured_setup/main.py`), include `"vmpl": 0` in `projects/committee-node/metadata.json` and documentation examples, and add a negative unit test asserting that `bundle::verify_evidence` rejects a `VMPL = 2` report under a default policy.

---

### 2. Share repair (`GroupClient::repair`) misattributes blame to honest helpers under a single Byzantine peer (`f = 1`), breaking `f = 2` fault tolerance, and exposes a global `st.masks` DoS cap

- **Severity**: BLOCKING
- **Location**:
  - `tree/server/seald/src/group.rs:58-59, 525-547, 566-600, 608-624, 817-869`
  - `PR.md:6, 48, 144`
  - `tree/docs/committee-signing-mode.md:151-155, 421-424`
- **Claim**: Share repair recovers a rebooted node's PRF share in an `(n = 9, f = 2, t = 7)` committee whenever at least `t = 7` honest helpers hold their shares (`PR.md:144` only notes per-requester `REPAIR_CAP` exhaustion).
- **Reason with evidence**:
  `GroupClient::repair` iterates over `t`-combinations of candidate helpers and maintains a permanent `failed: BTreeSet<u32>` across combinations (`tree/server/seald/src/group.rs:817-831`):
  ```rust
        let mut failed: BTreeSet<u32> = BTreeSet::new();
        for helpers in combinations(&candidates, t) {
            if helpers.iter().any(|h| failed.contains(h)) {
                continue;
            }
            match self.repair_with(epoch, &helpers) {
                Ok(share) if commitment(&share.k) == own_commit => return Ok(share),
                Ok(_) => continue,
                Err(Some(h)) => {
                    failed.insert(h);
                }
                Err(None) => {}
            }
        }
        Err(GroupError::RepairFailed(t))
  ```
  `repair_with` blames `Some(h)` whenever a call to helper `h` returns an error (`lines 851-866`):
  ```rust
        for &h in helpers.iter().rev() {
            match self.transport.call(h, &start) {
                Ok(PeerResponse::RepairStarted) => {}
                _ => return Err(Some(h)),
            }
        }
        ...
        for &h in helpers {
            let Ok(PeerResponse::RepairShare(r)) = self.transport.call(h, &finish) else {
                return Err(Some(h));
            };
  ```
  A single Byzantine peer (`f = 1 <= 2`) causes `repair_with` to blame and blacklist **honest** helpers in two independent ways:
  1. **Refusing `RepairMask` after accepting `RepairStart`**: Because `repair_with` runs `RepairStart` from highest index to lowest (`helpers.iter().rev()`), a higher-index Byzantine helper `b` receives `RepairStart` first and returns `Ok(PeerResponse::RepairStarted)`. Next, a lower-index honest helper `j < b` receives `RepairStart` and synchronously sends `RepairMask` to every helper `k > j`, including `b` (`group.rs:525-546`):
     ```rust
        for &k in req.helpers.iter().filter(|&&k| k > self.self_index) {
            ...
            match self
                .transport
                .call(k, &PeerRequest::RepairMask(SignedRepairMask { mask, sig }))
            {
                Ok(PeerResponse::RepairMaskStored) => {}
                _ => return Err(PeerError::Unavailable(format!("helper {k} took no mask"))),
            }
     ```
     When Byzantine helper `b` refuses or drops `j`'s `RepairMask`, honest helper `j`'s `repair_start` fails, `repair_with` returns `Err(Some(j))`, and `repair()` inserts **honest helper `j`** into `failed`.
  2. **Accepting `RepairStart` without sending `RepairMask`**: Conversely, if a lower-index Byzantine helper `b` returns `Ok(PeerResponse::RepairStarted)` without having sent `RepairMask` to a higher-index honest helper `k > b`, then in Round 2 honest helper `k`'s `repair_finish` fails (`group.rs:616-621`):
     ```rust
            for &k in s.helpers.iter().filter(|&&k| k < self.self_index) {
                let (m, _) = st
                    .masks
                    .remove(&(req.session, k))
                    .ok_or_else(|| refuse(format!("no mask from helper {k}")))?;
                received.push(m);
            }
     ```
     `repair_with` receives the refusal from `k`, returns `Err(Some(k))`, and inserts **honest helper `k`** into `failed`.

  When 8 peers are online (7 honest + 1 Byzantine) and the 9th node reboots and runs `repair`, there are $\binom{8}{7} = 8$ subsets of size 7, of which **only one** contains all 7 honest peers. As soon as any subset containing the Byzantine peer is tried first (7 out of 8 subsets), 1 honest helper is added to `failed`, causing `repair()` to skip the sole all-honest 7-subset and fail with `GroupError::RepairFailed(7)`. Even when all 8 other peers hold shares (7 honest + 1 Byzantine), 1 Byzantine peer can poison multiple honest helpers across subsets until fewer than 7 non-blacklisted candidates remain.

  3. **Global `st.masks` table exhaustion**: In `GroupServer::repair_mask` (`group.rs:593-599`), masks arrive *before* the recipient's `RepairStart` session exists and share a single global map bounded by `REPAIR_CAP * self.threshold` (`256 * 7 = 1792` entries, `REPAIR_TTL = 120s`):
     ```rust
        if st.masks.len() >= REPAIR_CAP * self.threshold {
            return Err(refuse("too many repair masks"));
        }
        st.masks
            .insert((m.session, m.from), (m.clone(), Instant::now()));
     ```
     Any 1 corrupt peer holding a current boot ticket can send 1792 signed masks with random `session` IDs once every 120 seconds to every honest node, causing all legitimate `RepairMask` calls to fail with `"too many repair masks"`.
- **Suggested fix**:
  Do not permanently add `h` to `failed` when `h`'s failure can be caused by another peer in `helpers` (e.g., distinguish unreachable/unauthenticated `h` from inter-helper mask delivery/missing-mask failures, or try all $\binom{n-1}{t} \le \binom{8}{7} = 8$ combinations without cross-subset blacklisting when `n` is small; alternatively route HPKE-encrypted masks via the coordinator/requester so pairwise faults are attributable). In `GroupServer::repair_mask`, enforce a per-`from` peer quota in `st.masks` so one corrupt peer cannot starve masks from honest helpers.

---

### 3. Witness restart refetch (`WitnessClient::refetch`) persists unverified entries from any single peer into durable Tier-0 storage, allowing 1 Byzantine peer to permanently poison unused signing slots

- **Severity**: BLOCKING
- **Location**:
  - `tree/server/seald/src/witness.rs:133-161, 297-331, 362-370, 403-483`
  - `PR.md:145`
  - `tree/docs/committee-signing-mode.md:188-195`
- **Claim**: Peer witnessing tolerates `f = 2` Byzantine peers (`n = 9, w = 6`), and `PR.md` Open Item 6 (`line 145`) states only that a conflicting digest reported by a peer halts `refetch` liveness (*"One peer that reports a conflicting digest stops the refetch of a restarted node"*).
- **Reason with evidence**:
  `WitnessStore` (`tree/server/seald/src/witness.rs:59-75`) stores only `(committee, node_index, slot) -> digest` and discards the requester's `SignedWitness` signature. When a restarted node runs `WitnessClient::refetch` (`lines 448-468`), it collects `SignedWitnessLog` responses from all reachable peers and takes the **set union** of every reported `(slot, digest)` entry without requiring either a requester boot-key signature or a quorum of peers:
  ```rust
            for e in &l.entries {
                match learned.get(&e.slot) {
                    Some(d) if *d != e.digest => return Err(WitnessError::PeerConflict(e.slot)),
                    _ => {
                        learned.insert(e.slot, e.digest);
                    }
                }
            }
            answered.insert(p);
        }
        if answered.len() < self.witness_count {
            return Err(WitnessError::NotEnough {
                got: answered.len(),
                need: self.witness_count,
            });
        }
        let entries: Vec<(Slot, [u8; 32])> = learned.into_iter().collect();
        match self
            .own_store
            .record_many(t.committee, t.node_index, &entries)
  ```
  Unlike `PR.md` Open Item 6 (where two peers report *different* digests for an already-used slot and trigger a detectable `PeerConflict` halt), a single Byzantine peer (`f = 1 <= 2`) can return truthful digests for already-witnessed slots (avoiding `PeerConflict`) while appending fabricated `(future_slot, garbage_digest)` entries for any predictable or upcoming slots `(rid, g, kind)` that no honest peer has seen. Because no other peer has an entry for `future_slot`, `learned.get(&e.slot)` is `None`, `refetch()` succeeds once `w` peers respond, and `self.own_store.record_many` **durably persists** the fabricated entries into the honest node's Tier-0 witness store on `/var/lib/seald`.

  When the application later attempts to sign/witness the genuine output digest for `future_slot`, `WitnessClient::witness` checks `self.own_store` first (`lines 368-369`):
  ```rust
        // Own entry first: a node never asks for a second digest itself.
        self.own_store
            .record(t.committee, t.node_index, slot, digest)?;
  ```
  This permanently fails with `WitnessError::Conflict`. Because `own_store` lives in durable Tier-0 storage, the slot remains poisoned across subsequent reboots even after the Byzantine peer is identified and removed.
- **Suggested fix**:
  Store the requester's `boot_counter` and Ed25519 signature (`SignedWitness`) alongside `(slot, digest)` in `WitnessStore` and return `SignedWitness` entries in `WitnessLog`. During `WitnessClient::refetch`, look up the historical `BootTicket` for `(self.committee, self.node_index, entry.boot_counter)` on the `CommitteeLedger` (extending `CommitteeLedger` to query historical tickets by `(node_index, boot_counter)` or walking the `Snapshot.tickets` list) and verify the node's own historical boot-key signature on every refetched entry before persisting it to `own_store`.

---

### 4. `FollowerLedger`, `Node::boot`, and container/systemd permissions self-fence nodes on reboot, omit class-`0x03` evidence from the outbox, and block follower file access

- **Severity**: BLOCKING
- **Location**:
  - `tree/server/seald/src/ledger_file.rs:40-54, 85-98`
  - `tree/server/seald/src/fence.rs:30-50, 83-95`
  - `tree/server/seald/src/node.rs:210-253`
  - `tree/server/seald/src/main.rs:180-208, 234-237`
  - `tree/services/veritee-seald.service:28, 59, 64-65`
  - `tree/projects/committee-node/run.d/docker-compose.yml:73, 89`
  - `tree/docs/committee-signing-mode.md:616-617, 626-629`
- **Claim**: `seald`'s in-repo `FollowerLedger` interface (`committee.json` snapshot + `outbox.jsonl`) cleanly integrates with an external Midnight follower so a node can register its boot ticket with class-`0x03` evidence and survive reboots (`PR.md:50, 140-141`; `docs/committee-signing-mode.md:616-629`).
- **Reason with evidence**:
  While `PR.md` Open Item 1 discloses that the Midnight contract and follower binary are external to this repo, three defects inside the in-repo `seald`, systemd, and template files break the documented follower contract itself:
  1. **Guaranteed self-fencing (`EXIT_SUPERSEDED = 3`) on reboot when the volatile `/run` snapshot is not yet populated**:
     `FollowerLedger` defaults to `/run/veritee/midnight/committee.json` on volatile `tmpfs` (`/run`), and `seald` starts in Phase 1 before Phase 2 mounts `/mnt/persist` and starts Docker containers (`main.rs:180-208`). `FollowerLedger::read` (`ledger_file.rs:41-44`) conflates a missing or unreadable snapshot file with an empty ledger:
     ```rust
     impl FollowerLedger {
         fn read(&self) -> Option<Snapshot> {
             let b = std::fs::read(&self.snapshot).ok()?;
             serde_json::from_slice(&b).ok()
         }
     }
     ```
     When `/run/veritee/midnight/committee.json` does not exist yet on reboot, `latest_boot_ticket` returns `None` (`ledger_file.rs:48-54`), so `register_boot` (`fence.rs:38-49`) assumes this is the node's very first boot ever and mints `boot_counter = 1, prev_ticket = [0; 32]`:
     ```rust
         let prev = ledger.latest_boot_ticket(&committee, node_index);
         let ticket = BootTicket {
             committee,
             node_index,
             boot_counter: prev.as_ref().map_or(1, |t| t.boot_counter + 1),
             ...
             prev_ticket: prev.as_ref().map_or([0; 32], BootTicket::digest),
         };
         ledger.submit(LedgerRecord::BootTicket(ticket.clone()))?;
     ```
     `FollowerLedger::submit` (`ledger_file.rs:85-98`) succeeds as long as the parent directory exists (`OpenOptions::new().create(true).append(true)`), locking `Fence::own` to `boot_counter = 1`. As soon as the follower starts and writes the real finalized snapshot (where the node's prior boot already recorded `boot_counter >= 1` with a different `boot_pubkey_ed25519`), `Fence::check` (`fence.rs:88-91`) triggers:
     ```rust
             Some(t) if t.boot_counter >= self.own.boot_counter => {
                 self.superseded.store(true, Ordering::SeqCst);
                 Err(FenceError::Superseded)
             }
     ```
     `seald` immediately exits with status `3` (`EXIT_SUPERSEDED`, `main.rs:234-236`), which `RestartPreventExitStatus=3` (`veritee-seald.service:28`) refuses to restart—and `PCR 14` is already capped, permanently bricking that boot.
  2. **Class-`0x03` boot evidence is never written to `outbox.jsonl`**:
     Contract Rule 2 (`docs/committee-signing-mode.md:617`, `PR.md:141`) requires every submitted `BootTicket` to carry verified class-`0x03` boot evidence (`BootClaim` + attestation bundle). However, `Node::boot` (`node.rs:212-253`) calls `register_boot` (which appends `LedgerRecord::BootTicket(ticket)` to `outbox.jsonl`) *before* generating `LocalNodeIdentity` or calling `deps.evidence.attest(EvidenceClass::Boot, ...)`, and never writes `claim` or `boot_evidence` to `outbox.jsonl` or any socket endpoint reachable by a follower.
  3. **Filesystem permissions and `:ro` bind mount prevent a container follower from accessing `/run/veritee/midnight`**:
     No host systemd unit exists for a follower, and `rpc.midnight.example.org` is placed in the DApp container `outbound` allowlist (`projects/committee-node/metadata.json:47`). Yet `projects/committee-node/run.d/docker-compose.yml:73, 89` runs `app` as `"10001:10001"` with `/run/veritee:/run/veritee:ro`, and `services/veritee-seald.service:59` sets `UMask=0077` as `root`. Neither `/run/veritee/midnight` creation nor read/write permissions for UID `10001` exist, so a follower in `app` can neither write `committee.json` nor read `outbox.jsonl`.
- **Suggested fix**:
  Require `Snapshot` to include a finalized block height/sync marker and make `register_boot` fail with `LedgerError::Unavailable` (causing `Node::boot` to retry in `main.rs:198-208`) until `snapshot` exists and parses cleanly. Construct `BootTicket`, `LocalNodeIdentity`, `BootClaim`, and class-`0x03` `boot_evidence` first, then submit them together in an attested boot submission record in `outbox.jsonl`. Finally, pre-create `/run/veritee/midnight` in `measured_setup` with explicit ownership/ACLs and mount `/run/veritee/midnight` read-write into the follower container (keeping the rest of `/run/veritee` `:ro`).

---

### 5. Unauthenticated network attacker can exhaust `PendingMap` on `/peer/session` by replaying a captured unsigned `PeerHello`, blocking all peer handshakes

- **Severity**: BLOCKING
- **Location**:
  - `tree/server/azure_attestation_server/src/committee.rs:90-91, 157-180, 200-201, 729-755`
  - `tree/server/azure_attestation_server/src/committee/peer_client.rs:91-99`
  - `tree/server/akx/src/committee/mutual.rs:60-65, 222-264`
  - `tree/server/akx/src/session_store.rs:48-55`
  - `tree/docs/committee-signing-mode.md:107-108`
- **Claim**: Mutual `akx` over untrusted transport TLS (`danger_accept_invalid_certs(true)`) establishes peer channels reliably in the presence of a network attacker and up to `f = 2` corrupt peers.
- **Reason with evidence**:
  `tree/docs/committee-signing-mode.md:108` states: *"TLS between peers is transport only. The akx session authenticates the peer enclave and encrypts the payload"*, and `PeerClient::new` disables TLS certificate verification (`tree/server/azure_attestation_server/src/committee/peer_client.rs:93-95`):
  ```rust
            http: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
  ```
  Consequently, an active network attacker (in the stated threat model) can terminate transport TLS and read a single legitimate `PeerHelloWire` sent by any honest node. `PeerHello` (`tree/server/akx/src/committee/mutual.rs:58-64`) contains **no signature** and binds an empty nonce (`&[]`) in its class-`0x01` evidence (`mutual.rs:167-172`), so `(epoch, epoch_pub, evidence)` remains valid for the entire epoch/boot.

  In `post_peer_session` (`tree/server/azure_attestation_server/src/committee.rs:729-748`):
  ```rust
  async fn post_peer_session(
      State(state): State<PeerRouteState>,
      Json(req): Json<PeerHelloWire>,
  ) -> Result<Json<PeerReplyWire>, PeerRouteError> {
      let hello = req.to_hello().map_err(|_| PeerRouteError::Rejected)?;
      let committee = state.committee.clone();
      let (pending, reply) = tokio::task::spawn_blocking(move || {
          committee
              .epoch
              .peer_reply(committee.verifier.as_ref(), &hello)
      })
      .await
      .map_err(|_| PeerRouteError::Rejected)?
      .map_err(|_| PeerRouteError::Rejected)?;
      state
          .committee
          .responders
          .insert(req.sid, pending)
          .map_err(PeerRouteError::Store)?;
  ```
  `PendingMap` has a global cap of `PENDING_CAP = 1024` entries with `PENDING_TTL = 60s` (`committee.rs:90-91, 168-179`). Any unauthenticated network attacker who captures one valid `(epoch, epoch_public, evidence)` tuple can replay it with 1024 random `sid` values every 60 seconds to `POST /peer/session` on every honest node (and simultaneously trigger expensive P-384 + RSA + SHA-256 verification on the blocking threadpool). Once `responders` reaches 1024 entries, every legitimate peer handshake fails with `503 Service Unavailable` (`SessionError::Full`), halting witnessing, `K_grp` PRF evaluation, and share repair across the committee. Likewise, a single corrupt peer completing handshakes can fill the global `SessionStore` (`max_sessions: 10_000`, `ttl: 300s`, `session_store.rs:48-55`), which enforces no per-`peer` (`epoch_pub`) session quota.
- **Suggested fix**:
  Require `initiator_hello` to sign `(MUTUAL_HELLO_LABEL, sid, nonce, timestamp_or_cookie, epoch, epoch_pub)` with the initiator's attested Ed25519 `EpochKey` so unauthenticated third parties cannot replay a captured `PeerHello` with fresh `sid` values. Additionally, partition or cap `PendingMap` and `SessionStore` per attested `peer` (`epoch_pub`) (e.g., evicting the oldest pending/established session for that `epoch_pub` when a peer exceeds a small per-peer limit such as 8 pending / 16 established sessions).

---

### 6. X.509 certificate-chain validation and TCB floor defects in `veritee_verify` (`BasicConstraints`/`KeyUsage` omitted, PSS parameters ignored, `min_tcb.fmc` silently bypassed on v2 reports)

- **Severity**: BLOCKING
- **Location**:
  - `tree/server/veritee_verify/src/certs.rs:95-149`
  - `tree/server/veritee_verify/src/hcl.rs:182-206`
  - `tree/server/veritee_verify/src/snp.rs:268-292, 411-413`
- **Claim**: `veritee_verify` accurately validates X.509 certificate chains (`certs.rs`, `snp.rs`, `hcl.rs`) and enforces the configured `SnpPolicy` TCB floor (`PR.md:37-38`, `docs/committee-signing-mode.md:88-91`).
- **Reason with evidence**:
  1. **Missing X.509 CA / KeyUsage / critical-extension checks (`certs.rs:95-149`, `hcl.rs:182-206`)**:
     `certs::verify_signed_by` checks only `child.tbs_certificate.issuer == issuer.tbs_certificate.subject` and the cryptographic signature over `tbs_certificate`. It never inspects `BasicConstraints` (`cA == true`, `pathLenConstraint`), `KeyUsage` (`keyCertSign`), or unhandled critical X.509v3 extensions. In the public API `hcl::verify_ak_cert` (`hcl.rs:182-206`), `roots: &AzureVtpmRoots` accepts caller-supplied `intermediates`, and any non-CA leaf certificate signed by a root (or intermediate) with `cA = false` is accepted as an issuing CA if its subject DN matches.
  2. **Incomplete RSASSA-PSS parameter validation (`certs.rs:105-129`)**:
     When verifying `OID_RSA_PSS`, `certs::verify_signed_by` checks only `params.hash.oid` (`SHA-384` or `SHA-256`) and ignores `params.mask_gen` (MGF1 hash OID), `params.salt_len` (`rsa::pss::VerifyingKey::new` assumes salt length equals digest output length), and `params.trailer_field`, rejecting compliant certificates with non-default salt lengths or accepting mismatched MGF parameters.
  3. **`min_tcb.fmc` policy floor is silently skipped for version 2 SNP reports (`snp.rs:411-413`)**:
     In `SnpPolicy::check`:
     ```rust
        if let (Some(got), Some(min)) = (t.fmc, f.fmc) {
            below("fmc", got, min)?;
        }
     ```
     On version 2 reports (or version 3 reports on Milan/Genoa where `t.fmc` is `None`), if an operator configures `min_tcb.fmc: Some(min)` expecting Turin FMC enforcement (while leaving `min_report_version` at its default of `2`), `t.fmc` is `None` and the check silently succeeds instead of rejecting the report.
  4. **Order-dependent certificate selection before validity checking (`snp.rs:274-290`)**:
     `verify_vcek_chain` uses `.find(...)` to pick the first `ask` and `vcek` whose signature verifies, and runs `certs::check_validity(c, now)` only *after* `.find(...)` returns (`lines 288-290`). If a PEM bundle contains an expired/rotated ASK or VCEK ahead of a newly issued valid certificate with the same key/DN, `.find(...)` selects the expired one and `verify_vcek_chain` fails with `CertError::Validity`.
- **Suggested fix**:
  Enforce X.509 `BasicConstraints` (`cA: true` and `pathLenConstraint` on root/intermediate issuers, `cA: false` on leaf VCEK/AK certificates), `KeyUsage::keyCertSign` when present on CA certs, and reject unknown critical extensions in `certs.rs`. Validate `RsaPssParams` `mask_gen` (`id-mgf1` with matching hash) and pass `params.salt_len` via `VerifyingKey::new_with_salt_len`. In `SnpPolicy::check`, return an error when `f.fmc.is_some()` and `t.fmc.is_none()`. In `verify_vcek_chain` (and `verify_ak_cert`), check `check_validity(c, now)` inside the candidate `.find(...)` predicate.

---

### 7. Template `Caddyfile.template` omits `/enclave-key`, `/session`, and `/session/complete`, breaking documented `veritee attested-prove --committee-policy`

- **Severity**: NON-BLOCKING
- **Location**:
  - `tree/projects/committee-node/run.d/Caddyfile.template:12-31`
  - `tree/docs/committee-signing-mode.md:571`
  - `tree/docs/committee-mode.md:250-257`
- **Claim**: Operators and clients can run `veritee attested-prove --committee-policy policy.json` against a committee node deployed from `projects/committee-node` (`docs/committee-signing-mode.md:571`, `docs/committee-mode.md:255-257`).
- **Reason with evidence**:
  `cli/veritee/attested_channel.py` (`attested-prove`) fetches `GET /enclave-key` (to verify the class-`0x01` `akx` epoch key) and runs the one-way client handshake over `POST /session` and `POST /session/complete`. However, `tree/projects/committee-node/run.d/Caddyfile.template:12-30` exposes only `/tee_attestation*`, `/peer/session`, `/peer/session/complete`, and `/proxy`, falling through to static `file_server` (`404`) for `/enclave-key`, `/session`, and `/session/complete`:
  ```caddyfile
	handle_path /tee_attestation* {
		reverse_proxy attestation:8000
	}
	handle /peer/session {
		reverse_proxy attestation:8000
	}
	handle /peer/session/complete {
		reverse_proxy attestation:8000
	}
	handle /proxy {
		reverse_proxy attestation:8000
	}

	file_server
  ```
- **Suggested fix**:
  Either add `handle /enclave-key`, `handle /session`, and `handle /session/complete` reverse-proxy blocks to `projects/committee-node/run.d/Caddyfile.template` (if external one-way `attested-prove` client sessions are intended on committee nodes), or document in `committee-mode.md` and `committee-signing-mode.md` that the template restricts the attestation host to peer-only mutual `akx` routes unless those handlers are added.

---

### 8. CI workflow (`.github/workflows/ci.yml`) omits `seald`, committee-feature Rust builds/tests, and Python committee test suites

- **Severity**: NON-BLOCKING
- **Location**:
  - `tree/.github/workflows/ci.yml:103-158, 193-250`
  - `PR.md:65, 92-103`
- **Claim**: CI continuously verifies the new committee-mode crates, feature gates, and CLI/OS setup logic.
- **Reason with evidence**:
  `.github/workflows/ci.yml` adds only the `veritee-verify` job (`lines 131-158`). It has:
  - no job building or testing `server/seald` (neither default nor `--features tpm`);
  - no `--features committee` run in the `akx` job (`lines 125-129` run only default features);
  - no `--features "raw-report,committee"` build or test in `attestation-server-build` (`lines 216-230`);
  - no execution of `cli/tests/test_committee.py` (`lines 245-250` run only `test_cli_helpers.py` and `test_proxy_policy.py`) or `veritee-os/measured_setup/test_committee.py`.
- **Suggested fix**:
  Add CI jobs/steps for `server/seald` (`cargo test --locked --all-targets` and `--features tpm`), `server/akx --features committee`, `server/azure_attestation_server --no-default-features --features "raw-report,committee"`, `cli/tests/test_committee.py`, and `veritee-os/measured_setup/test_committee.py`.

---

### 9. Unchecked preconditions in public `veritee_verify` crypto helpers (`lagrange_at`, `sign_labeled`) and `--amd-roots` override in production `veritee-verify`

- **Severity**: NON-BLOCKING
- **Location**:
  - `tree/server/veritee_verify/src/prf.rs:213-231`
  - `tree/server/veritee_verify/src/witness.rs:171-186`
  - `tree/server/veritee_verify/src/bin/veritee-verify.rs:100-105`
- **Claim**: Public verification and cryptographic primitives in `veritee_verify` fail safely on malformed inputs and protect root-of-trust anchors.
- **Reason with evidence**:
  1. `prf::lagrange_at` (`prf.rs:214-231`) is a `pub fn` whose doc comment states *"for distinct node indices"*, but it uses `if j != i` by value rather than position and does not assert uniqueness:
     ```rust
     pub fn lagrange_at(indices: &[u32], x: Scalar) -> Vec<Scalar> {
         indices
             .iter()
             .map(|&i| {
                 ...
                 for &j in indices {
                     if j != i {
     ```
     If an external caller passes duplicate indices, `lagrange_at` neither panics nor returns `Result`; it silently drops the duplicate term and returns wrong Lagrange coefficients (whereas internal `seald` callers deduplicate beforehand).
  2. `BootKey::sign_labeled` and `verify_labeled` (`witness.rs:171-186`) concatenate `[label, body].concat()` without a length prefix or separator byte (`0x00`), relying on callers to choose prefix-free labels (all current in-repo labels end in `/v1` and are prefix-free).
  3. `veritee-verify` (`src/bin/veritee-verify.rs:100-105`) exposes `--amd-roots <PATH>` unconditionally in release builds installed into production OS images (`/usr/local/bin/veritee-verify`), allowing any wrapper script that passes user-controlled flags to replace the pinned AMD ARKs.
- **Suggested fix**:
  Make `lagrange_at` return `Result<Vec<Scalar>, PrfError>` (or `assert!` strict ascending/unique indices), length-prefix `label` in `sign_labeled`/`verify_labeled` (`(label.len() as u64).to_be_bytes() || label || body`), and gate `--amd-roots` behind an explicit Cargo feature or environment-disabled test flag (or emit a prominent stderr warning when used).

---

### 10. Minor undocumented changes to default (non-committee) OS behavior

- **Severity**: NON-BLOCKING
- **Location**:
  - `tree/veritee-os/mkosi/rootfs/mkosi.extra/etc/systemd/system/measured-setup.service:17`
  - `tree/veritee-os/measured_setup/main.py:921-927`
  - `PR.md:80-87`
- **Claim**: `PR.md:81-87` lists all image-level changes affecting non-committee DApps (`seal` partition, `PCR 4` change from new units and `mount-persist`, and inert binaries).
- **Reason with evidence**:
  Two small runtime behavior changes also apply to non-committee boots:
  1. `measured-setup.service:17` increases `TimeoutStartSec` from `300` to `900` seconds on all images.
  2. `committee_setup` (`veritee-os/measured_setup/main.py:922-927`) adds a hard check on non-committee boots that raises `CommitteeSetupError("persist is not mounted; a LUKS persist partition needs committee_mode")` if `/mnt/persist` is not mounted when `measured_setup/main.py` runs (e.g., if an operator formatted `/mnt/persist` or `mount-persist` skipped mounting).
- **Suggested fix**:
  Mention both behavioral adjustments in `PR.md` under **Default behavior**.

---

## What Was Checked and Found Sound

1. **Evidence-class domain separation and public route isolation (`veritee_verify/src/evidence.rs`, `azure_attestation_server/src/main.rs`, `src/committee.rs`)**:
   - `evidence_digest` frames `"veritee/evidence/v1" || class_byte || u64_be(payload.len()) || payload || nonce` (empty nonce omitted, classes `0x01`–`0x04` capped at 64-byte nonces).
   - The public HTTP attestation route (`GET /` / `/tee_attestation*`) exclusively emits class `0x00` (`EvidenceClass::Public`) in committee mode (`committee_public_route_tests` accurately verifies that arbitrary `runtime_data` or `nonce` query inputs cannot collide with classes `0x01`–`0x04`).
   - Internal classes `0x01` (`AkxEpoch`), `0x02` (`NodeKeys`), and `0x04` (`Provision`) never accept raw key bytes from socket callers; `node_keys_import` recomputes all four public keys (`X25519`, `secp256k1`, `Ed25519`, `X25519`) from the 128-byte private scalars before accepting an import.
2. **Shared vTPM NV-index serialization (`azure_attestation_server/src/committee.rs:135-154`, `src/vtpm.rs`, `guest_attestation/veritee_attestation/tpm_quote.py`)**:
   - `SerializedAttester` serializes concurrent attestations across HTTP and Unix-socket callers so writes to NV index `0x01400002` and vTPM quotes under AK `0x81000003` cannot interleave.
   - `tpm.rs` (`veritee_verify`) checks `TPM_GENERATED_VALUE` (`0xff544347`), `TPM_ST_ATTEST_QUOTE`, RSA-2048 RSASSA-PKCS1-v1_5 SHA-256 signature against the HCL report's `HCLAkPub`, exact `extraData == evidence_digest`, SHA-256 PCR bank selection, and exact `pcrDigest == SHA-256(concat(selected_pcrs))`, refusing empty PCR policies.
3. **Threshold PRF, Chaum-Pedersen DLEQ proofs, and `SealedToNode` (`veritee_verify/src/prf.rs`, `src/sealed.rs`, `seald/src/group.rs`)**:
   - `hash_to_point` implements RFC 9380 `expand_message_xmd` (SHA-512, 64 uniform bytes) into `RistrettoPoint::from_uniform_bytes` with domain separation `"veritee/prf-h2c/v1"`.
   - `decode_point` enforces canonical 32-byte Ristretto encodings and explicitly rejects the identity element; `decode_scalar` enforces canonical mod-$\ell$ scalars.
   - Chaum-Pedersen DLEQ proofs bind `(B, H(x), S_j, y_j, A_1, A_2, partial_context)` in length-framed Fiat-Shamir challenges, and `GroupClient` verifies every DLEQ proof against the ledger's epoch commitment `S_j` before Lagrange interpolation.
   - `SealedToNode` uses RFC 9180 HPKE Base mode (`X25519HkdfSha256`, `ChaCha20Poly1305`) binding recipient slot (`0x01` node / `0x02` provision), `committee`, `epoch`, `node_index`, `boot_counter`, and application `context` into both HPKE `info` and AEAD `aad`.
4. **Mutual `akx` transcript and tunnel isolation (`akx/src/committee/mutual.rs`, `azure_attestation_server/src/proxy_routes.rs`)**:
   - `mutual_transcript` and `finish_hash` use 64-bit big-endian length prefixes on every field, reject self-reflection (`hello.epoch_pub == own_pub`), bind both peers' epochs and Ed25519 keys plus the responder's ephemeral X25519 KEM key and HPKE `enc`, and derive directional ChaCha20-Poly1305 record keys with distinct export labels and non-overlapping sequence counters.
   - `proxy_routes.rs` strips caller-supplied `x-veritee-peer-akx` headers on one-way client sessions and routes `/veritee/seald/peer` exclusively when `session.peer.is_some()`.
5. **vTPM sealing, PCR14 cap ordering, Tier-0/Tier-1 encryption, and secret hygiene (`seald/src/tpm.rs`, `src/store.rs`, `src/harden.rs`, `src/api.rs`, `src/main.rs`)**:
   - `TpmSealer` seals 32 random bytes (`K_tpm`) under `PolicyPCR(4, 14, 15)` (SHA-256 bank) with empty auth, caps `PCR 14` with `SHA-256("veritee/seal-cap/v1")` immediately after unsealing (verifying the post-extend PCR value), and `main.rs` binds `/run/veritee/seald-admin.sock` only *after* `Local::open_and_cap` succeeds.
   - `api.rs` enforces `SO_PEERCRED` UID checks (`uid == 0` on `seald-admin.sock` and `seald-peer.sock`, `uid == app_uid` on `seald.sock`), with atomic `0700` parent directory and `0600` socket permissions.
   - `store.rs` encrypts Tier 0 (`K_tpm`) and Tier 1 (`K_seal = HKDF(K_tpm || K_grp || ratchet)`) with ChaCha20-Poly1305 using fresh 32-byte random per-write HKDF salts, domain-separated AAD binding `(tier, generation, epoch, name)`, and atomic write + `sync_all` + rename + directory `sync_all` on `destroy` and `rekey`.
   - Secret wrappers (`KeyBytes`, `LocalKey`, `PrfShare`, `BootKey`, `NodeKeySecrets`) implement `Zeroize`/`ZeroizeOnDrop` and redacted `Debug` impls; `harden.rs` and `measured_setup` apply `PR_SET_DUMPABLE(0)`, `RLIMIT_CORE = 0`, `mlock`, and `swapoff --all`.
6. **Packaging, PCR14/PCR15 parity, Terraform, and non-committee gating (`cli/veritee/committee.py`, `veritee-os/measured_setup/main.py`, `cli/deploy-azure-snp/*`)**:
   - `expected_pcr14`, `capped_pcr14`, and `post_setup_pcr15` match byte-for-byte across `cli/veritee/committee.py`, `veritee-os/measured_setup/main.py`, and `seald/src/tpm.rs`.
   - Both packaging and guest runtime setup reject `maa`, `azure_vault` / `tls_keyvault_name`, `egress_profile`, missing `ulimits.core: 0`, and `/dev/tpmrm0` outside `guest-attestation`; `create-vm` sets `enable_managed_identity = false` in committee mode.
   - Apart from the minor items noted in Finding 10 and the documented `seal` partition / `PCR 4` / inert binary additions, non-committee DApps follow the existing packaging and boot paths.
