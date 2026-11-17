# The first shard in Midnight Passport

Passport is commit `9906267` of `midnightntwrk/passport`. The protocol is split-line dealing, `design/enhancement/DESIGN.md`. Paths that begin with `docs/`, `contract/` or `experiments/` are Passport paths. `DESIGN.md` and `tpm.rs` are ours.

## Verdict

The first shard works in Passport as a **wrapped shard root**. It does not work as a passkey-held key, and it does not work as a copy of the seald TPM sealer.

1. The user holds one 32-byte secret per Passport account, the **shard root** `r_u`. Every user-held value of the single-user form derives from it: `x_u` and the tweak seed of each address, the receive key `u`, and `K_exit`.
2. The root is random. The wallet wraps it once for each enrolled passkey, to an X25519 key derived from that passkey's WebAuthn PRF output, and stores each 192-byte wrap in the Passport account inbox. This is the reader-envelope construction that Passport already runs for its viewing secret (`experiments/inbox-view-envelope/README.md:49-60`, `:139-143`).
3. Each spend takes two user-verified ceremonies on one passkey. A PRF evaluation unwraps the root, and the wallet computes the contribution of §4 and erases the root. A plain ES256 assertion then authorizes the intent on Midnight (question 2).
4. A native wallet replaces the PRF-derived key with a P-256 key in the Secure Enclave or StrongBox that demands a biometric for every use. That is the part of the TPM design that carries over.
5. ECDSA slot halves never enter an envelope. They are single-use state of one device.
6. Passport's guardian quorum receives one more wrap of the root. That makes the quorum an OR branch of the user leaf. The recovery group `E` stays what it is: the backup of `x_f`.

The recommended launch is on the Schnorr suites (Bitcoin P2TR, Solana). There the user half is stateless, and every device that can unwrap the root can sign. Ethereum and P2WPKH follow once slot state has a rollback rule on a phone.

## 1. Where the shard can live

### What the wallet holds

The launch form is `x = x_u + x_f + tw`, with the holder's wallet as the only actor (`DESIGN.md:26`, `:51`). The wallet holds more than one scalar:

| Item | Source | Kind |
|---|---|---|
| `x_u` | fresh for every address and change address (`DESIGN.md:67-68`, `:165`) | derivable |
| tweak seed | 32 bytes per address (`DESIGN.md:185`) | derivable |
| receive key `u` | one per charter; `x_u = u + Hq_st(u·E_c)` with `E_c` in the Midnight record (`DESIGN.md:76`, `:180`) | derivable |
| `K_exit` | per Bitcoin address, optional (`DESIGN.md:75`) | derivable |
| initiator nonce `k_0` | fresh per half, hedged (`DESIGN.md:282`, `:401`) | no state |
| ECDSA halves `(w_u, μ_u)` | output of the interactive slot session, one message per slot (`DESIGN.md:83`, `:397`) | random, single-use state |
| owner spend key | signs `ic` for `authorize` (`DESIGN.md:77`, `:561`) | replaced, question 2 |

Two facts decide the placement. The Schnorr single-user form keeps no state: the initiator draws no pool pair and uses a fresh nonce per half, so two devices that hold the same `x_u` never share a nonce. The ECDSA form is the opposite. Two contributions on one slot reveal `(w_u, μ_u)`, and the actor's refusal is the only defence against a corrupt committee: "The actors' rule holds against a fully corrupt committee. The board rule does not" (`DESIGN.md:397`).

### What a passkey gives

A passkey signs ES256 over a WebAuthn envelope and exports nothing (`experiments/p256-in-circuit/README.md:15-23`). The hardware behind it is P-256 only. Apple's Secure Enclave "works only with NIST P-256 elliptic curve keys" [S5]. Android StrongBox supports RSA 2048, AES, HMAC-SHA256 and "ECDSA, ECDH P-256" [S6]. No retail secure element computes `c·x_u` on secp256k1 or edwards25519. A platform key store that offers a standard Ed25519 key does not help: a standard signer picks its own nonce and signs under its own key, so it cannot produce a half-signature under the shared key `X`. The shard scalar therefore exists in application memory at the moment of use in every option below. The options differ in what guards it at rest and in who can ask for it.

The PRF extension returns 32 bytes per credential and input. The browser hashes the input under the prefix `"WebAuthn PRF"`, and on CTAP authenticators the PRF "MUST be the one used for when user verification is performed" [S1]. The output goes to the page: `results` is a client extension output. The authenticator enforces user verification for a PRF evaluation. Nobody enforces what the page does with the output afterwards.

### Platform support in 2026

The PRF rows come from Corbado's tables of August 2026, which are a vendor's own tests [S2][S3].

| Platform | PRF from the platform passkey | Passkey kind |
|---|---|---|
| iOS and iPadOS 18.4+ | yes, iCloud Keychain, every browser (WebKit) | synced |
| macOS 15+ | yes: Safari 18+, Chrome 132+, Firefox 139+ | synced |
| Android | yes, Google Password Manager: Chrome, Edge, Samsung Internet, Firefox 149+ | synced |
| Windows 11 24H2/25H2 with the February 2026 update | yes, Windows Hello: Chrome/Edge 147+, Firefox 148+ | device-bound |
| Windows 10 | no | — |
| Security keys (hmac-secret) | yes; on Safari from 26.4, with two open WebKit bugs | device-bound |
| Third-party managers | 1Password, Proton Pass, Keeper, Enpass yes; Bitwarden split by platform; Dashlane and NordPass no | synced |

A synced passkey is meant to return one PRF output on every device. Apple's engineer says so on the developer forum: "the prf should be identical in this case." The same thread carries reports from April to July 2026 of different outputs between iPhone and Mac, and of an iOS 18.6 device that cannot reproduce the output of a passkey created on iOS 26. It shows no fix [S4]. `largeBlob` is weaker ground: Windows Hello and every third-party manager decline it, and Chrome on Android does not forward it [S3]. Passport never uses `largeBlob`: the string does not occur in the repository.

Passport itself has no real-browser PRF evidence. Its envelope run uses "software ES256 credentials and synthetic PRF outputs" (`experiments/inbox-view-envelope/README.md:8-11`; `docs/plans/STATUS.md:41-48`). The PRF support matrix and the fallback policy are open in C9 (`docs/plans/components/C9-device-bound-authentication.md:61-67`).

### The options

**(a) Derive `x_u` from the PRF output.** This is Passport's own first design for its JubJub device key: the PRF output for the salt `midnight:passport:prf:device:v0` is the device secret, "re-derived on every visit" (`experiments/account-custody-prototype/app/src/lib/passkey.ts:14`, `:72-93`; `docs/protocol-flows/01-first-account-creation.md:39-43`).

- *Theft.* A thief needs the device and its unlock.
- *Malicious server.* The wallet origin's script receives the PRF output. One unlock gives a malicious origin the root for good.
- *Synced provider.* A party that takes over the user's passkey account evaluates the PRF.
- *Recovery.* None beyond the provider's sync. A second passkey has a different PRF, so it derives a different `x_u`, and `X` is fixed at birth. A deleted passkey deletes the shard, and a P1 charter whose only actor disappears traps the funds (`DESIGN.md:42`).
- *Our side.* A derivation rule for `x_u`.

Option (a) fails on recovery and on the second device. It also rests on cross-device PRF equality, which fails in the field between Apple OS versions [S4].

**(b) Wrap a random root under a PRF-derived key.** The root is independent of any passkey. Each passkey derives a reader key (`PRF → HKDF → X25519`) and opens its own wrap. Theft, malicious-server and provider exposure equal those of (a) for each enrolled passkey. Recovery is open-ended: any number of passkeys from any ecosystem, a hardware key, a guardian wrap. A wrap on the device alone dies with the device, so the store matters, and that is option (d). Our side needs the same derivation rule.

**(c) Seal in a device TPM or secure enclave.** The seald sealer puts 32 bytes in a TPM keyed-hash object under `PolicyPCR` over PCR 4, 14 and 15, with `fixed_tpm`, `fixed_parent`, `no_da` and `user_with_auth(false)` (`tpm.rs:177-190`, `:329-336`). After the one unseal of a boot it extends PCR 14, "so no later process in the same boot can unseal again" (`tpm.rs:394-404`; `DESIGN.md:865`). Set beside a retail device:

| seald property | On a phone or in a browser |
|---|---|
| a 32-byte secret sealed to hardware, an opaque blob on disk, bound to one device | **carries over**: a Secure Enclave or StrongBox P-256 key wraps the root, and the key cannot leave the device |
| policy = measured image (PCR 4, 15) | **breaks**: an app controls no PCR, and a browser reaches no TPM. The policy becomes user verification per use (an access-control flag such as `biometryAny` on Apple [S5]; per-operation authorization in Android Keystore [S6]) |
| no user authentication in the policy | **inverts**: user verification is the whole policy |
| one unseal per boot, then the secret stays in RAM (PCR 14 cap) | **inverts**: one unseal per spend, erased after the contribution |
| `K_tpm` is replaceable; sessions reopen in a replacement VM from peer partials (`DESIGN.md:870`) | **breaks**: `x_u` is in `X`. A lost shard is lost funds |
| rollback protection comes from the peer witness, not from the TPM (`DESIGN.md:867-870`) | **missing**: a phone has no witness. This matters for ECDSA slot state |

The TPM design carries over as a storage layer for a native wallet. It is the best profile against theft and the only one that keeps the root away from a web origin. It needs an installed app, so it is one reader kind among several, and it brings no recovery.

**(d) Hold the wrap in the Passport account.** The account inbox is an opaque `Bytes<192>` map with authorized append. Passport already stores one wrap of its viewing secret per reader there, and a fresh client restores from the account address alone (`experiments/inbox-view-envelope/README.md:17-19`, `:104-119`, `:167-182`). The same record under a new type carries the shard root. Recovery of authority through `recover_submit` and `recover_finalise` then needs one more wrap, to a key derived from the guardians' reconstructed secret. That is the recovery-group recipient that Passport proposes and has not built (`experiments/inbox-view-envelope/DISCUSSION.md:127-155`; `docs/plans/STATUS.md:46`). The root must not be the viewing secret or a child of it: a scoped grant with `read = true` hands the viewing secret to a dApp (`docs/mps-mip/mips/mip-xxxx-scoped-grants.md:1370-1393`).

**(e) What else the repository suggests.**

- *A committee as one device.* A FROST committee, or an MPC or HSM signer on the k256 arm, registers as a single device (`docs/plans/components/C5-signing-primitive.md:42-46`; `docs/plans/components/C1-account-custody-contract.md:60-68`). That is authorization. It places no shard.
- *The managed path.* The passkey authenticates to an MPC service that holds the key (`docs/plans/components/C9-device-bound-authentication.md:35-40`). Passport retires it because the operator becomes a required service (`docs/plans/components/C5-signing-primitive.md:197-203`).
- *Shamir with reconstruction in a device enclave* (`docs/reference/machine-investigation/mpc-candidates-nightstream.md:21-57`). The key is whole at signing time. Split-line dealing exists to avoid that.

### The placement

Options (b), (c) and (d) are one design. The root is wrapped per reader. A reader is a passkey (PRF) or a device enclave key. The wraps live in the account inbox.

| | Web wallet, passkey reader | Native wallet, enclave reader |
|---|---|---|
| iOS, Android, macOS | yes | yes |
| Windows 11 | yes after the February 2026 update | TPM through the platform key store |
| Windows 10, Dashlane, NordPass | no PRF: a hardware key or the native wallet | — |
| Stolen locked device | safe | safe |
| Stolen unlocked device, or known PIN | root and credential exposed | root and credential exposed |
| Malicious wallet origin | root exposed at first unlock; it sets the challenge of each later approval | not reachable |
| Passkey provider takeover | root and credential exposed | credential exposed, root not reachable |
| Fully corrupt committee alone | holds `x_f`, completes only dealt variants (C3, `DESIGN.md:1040`) | the same |

A root holder still needs the committee half and an authorization in force. The authorization is a second factor, and it stays in the authenticator. Question 2 states what it stops.

One limit stands. A web wallet's origin sees the root. If the party that serves the wallet page also directs `t` committee nodes, that party holds the whole key of every web user. Co-custody on the web holds against operators distinct from the origin. The native reader, a self-hosted client under Passport's own substitutability promise, or a reproducible extension removes the overlap.

## 2. Authorization

A passkey assertion is a valid charter predicate, and it binds to `ic`.

The owner source of §5.3 is "a signature over `ic` by the Midnight spend key of an actor the charter admits as initiator" (`DESIGN.md:561`). Passport verifies exactly such a statement in Compact 0.35. The `p256` arm reconstructs every byte of the 134-byte client data, including the base64url of a 32-byte challenge. It checks `rpIdHash`, requires the user-presence and user-verification flags, and verifies ECDSA over `SHA-256(authenticatorData ‖ SHA-256(clientDataJSON))` (`contract/WEBAUTHN.md:13-19`, `:43-52`). The challenge is 32 bytes that the relying party chooses. Set

`challenge = H("SL1/passport-auth" ‖ charter_id ‖ ic ‖ nf)`.

The assertion then authorizes one intent on one record state. `nf` gives freshness, because Midnight accepts one `authorize` per `nf` (`DESIGN.md:586`). Passport's own freshness uses `auth_nonce` and a rolling device entry in the same role (`contract/WEBAUTHN.md:54-58`). The circuit proves user verification on every spend, which no software key can prove.

Three consequences follow.

1. **Two factors, with a stated reach.** The root is extractable software. The P-256 key is not. With an honest committee the assertion stops a guardian quorum that read the root and a removed device that kept it: neither holds an enrolled credential. It does not stop the thief of an unlocked device or the provider of a synced passkey, because the credential falls with the root. It limits a malicious web origin and does not stop it: WebAuthn shows the user no intent, so the origin sets the challenge, and each approval gesture of the user authorizes one intent of the origin's choice. A native wallet closes that case.
2. **Verify inside `authorize`.** The charter record holds a commitment to each enrolled credential `(pk, rpIdHash, origin)`, as Passport's device entry does (`contract/WEBAUTHN.md:89-91`). `authorize` still publishes `auth`, `nf`, `rh` and a proof, and nothing else (`DESIGN.md:550`). The other route is a cross-contract call into the account contract. It would name the Passport account next to every Fenrir authorization and end the unlinkability of §6.3.
3. **Midnight-first only.** A charter whose credential set changes on Midnight reads mutable state, so `board_first` is not available (`DESIGN.md:588`, `:596`).

The `wa-json134` profile accepts 37-byte authenticator data with no extension output, so Passport runs the PRF ceremony and the signing ceremony apart (`experiments/inbox-view-envelope/README.md:249-252`). A spend therefore costs two prompts. One prompt is reachable: `ic` does not depend on the contributions, so one assertion over `H(… ‖ ic ‖ nf)` that also carries the PRF evaluation yields both. It needs a profile that accepts that authenticator data, and nobody has measured one. The profile also fixes the origin at 21 bytes (`contract/WEBAUTHN.md:22-29`). Proving the P-256 gate took 27 s on an 8-CPU host in Passport's one live run (`experiments/passkey-account-flow/README.md:41-44`).

Passport's PRF-to-JubJub path can also sign `ic`, in software. It then derives the authorization key and the shard from one unlock, and the second factor is gone.

## 3. Recovery

Passport has three flows. Each maps to a different part of our structure.

**Several devices.** Each Passport device is an independent credential, and a live device enrolls the next (`docs/arc42.md:300-304`). Each device receives its own wrap of the one root and registers its own credential commitment in the charter. Several shards are not needed. The DESIGN OR gate already means "each child holds the whole gate secret" (`DESIGN.md:145`), and a wrap is that escrow without a dealing. For ECDSA an escrow of `x_u` alone is useless (`DESIGN.md:263`), so a new device runs a slot refill session as the user party and owns the slots it creates.

**Total loss.** Guardians reconstruct the recovery secret, `recover_submit` records a successor, a live device can veto, and `recover_finalise` retires every prior device (`docs/arc42.md:326-333`). The successor needs the root, so the guardian quorum `R` holds a wrap.

The access structure is

`Fenrir AND ( d_1 OR … OR d_m OR R )`, and in P2 `Fenrir AND ( d_1 OR … OR d_m OR R OR G )`.

The committee sees the single-user form throughout: `|A| = 1`, `S = {user}`, no pool pairs and no collection. The OR sits inside the user leaf. The authorization predicate is the matching disjunction over credentials.

**`E` is not `R`.** `E` holds `x_f` at 3 of 5 and "holds no shard" (`DESIGN.md:273`). `R` holds the user side and no part of `x_f`. Recovery never puts the key in one place while the two stay apart. A quorum of `R` together with three members of `E`, or with `t` nodes, holds the whole key. A Passport guardian service run by a committee operator or by an `E` member is that collusion by default, so a charter forbids the overlap as it does for `G` (`DESIGN.md:56-57`).

Three limits follow from Passport's design.

- The veto window guards authority, not the wrap. A guardian quorum reconstructs the recovery secret off-chain at any time (`docs/plans/components/C15-helper-protocol.md:54-58`) and reads the root. With an honest committee it still cannot spend without `recover_finalise`.
- Removing a device revokes its credential. It does not make the device forget the root. Passport's own `remove_device` is incomplete as well (`contract/README.md:400-407`). After a suspected compromise the user sweeps to addresses under a new root.
- Finalization rotates the recovery key and clears the guardians' public vector (`contract/DORMANT-RECOVERY.md:64`). The root's guardian wrap is republished after every finalization, as the viewing wrap is.

**Chain recovery and dormant recovery.** Chain recovery rebuilds holdings from the account address, viewing keys and chain data, with no device (`contract/CHAIN-RECOVERY.md:7-12`). Our analogue rebuilds the address list from the shielded asset records, which is why the tweak seed derives from the root or sits encrypted in the record. ECDSA halves do not come back, and the recovered device refills. Dormant recovery, before first activation (`contract/DORMANT-RECOVERY.md:9-14`), is our unacknowledged network-created address: the recovered holder derives `u` from the root and sends the acknowledgement (`DESIGN.md:192`).

## 4. The C25 slot

C25 expects an upstream "MCS (Multi-Chain Signature) scheme — threshold-Schnorr forking NEAR-MPC", a solver network and an Intent Escrow Contract. Passport hands off "user-signed trade intents" and consumes settlement confirmations (`docs/plans/components/C25-cross-chain-integration-interface.md:10-14`, `:27-33`). The user "signs the trade intent in JubJub, MCS handles the foreign-chain side" (`docs/plans/components/C5-signing-primitive.md:118-122`). In the NEAR model the network alone holds the key and derives each address by a public tweak of the account id (`docs/reference/machine-investigation/near-mpc-chain-signatures.md:19-33`, `:104-123`).

Split-line dealing fills the signer slot for the user's own foreign-chain addresses, and it is the stronger signer:

| C25 question | NEAR-MPC shape | Split-line dealing |
|---|---|---|
| Who can sign | the committee alone | the committee and the user's shard, never either alone |
| Chains | threshold Schnorr, with OT-based ECDSA in NEAR itself | BIP340, Ed25519 and ECDSA from one committee key per curve |
| Cross-chain identity (`:80-84`) | public derivation from the account id; C25 names the linkage as a failure mode (`:108-111`) | a fresh shard and a secret tweak per address; shielded records |
| Settlement notification (`:62-65`) | callback | the settlement leaf under `settle_root` on Midnight |
| Failure semantics (`:67-69`) | upstream | FINAL, VOID, EXPIRED, RELEASED (`DESIGN.md:524-527`) |
| Loss of every device mid-trade (`:91-93`) | upstream | a dealt request completes without the user; a reissue needs the recovered root |
| Substitutable committee (`:76-78`) | one named committee | `E` reprovisions a successor; the exit leaf on Bitcoin |

It does not fill the slot unchanged. A contribution is a half-signature over an exact sighash, so the wallet builds the transaction and its fee grid. A declarative intent that a solver routes later has no sighash yet. Two shapes work.

- **Quote, then sign.** The solver quotes, and the user's one move is the envelope for the foreign leg. The admitted source of its `authorize` is the state of the Intent Escrow Contract. The offline move is the signed intent.
- **Pooled vaults.** A vault with no user behind it needs an actor. The solver, or an escrow policy actor, holds the shard: `Fenrir AND solver`. DESIGN defines no such profile.

The hand-off Passport calls:

```
register(charter: P1, Γ = user, credentials, U, pop_U)      once per account
birth(chain)                         -> cm_addr, BIRTH envelope
prepare(intent)                      -> ic, variants, slots
unlock()        PRF ceremony         -> contributions, envelope (hd, tkc)
approve(ic, nf) ES256 assertion      -> assertion
authorize(proof; auth, nf, rh) + post(envelope)
status(eid)                          -> state, settlement leaf
```

`docs/reference/machine-investigation/mpc-technique.md` and `docs/reference/human-investigation/mpc.md` concern general MPC that settles into a proof system. They set no requirement on the signer.

## 5. Gaps

| Rank | Gap | Change in | Recommended option |
|---|---|---|---|
| 1 | The web origin sees the root, and the committee's sponsor may run it | Passport | ship the enclave reader in a native wallet as the custody-grade profile; a charter states which reader kinds it admits |
| 2 | `authorize` has no passkey source | DESIGN §2.2, §5.3, §14.3; Passport | owner source = ES256 assertion over `H(charter_id ‖ ic ‖ nf)`, verified inside `authorize` against credential commitments; reuse `webauthn.compact` |
| 3 | `x_u` and the tweak seed are specified as random (`DESIGN.md:179`, `:185`) | DESIGN §3.1 | derive `x_u`, the seed, `u` and `K_exit` from the root by a domain-separated hash-to-scalar; keep random shards for other actors |
| 4 | ECDSA halves sit on a device with no rollback fence | DESIGN §3.6, §4.4 | launch Passport on Schnorr suites; for ECDSA, slots belong to one device, are never wrapped or synced, and a restored device burns its slots and refills |
| 5 | The recovery-group wrap does not exist in Passport | Passport | build the recovery-group recipient for the shard root with the viewing one; the charter forbids overlap of `R` with `E` and with operators |
| 6 | Credential-set changes and recovery do not reach the charter | DESIGN §5.3 | a `rekey` transition authorized by a live credential, or by the Passport account after `recover_finalise` |
| 7 | Revocation does not erase the root | DESIGN §2.4; wallet | sweep to a new root after a suspected compromise |
| 8 | Two prompts per spend; fixed 21-byte origin | Passport | measure the one-ceremony profile (PRF and assertion over `ic`) |
| 9 | No real-browser PRF evidence; Apple cross-device inconsistency; no PRF on Windows 10 | Passport C9 | per-passkey wraps make sync equality unnecessary; a hardware key or the native wallet where PRF is absent |
| 10 | No vault profile for solver settlement | DESIGN §2.4; C25 | define `Fenrir AND policy actor`, or state the scope as user addresses with quote-then-sign |
| 11 | The ECDSA birth session needs the user online, and O1, O2 and O19 are open (`DESIGN.md:226`) | DESIGN | Schnorr first |

## 6. The checked model

`SHARD-SPEC.md` states this placement as a state machine with 66 requirements, and `formal/passport-shard/lean` holds its Lean model. The cryptography is abstract: each primitive is a named hypothesis. Lean proves these statements for every interleaving of honest and adversarial operations.

- A coalition that never entered the user leaf signs only the intents that a user-verified unlock dealt. This holds with a fully corrupt committee and a corrupt `E`. A corrupt committee completes those dealt intents without an authorization.
- Without the committee half, every signature has an authorization in force and an assertion over exactly its `(ic, nf)`. One `nf` authorizes one intent.
- Every signature rests on a user-verified PRF evaluation, with three exceptions that the model names: the provider of a synced passkey, a guardian quorum, and an honest recovery on a corrupt origin. With device-bound readers and no recovery wrap there is no exception.
- No Passport recovery operation and no reprovision by `E` gives the adversary the committee half. With an honest origin and fewer corrupt guardians than the quorum, none gives the root. A reprovision by `E` changes committee state only.

The model has no ECDSA slot state and no time.

## Sources

- [S1] W3C, *Web Authentication Level 3*, Recommendation of 25 August 2026, §10.1.4. https://www.w3.org/TR/webauthn-3/#prf-extension
- [S2] Corbado, "Passkeys & WebAuthn PRF for End-to-End Encryption (2026)", modified 29 September 2026. Vendor tests. https://www.corbado.com/blog/passkeys-prf-webauthn
- [S3] Corbado, "WebAuthn L3 Support in Credential Managers", modified 3 October 2026. Vendor tests. https://www.corbado.com/blog/webauthn-l3-credential-manager-support
- [S4] Apple Developer Forums, "same passkey synced on 2 devices generate different prf outputs for the same salt", April to July 2026. https://developer.apple.com/forums/thread/822523
- [S5] Apple, "Protecting keys with the Secure Enclave". https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
- [S6] Android Developers, "Android Keystore system". https://developer.android.com/privacy-and-security/keystore
