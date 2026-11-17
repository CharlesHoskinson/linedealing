Written to [PROPOSAL.md](/home/hoskinson/Projects/mpcexperiments/design/enhancement/astra/PROPOSAL.md).

# Sealed co-signing behind a private execution board

## 1. Summary

Fenrir replaces owner-held address keys with joint keys. The wallet holds one signing factor. Fenrir holds a threshold sharing of the other factor. Address creation includes an interactive setup that prepares signing material. At spend time, the owner sends one encrypted message containing sealed, message-specific contributions to joint signatures and goes offline. Every variant spends the same pinned input or account nonce. Fenrir completes only a variant that Midnight authorizes.

The central change is to **deal the user's finished contribution to a joint signature**. Fenrir never receives the user's reusable signing factor. The owner never knows the controlling private key or the complete signing nonce. This preserves sealed line dealing's confinement to an enumerated transaction family while removing the owner's direct-spend bypass. It requires joint-signature preprocessing, which the current scheme deliberately avoids.

Both execution modes use the same address records, ciphertext envelopes, ordering certificates, authorization relation, nonce reservations and settlement receipts:

- **TEE mode:** Veritee runs the node, mempool, policy interpreter, signing code and erasure service inside an attested confidential VM. Threshold decryption opens an ordered request only inside approved VMs. Operators receive commitments and operational metadata.
- **Non-TEE mode:** the same decryption and signing interfaces execute through malicious-secure MPC. Decryption produces secret-shared plaintext. The MPC checks the authorization relation and completes the signature without opening the request to operators. Replacing Veritee does not change addresses or the owner's message semantics.

R1 means that a spend needs one of the charter's three authorization sources: unanimous principal intent, a qualifying seizure, or the owner's standing exit record. A Midnight authorization consumes a private asset nullifier and binds the exact transaction commitment. A legal hold ordered before that authorization blocks the owner's payment and exit routes. A signature already released to a public chain cannot be recalled.

The proposal retains two algebraic custody factors at launch. It also requires independent legal trustees for owner-absent seizures and independent recovery trustees for loss of the Fenrir committee. These are separate organizations with separate escrow holdings. Neither receives the whole address key. Their availability and integrity are additional assumptions.

The full brief is not simultaneously achievable with ordinary native-chain signatures. In cryptography-only mode, a fully corrupt Fenrir committee can complete previously supplied user contributions without checking Midnight. Public Bitcoin inputs and account-chain senders expose funding relationships. An unconditional exit after all policy services disappear cannot also enforce subsequent legal holds. The requirement table records these limits. TEE mode enforces authorization against all malicious operators while the measured code and hardware remain intact. Non-TEE mode enforces it under the stated committee bound and retains cryptographic confinement of the sealed user contribution even when every Fenrir node is corrupt.

The selected design uses privileged-user joint signing. A network-only threshold signer loses R1 against total network compromise. Dealing an open user key line loses the separation of custody factors. A mandatory independent third signing factor strengthens policy enforcement but changes the two-key launch requirement.

## 2. Key and address model

### 2.1 Parties and thresholds

Use `Q` for the board quorum and `ell` for a signature curve's scalar order.

| Profile | Nodes `n` | Byzantine bound `f` | Board quorum `Q` | Custody and decryption threshold `t` |
|---|---:|---:|---:|---:|
| Launch | 9 | 2 | 6 | 7 |
| Later | 17 | 5 | 12 | 12 |

`Q = ceil((n + f + 1)/2)` and `t = n - f`. Ordering votes and cryptographic shares have different purposes. Six launch votes never reconstruct a seven-share secret.

The logical signing policy is `USER AND t-of-n FENRIR`. This is not a flat threshold among the user and nine nodes. Such a threshold could admit a network-only signing set.

For ECDSA, write the key as `x = u + v mod ell`. The wallet holds `u`. Fenrir holds verifiable shares `v_i` of `v`. The public key is `X = U + V`, with `U = uG` and `V = vG`. Schnorr suites use their specified aggregation coefficients and parity rules. For Taproot, `X` includes the BIP327 aggregation and BIP341 tweak. Neither party reconstructs `x`.

Separate keys serve separate purposes: custody shares, threshold-envelope decryption shares, board signing keys, transport keys and storage keys. A board certificate does not authorize arbitrary use of a custody share.

The architecture follows the privileged-client distinction in 2PC-MPC and Ika. Ika also distinguishes joint key generation from importing an existing key whose owner retains a direct-spend capability. This proposal uses joint generation only. [Ika whitepaper, §§3.1–3.2](https://docs.ika.xyz/whitepaper.pdf)

### 2.2 Address creation

1. The wallet generates a fresh scalar `u` and proves possession of `U`. It supplies an authenticated return-encryption key and commits to its charter, principals and standing exit record. This uses the wallet-supplied-share option in R3. Fenrir does not generate `u` and then promise to forget it.
2. Fenrir runs malicious-secure verifiable DKG for `v`. Contributions include proofs of possession and consistency. The DKG rejects identity points, invalid encodings and rogue-key substitutions.
3. The parties complete the selected two-party signing setup, treating the threshold network as one logical party. They verify the public key, suite, chain identifier and address encoding.
4. During this same setup, they prepare a finite pool of one-use signing slots. ECDSA slots contain the user's presignature state and threshold-shared network presignature state. Schnorr slots contain the network's committed nonce pairs. The wallet receives the authenticated public transcript and its private setup outputs through an authenticated encrypted channel.
5. Midnight registers a hiding commitment to the address record. Its private fields include `X`, the charter, custody epoch, user credential, trustee registrations and setup-transcript digest. An address becomes fundable only after setup, escrow and data-availability checks complete.

The wallet prepares a pool of fresh user factors and destination/change addresses during setup. Each funded successor address uses a new factor and a new network DKG. A returning owner can set up more addresses. A recipient can prepare addresses independently. Exhausting the prepared pool requires another setup session before a later spend. It never causes a signing round after an already submitted spend request.

There is no master user secret shared with Fenrir and no requirement that the wallet expose a public derivation path linking its addresses. Setup traffic itself still needs anonymity measures.

### 2.3 Native chain representation

| Chain | Native representation | Adapter rules |
|---|---|---|
| Bitcoin P2TR | One BIP340 output key and one key-path signature per input | BIP327 logical user/network signing. Apply all key and nonce parity adjustments. Use a committed empty script tree for the launch profile. |
| Bitcoin P2WPKH | One compressed secp256k1 key and ECDSA signature | Joint ECDSA. Commit all inputs and outputs with `SIGHASH_ALL`. |
| Ethereum/EVM | One EOA and ordinary ECDSA transaction signature | Pin the account nonce and chain ID. Normalize low `s` and recovery parity. The EOA pays gas. |
| Solana | One Ed25519 public key | Use an Ed25519-compatible joint signing protocol and a separately funded durable nonce account. The joint address controls the nonce authority as well. |

MuSig2 supplies the native Taproot aggregation interface. Its network participant is implemented as a distributed logical signer. Its partial signatures are not standalone signatures. [BIP327](https://bips.dev/327/)

For Solana, use the Ed25519 ciphersuite of FROST with two logical participants and threshold emulation of the network participant. Preserve FROST's participant identifiers, interpolation coefficients and binding factors. Do not port MuSig2 to Edwards curves by changing a curve parameter. FROST specifies Ed25519-compatible output but does not supply DKG or metadata protection. [RFC 9591, §§5–7](https://www.rfc-editor.org/rfc/rfc9591.html)

Solana's first instruction advances the durable nonce. A transaction that passes nonce validation but fails execution still consumes the nonce and fees. Such a result terminates the request without asserting that payment succeeded. The current documentation also flags possible future deprecation of durable nonces. Adapter admission therefore pins and tests supported validator behavior. [Solana durable nonces](https://solana.com/docs/core/transactions/durable-nonces)

The proposal adds Compact contracts on Midnight. It adds no custody contract or multisig script to these native addresses. Regulated token contracts and programs are separate asset-level enforcement described in §3.5.

### 2.4 Seizure and recovery holdings

An owner-absent seizure requires a previously provisioned alternative to the live wallet. A legal order cannot manufacture a missing signing factor.

At setup, the wallet verifiably escrows `u` to an independent **3-of-5 legal trustee group L**. Trustees receive encrypted shares with proofs that their joint secret matches `U`. No Fenrir node belongs to L. L computes the user-side joint-signing algorithm in MPC after a finalized seizure permit. It exports a message-specific contribution, never `u`. These trustees act under the charter's legal-order or default-term authority. They are trusted to authenticate the legal basis. Cryptography proves that registered authorities approved a statement, not that a court's decision is substantively correct.

Fenrir also creates a verifiable **3-of-5 backup sharing of `v` for an independent recovery group E**. The backup includes unused network-side presignature state, nonce material and its authenticated slot manifest. Backing up `v` alone would not let an offline wallet use its existing ECDSA slots after total committee loss. No member of E belongs to L or Fenrir. E has no user factor. L has no network factor. The two escrow groups cannot share an administrator, recovery credential or cloud account. Replacing either group requires a charter-authorized state transition.

If Fenrir disappears, E verifies a finalized Midnight recovery transition and provisions fresh shares of the same `v` to a replacement committee. The wallet then submits one sealed exit request, or L supplies the user-side contribution when the standing exit record explicitly delegates that operation. The successor committee signs only the standing sweep or an admitted seizure during recovery. It does not receive a general authority to change the charter.

The charter fixes a recovery delay in Midnight heights from the last accepted Fenrir service checkpoint. A recovery transition requires that delay and the registered recovery approvals. A timeout is an operational failover rule, not proof that the old network no longer exists. The successor restores only unused slots according to finalized state. Per-slot backup keys are retired when slots are consumed. Newly created slots become usable only after verifiable backup delivery.

This preserves the address and avoids reconstructing `x`. Recovery requires Midnight, enough trustees, a reachable replacement committee and target-chain inclusion. A live legal hold prevents the owner's sweep. If those services also disappear, funds can remain unavailable. The proposal does not promise unconditional recovery or release a complete key to the wallet.

The launch has two algebraic signing factors. Escrowing them adds independent custody organizations even though it adds no third factor to `X`. A charter that requires a third party's cryptographic veto adds a third logical signing factor at address creation. A proof-only approver does not provide that protection against a fully corrupt signer network.

The trustee assumption is fewer than three corrupt members in each five-member group. A threshold of L can impersonate the user-side signer. A threshold of E can impersonate the network-side signer. Threshold compromise of both groups defeats custody. The protocol does not classify these escrows as trust-free recovery.

## 3. Spend flow in both modes

### 3.1 The sealed user contribution

Each transaction variant and each input uses its own setup slot. All variants spend the same pin. Fees, destinations, change addresses, calldata or instruction bytes, and signature modes are fixed by the owner. There are no arbitrary-hash requests.

For ECDSA, secure preprocessing creates additive logical-party shares satisfying:

```text
R = kG
w_U + w_F = k^-1
mu_U + mu_F = x k^-1

z_U(h) = h w_U + r mu_U
z_F(h) = h w_F + r mu_F
s = z_U(h) + z_F(h), where r = x-coordinate(R) mod ell
```

The wallet knows only its presignature pair. Fenrir threshold-shares its pair. The preprocessing protocol supplies correctness, secrecy and malicious-party checks. These equations alone are not a preprocessing protocol. A CGGMP-style two-party presigning implementation supplies the interface, with Fenrir's logical party emulated securely. The published implementation exposes a noninteractive partial-signature operation and explicitly warns against presignature reuse. [CGGMP presignature API](https://docs.rs/cggmp21/latest/cggmp21/signing/struct.Presignature.html)

The owner deals `Share_t(z_U(h_j))`, never `w_U`, `mu_U` or `u`. Let preprocessing authenticate `A_U = w_U R` and `B_U = mu_U R`. The implied constant commitment for this dealing is:

```text
z_U(h_j) R = h_j A_U + r B_U
```

This is line dealing's algebra applied to one finished user contribution. The corresponding network commitments sum with the user commitments to `G` and `X` in base `R`. The encrypted dealing contains the preprocessing-transcript identifier and proofs binding these values to that transcript.

For Schnorr, the owner evaluates the selected protocol's partial-signature equation after fixing the message and complete logical-party nonce transcript. In schematic notation:

```text
z_U = adjusted_user_nonce + challenge * adjusted_user_key_factor
s = z_U + z_F + specified_public_tweak_term
```

The implied commitment is the exact partial-verification equation of that suite. The owner deals only `z_U`. BIP327 or FROST determines the nonce binding factors and adjustments. A separate proof of request authorship prevents treating partial-signature verification as proof of key possession.

Every scalar dealing retains canonical encodings, polynomial commitments, per-recipient encryption and a proof binding the ciphertexts to the dealing. All these objects sit inside the request envelope. Public verification becomes verification of a zero-knowledge statement about that envelope.

One nonce or presignature is never shared by two variants. Reusing ECDSA preprocessing would reveal the user's coefficients from two responses. Repeated network continuations can also expose network secrets. Retries retransmit the identical contribution for the identical locked message. A fee change uses another prepared slot.

### 3.2 The owner's one move

The owner constructs:

```text
Request = {
  private request identifier, chain, suite, address-record opening,
  pin, variants, slot identifiers, sealed user dealings,
  intent and principal approvals, charter witnesses,
  successor-address certificates, fee ceiling, trigger, window,
  encrypted return address
}
```

The owner signs the request binding, encrypts the canonical padded object under the epoch threshold-encryption key and submits one envelope with an anonymous admission proof. A relay can deliver this message. No later challenge to the owner is permitted.

Request authorship uses a separate credential registered during setup with a proof tying it to `U`. It does not reuse a host-signing nonce or treat a joint-signature partial as an authentication signature.

Setup supplies signing slots and the current public encryption parameters. Reading public state before constructing the message is allowed. Transport establishment does not add an application-signing exchange. A strict one-packet client posts the threshold ciphertext through a relay without opening a new AKX session.

The original open target-key mode is disabled for these governed addresses. A fully corrupt committee must not reconstruct the user's line. A builder can select among sealed variants and evaluate triggers, but it cannot invent a later sighash. Requests that need arbitrary later transaction construction require a weaker authorization model or a new owner action. This follows the copying argument in SCHEME §6.6.

### 3.3 Shared state machine and authorization

```text
ENCRYPTED -> ORDERED -> PRIVATELY_VALIDATED -> WAITING
          -> RESERVED -> SIGNED -> SUBMITTED -> SETTLED
          -> REJECTED / EXPIRED / PIN_CONSUMED
```

`ORDERED` requires a `Q`-signature certificate over the ordered ciphertext root and a finalized Midnight record of that root. The independent Midnight anchor matters: a six-node launch coalition can manufacture board votes but cannot manufacture Midnight finality. Decryption starts only after both checks pass.

Private validation checks the user dealing, slot, address, charter and all variant bytes. Nodes obtain chain facts independently. Target state enters through verified light-client evidence or a named, charter-approved observation quorum. An authenticated RPC response alone is not a proof of chain state.

The authorization relation has public inputs consisting of the finalized state root, ordered ciphertext commitment, new state commitment, private-asset nullifier and a hiding commitment to the selected transaction. Its private witness proves:

1. The request opens the ordered ciphertext and a live address/asset record.
2. Its authorization is exactly one of `PRINCIPALS`, `SEIZURE` or `EXIT`.
3. `PRINCIPALS` carries the intent of every required principal and binds the complete economic effect.
4. `SEIZURE` carries registered legal-authority approvals, an order or default-term reference, scope and a permitted destination. It activates L's user-side signing service.
5. `EXIT` matches the owner's standing exit record. It cannot substitute another beneficiary, chain or charter.
6. The selected route satisfies its charter and named approver requirements. A current legal hold blocks `PRINCIPALS` and `EXIT`. An ordinary freeze also blocks those routes. `SEIZURE` proceeds only when the order explicitly grants the applicable override.
7. The pin, target-state evidence, fee bound and registered successor addresses are valid. The asset nullifier has not been consumed.
8. Every resulting asset record carries the same charter or an expressly authorized charter transition.

Approver credentials and rejection reasons remain private. A named issuer, regulator or KYC approver supplies a signed, scoped credential. The charter states which routes require it and how revocation works. Silence is a veto when that approval is required. A seizure does not silently bypass every approver.

Midnight atomically verifies the proof, checks current hold and revocation state, consumes the nullifier and records `RESERVED`. The reservation binds the exact selected variant and slot. It is the authorization linearization point. A later hold stops later reservations. It cannot cancel an already released native-chain signature.

The reservation also creates a request-family record for its pin and sealed variant set. A fee bump advances that record with a new authorization proof and an unused slot. It does not consume the same asset nullifier again. It rechecks current holds and approvers, preserves the economic outputs and conflicts with every earlier variant. After pin consumption, the family closes.

A reservation is not deleted merely because a submission times out. The native transaction remains usable. Release requires proof that the pin was consumed or another chain-specific condition makes the old signature permanently unusable. Failure to observe inclusion is insufficient.

For an owner-absent seizure, the institution submits an encrypted request with the legal witness and proposed transaction family. Initial validation checks that route instead of demanding a wallet contribution that does not exist. After the finalized reservation, L and Fenrir run fresh joint preprocessing if necessary. L supplies sealed contributions for only the reserved bytes. The completion computation verifies their binding before signing. The same procedure serves an explicitly delegated standing exit. These institutional exchanges do not require the owner and do not add a fourth authorization route.

### 3.4 Execution by mode

**TEE mode.** Operators order ciphertexts. After `ORDERED`, each approved Veritee instance sends its verifiable decryption contribution over an attested channel to the approved signing instances. No contribution is posted in plaintext. These instances open the request in protected memory, validate it, select the variant and produce the authorization proof. After finalized `RESERVED`, at least `t` instances release network signing contributions through protected channels. The final transaction leaves through the measured broadcast service. Completion or a terminal failure triggers erasure and an authenticated state checkpoint.

No single VM stores the complete reusable Fenrir factor. A combiner handles finished signatures and request plaintext, not the address key. Its compromise therefore has a different consequence from compromising a threshold of custody shares.

**Non-TEE mode.** Select an execution set `S` of `t` registered nodes. Use malicious-secure, dishonest-majority MPC with authenticated shares, OT-based preprocessing and secure channels. MASCOT/SPDZ is the concrete prototype family. This choice supplies privacy and correctness with abort, not guaranteed output against a malicious participant. [MP-SPDZ protocol documentation](https://mp-spdz.readthedocs.io/en/latest/readme.html)

Each selected node inputs its threshold-decryption contribution privately. The MPC verifies each contribution, reconstructs the envelope key as a shared value, authenticates and decrypts the ciphertext inside the computation, and retains the plaintext as shares. It evaluates the same validation and authorization relation. Private witnesses remain shared while the parties jointly generate the proof. No external prover receives the witness in clear.

The computation also receives each participant's registered inner-dealing decryption key and custody/presignature share as private inputs. It checks those inputs against the setup commitments, decrypts the recipient-specific user shares and interpolates only inside MPC. Reconstructing the outer envelope alone is not permission to reveal its inner header or dealing.

After finalized `RESERVED`, the same computation reconstructs the user's finished contribution as a shared value, evaluates the network's signing continuation and checks the complete native signature. Only the signed host transaction opens to a designated broadcaster in `S`. Other outputs are the prescribed public commitments and proof, or a fixed-size rejection record. Request identity, approvals and charter witnesses do not open.

On abort, the board selects another execution set. It retains the same request, transaction commitment and slot lock. New MPC randomness never authorizes a different message under an old signing nonce. Enumerating sets eventually reaches an all-honest set when at most `f` nodes fail and the network becomes synchronous. This gives eventual completion under those assumptions, with an expensive worst case described in §8. No generic MPC abort is automatically a publicly provable offense.

Both modes use the same `OpenOrdered`, `CheckAndReserve`, `CompleteSignature`, `Reshare` and `Erase` interfaces. Non-TEE mode can first execute alongside the TEE implementation and compare committed results. Switching an address's execution mode requires a charter-authorized transition. It retains `X` and the signing material through verified resharing.

### 3.5 Freeze, reversal and covenant continuity

Fenrir submits evidence and executes authority decisions. It has no fourth authorization source called administrator override. Legal authorities register holds and seizure orders under the charter. Hold updates, revocations and payment reservations share Midnight's total order.

A reversal is a new authorized transfer of an asset that remains controllable. It does not rewrite Bitcoin, Ethereum or Solana history. A seizure uses L and Fenrir jointly, moves value to a registered destination and carries the charter forward. The owner need not return online.

For native BTC, ETH and SOL, the covenant continues only through joint addresses and approved representations. Every change and recipient address needs a certificate for the successor control policy. An unrestricted external destination is rejected for a continuing covenanted asset. Cross-chain continuation requires source finality, a consumed transfer nullifier and a corresponding destination lock/mint or swap protocol. A signature does not transport BTC onto another chain or prove bridge solvency.

For issued EVM assets, an ERC-3643-style contract can enforce transfer policy independently of the signing service. Its forced-transfer function bypasses ordinary compliance checks, so Fenrir must explicitly constrain the agent authority to the seizure route. [ERC-3643](https://eips.ethereum.org/EIPS/eip-3643)

For issued Solana assets, Token-2022's permanent delegate supplies a mint-level transfer and burn authority that holders cannot revoke. It needs separate policy enforcement for the proposed legal route and does not control native SOL. [Solana permanent delegate](https://solana.com/docs/tokens/extensions/permanent-delegate)

These token mechanisms are optional asset adapters, not evidence that a bare EOA or Taproot key enforces a covenant. Universal reversal after value reaches an unrestricted address is outside the proposal's guarantee.

## 4. Blindness in both modes

### 4.1 Public board format

The board records:

```text
protocol version, encryption epoch, padded ciphertext,
ciphertext digest, anonymous fee-token nullifier,
admission proof, ordering position and certificate,
hiding state commitments, execution receipts
```

It does not record the address, owner, chain-specific intent, charter, route discriminator, raw transaction digest, plaintext complaint or signature partial. Use randomized hiding commitments for low-entropy policy fields. Hashing a country code, amount or transaction template without a secret salt does not hide it.

Launch payment envelopes occupy a fixed 64 KiB frame. Admission proves a valid anonymous fee credential, ciphertext well-formedness and bounded resource class. The complete semantic checks happen after ordering. Malformed ciphertexts consume the sender's admission resource. Authentication failure does not create a plaintext complaint oracle.

The decryption layer uses a CCA-secure threshold hybrid-encryption construction with public ciphertext and share validity checks, following the Ferveo construction interface. Associated data includes protocol, epoch and admission context. In this proposal, decryption shares go to protected computation, rather than being revealed publicly. [Ferveo threshold encryption](https://nikkolasg.github.io/ferveo/tpke-kzg-dkg.html)

Shutter supplies the order-before-decrypt precedent. Its TEE discussion also treats a TEE as a gate on release of a key share. Fenrir additionally needs confidentiality after ordering. [Shutter encrypted-mempool research](https://docs.shutter.network/docs/shutter/research/the_road_towards_an_encrypted_mempool_on_ethereum)

### 4.2 Visibility by stage

| Stage | TEE operator sees | Non-TEE operator sees | Public observer sees |
|---|---|---|---|
| Setup | Attestation and padded encrypted traffic | Its DKG/secure-computation view | Registration commitments and timing |
| Pending | Ciphertext, fixed frame, admission result | Same, plus its own decryption-key share | Ciphertext and public board fields |
| Ordered | Protected execution traffic and timing | Its MPC shares and transcript | Ordering certificate and committed root |
| Policy check | Padded processing and encrypted state I/O | MPC transcript and permitted public outputs | Proof, nullifier and state commitments |
| Signing | Protected partial-signature traffic | Its protocol view | Fixed-size progress receipts |
| Broadcast | Destination endpoints, sizes and timing | Designated broadcaster learns the signed host transaction | Host transaction when a relay, mempool or block exposes it |
| Settlement | Public chain result | Public chain result | Public chain result |

The TEE node sees plaintext after order. Its operator does not under the TEE assumption. In non-TEE mode no individual operator sees the request plaintext, but the broadcaster necessarily learns the host transaction. ZK proof generation and state lookup must preserve this distinction.

Private address and charter lookup uses authenticated oblivious storage or a bounded full scan. Indexing an encrypted database by a public address leaks the relation. TEE mode also uses an access pattern that does not expose secret-dependent disk locations. Both modes use common processing deadlines and fixed-size outward errors.

### 4.3 Censorship, slashing and metadata

Anonymous admission tokens avoid linking a board fee payer to the owner. Clients submit through independent relay hops, use a common endpoint and avoid per-customer TLS names. Relays batch fixed-size frames and send cover traffic. At least one relay outside the observer's control is an explicit anonymity assumption.

These measures remove content as a selection criterion within the defined leakage model. They do not prevent a host from censoring an IP address, blocking all traffic, exploiting timing correlations or denying service after a public transaction exposes an address. B2 is therefore partial under its literal wording.

Board equivocation is publicly punishable through contradictory signed roots. Data-availability promises have signed receipts and challenge responses. An invalid private contribution can be punished only with a zero-knowledge proof of a precisely defined violation tied to a signed message. Neither mode publishes the offending request or a DH secret to make an allegation checkable. Timeouts and unidentifiable MPC aborts cause retry or exclusion under the availability policy, not an unsupported fraud conviction.

The pending-privacy claim requires fewer than `t` compromised decryption shares and no honest decryption before a finalized order. MPC privacy after order has its own corruption assumptions. Threshold encryption does not automatically confer threshold-private execution.

### 4.4 Unlinkability and the publication boundary

Native signatures hide the co-signing arrangement. They do not hide a Bitcoin input's outpoint, an Ethereum sender or Solana account keys. Taproot's spending rules still expose and commit to transaction structure. [BIP341](https://bips.dev/341/)

Fresh addresses, private ownership records, batching, amount denominations and common broadcast infrastructure reduce identity and route correlations. They do not make a unique deposit and its later spend unlinkable. A public seizure destination can identify an institutional route even when its authorization proof hides the route selector.

Strong B5 requires a shielded asset pool or a separately specified liquidity service that breaks deposit-to-egress correspondence. The latter changes custody and reserves. The former changes the asset representation and, on EVM or Solana, adds a contract or program. Neither follows from native joint signing, so the native profile marks B5 NOT MET.

Before broadcast, only the approved signing computation receives the host message. Literal secrecy until inclusion is unavailable on ordinary public-chain submission paths: relays, builders, validators or public mempools receive the transaction first. Private submission reduces that exposure but adds recipients outside the Fenrir signing set. B6 is partial at that boundary.

## 5. Veritee integration: TEE mode

### 5.1 Existing components used

The inspected Veritee checkout contains the required platform and channel components. It does not establish that the proposed custody service is deployed or audited.

| Component | Existing behavior used by Fenrir |
|---|---|
| Azure Confidential VM and AMD SEV-SNP | Protect the measured guest from the external host, subject to the platform threat model. |
| Immutable base image and dm-verity application image | Bind the approved software and application package to measurements. |
| `veritee-os/measured_setup/main.py` | Derives the application root hash from partition metadata, extends PCR15, opens the verity mapping and installs measured runtime policies. |
| `measured_setup/egress.py` and `server/egress_proxy` | Restrict container and host egress through separately scoped proxies and measured destinations. |
| `server/azure_attestation_server` | Collects vTPM evidence and either MAA or raw SNP evidence. Hosts the AKX endpoints and local proxy. |
| `server/akx` | Implements the attested epoch key, signed session exchange, HPKE and directional AEAD records. |
| Warden registration | Supplies the intended link between reproduced application measurements, attestation verification and Midnight registration. |

The exact AKX binding differs from the abbreviated prose formula in the design notes. `epoch.rs::report_data_for` computes:

```text
B = SHA256("temenos-akx-v1" || "epoch" || epoch_be64 || pk_epoch)
epoch_payload = B || zero_bytes(32)
```

`PlatformAttester` base64-encodes that 64-byte value as the payload and uses nonce `temenos-akx-v1-epoch`. In raw-report mode, `main.rs::report_data_binding` hashes the JSON `ReportData { nonce, payload }` and passes that digest through Azure HCL's report-data API. MAA mode binds the client payload through its evidence path. Verification must reproduce the relevant wrapping exactly. Comparing the hardware field directly with the abbreviated inner digest is wrong.

The client fetches `/enclave-key`, verifies the evidence and approved policy, then sends `/session` with `sid` and fresh `nonceC`. The server generates an X25519 session key and signs a SHA-256 transcript under the attested Ed25519 epoch key. `transcript.rs` length-prefixes every field with eight bytes. The client verifies that signature, performs HPKE using X25519/HKDF-SHA256/AES-256-GCM and sends `enc` to `/session/complete`. `/proxy` carries encrypted requests to the local application. Directional record nonces are `dir || 0^24 || seq_be64`, with `sid` as AAD. [HPKE specification](https://www.rfc-editor.org/rfc/rfc9180.html)

Fenrir uses AKX for setup, node-to-node provisioning and protected service calls. The outer browser TLS certificate is not the custody trust root. The threshold-encrypted request remains sealed even if a transport endpoint sees the outer request bytes.

The implementation plan leaves real-CVM end-to-end validation and the Warden epoch-binding check as open items. The companion Warden, spec and contract repositories are unavailable here. This proposal assumes they verify the exact binding, measurement, TCB floor, revocation and freshness policy. It also assumes Midnight can record current incarnation and authorization state. Those interfaces require integration validation before funds are accepted.

### 5.2 Additions required

**Custody application.** Add the DKG, presigning, private mempool, policy interpreter, chain verifiers and signing state machine as a measured application. Include setup and runtime hooks in review. Veritee runs application lifecycle hooks as guest root. Attestation must approve those hooks as well as container images.

**Sealed storage.** Encrypt persistent share state, request state and nonce ledgers with AEAD. Bind each record to node identity, address, share epoch, incarnation and state version. Keep decryption keys outside operator-managed disk images. Use attestation-gated threshold provisioning and the independently maintained recovery escrow. A boot measurement protects image integrity. It does not establish confidentiality or freshness of saved data.

**Rollback and clone fencing.** Midnight registers one current incarnation per node identity. Every nonce slot has a unique reservation tied to a finalized state transition. A restored instance obtains current state independently, checks its incarnation, replays all reservations and tombstones, and abstains on any ambiguity. It cannot sign from a local counter alone. A clone can retransmit the same locked response but cannot obtain authority for a different digest in that slot.

The current `next_boot_epoch()` reads and writes an ordinary file and warns on persistence failure. It is not a hardware monotonic counter or a rollback defense. Timed AKX key rotation is also distinct from custody-state fencing. Return the epoch, public key and evidence as one consistent snapshot during concurrent rotation.

**Redeployment.** A new measured instance registers its fresh attested transport key and incarnation. Existing nodes verify the current Midnight authorization, then reshare into the new instance over AKX. Each recipient verifies its encrypted share and the unchanged public-key commitment. No operator exports a plaintext share or restores an unverified checkpoint. If the old committee is lost, E performs the registered recovery procedure.

**Erasure.** Add explicit zeroization for custody shares, request keys, presignatures, plaintext buffers and library-owned copies. Disable swap, core dumps and payload logging. Erase per-request wrapping keys and remove them from backups. The inspected AKX code does not establish complete zeroization of all cryptographic objects. Secure erasure is a platform and implementation assumption, not something a signed deletion receipt proves against an already compromised VM.

**Egress and observability.** Approve only the required board, peer, chain and relay destinations. Use strict encrypted proxy envelopes and local upstreams. Do not give the custody application the Warden host-access exception or unrestricted egress profile. The existing proxy checks CONNECT destination and SNI but does not terminate TLS, validate upstream certificates or inspect encrypted HTTP. Its approved endpoints can receive leaked secrets from faulty application code. The application must verify peer identities and restrict output content.

Phala's key-management design provides relevant prior art for attestation-gated sealing keys, migration and publicly governed key-release changes. It does not provide Veritee with those features automatically. [dstack key management](https://docs.phala.com/dstack/design-documents/key-management-protocol)

### 5.3 What the host can still do

An Azure host or deployment administrator can stop instances, delay packets, deny storage and present old encrypted disks. It can observe traffic endpoints, sizes and timing, and attempt side-channel attacks. It can deploy a different image, which correctly configured clients and provisioners reject. The host does not gain guest-root access merely by owning the deployment under the intact-TEE assumption. Guest-root lifecycle hooks, application vulnerabilities, attestation failures and platform compromises remain in the trusted computing base.

If one plaintext-processing VM is compromised after order, that request's content can leak. If a threshold of custody instances is compromised, the attacker obtains Fenrir's factor and can bypass its policy checks. Sealed user contributions still restrict ordinary spends to messages for which the attacker has a valid user-side contribution. The non-TEE execution layer removes this plaintext-in-one-VM exposure when enabled.

## 6. Security claims in both modes

These are conditional protocol claims and proof sketches. The composed protocol, threshold emulation, private proof generation and rotation extension have no completed proof or benchmark in the inspected project.

### Claim A: joint custody

**Adversary:** a malicious wallet alone, fewer than the required Fenrir shares, or all Fenrir nodes without a user contribution or access to L. Setup satisfies the selected malicious-secure joint-signing protocol.

**Statement:** no party obtains `x`, and neither the wallet nor Fenrir alone forges a new host signature outside its legitimately supplied signing capabilities.

**Argument:** emulate the distributed Fenrir party in the two-party signing security game. A new signature without the other logical party is a joint-signature forgery. DKG, share encryption and MPC hide the missing factor. This argument depends on the selected protocol's assumptions, including its preprocessing model. Merely proving `X = U + V` does not establish it. Escrow compromise changes which adversary controls the user or network logical party.

### Claim B: sealed user confinement under complete Fenrir compromise

**Adversary:** all Fenrir nodes and all their network-side state, including failed or broken TEEs. The wallet was honest during setup and request creation. L is not compromised and supplies no extra contribution.

**Statement:** the adversary can complete the supplied variants at arbitrary times, but cannot produce a signature on a new message without breaking the joint-signing protocol. All supplied variants spend the same pin, so the target ledger accepts at most one successful conflicting spend.

**Argument:** replace Shamir reconstruction by direct delivery of every sealed user contribution. This only strengthens the adversary. The remaining attack is against the honest logical user's security in the joint-signing protocol. The pin gives the chain-level conflict bound. Use fresh preprocessing for every variant and canonical sighashes to prevent cross-session substitutions.

This preserves the substantive all-corrupt guarantee of SCHEME §6.3 for the user's half. It does not inherit that section's single-signer proof verbatim, does not prove trigger enforcement against all corrupt nodes and does not make partial signatures independently unforgeable.

### Claim C: charter authorization

**TEE adversary:** all operators can be hostile. Hardware isolation, measured code, provisioning, Midnight finality, proof soundness and required external authorities remain intact.

**Statement:** every released signature has a finalized reservation satisfying one of the three admitted routes. A hold preceding that reservation blocks the owner's routes.

**Argument:** approved code uses custody material only after verifying the exact reservation. The code recomputes the transaction commitment and consumes its slot under external fencing. Hosts can stop that computation but cannot make approved code sign another message.

**Non-TEE adversary:** at most `f` Byzantine Fenrir nodes, correct independent Midnight verification and uncompromised required authorities.

**Statement:** the same authorization property holds, with completion conditional on obtaining an all-honest execution set after stabilization.

**Argument:** MPC correctness and proof soundness bind the private computation to the committed request. At least one honest participant in every active set refuses to release an unauthorized signature. External reservation state prevents contradictory retries.

**Failure beyond the bound:** all Fenrir nodes reconstruct their factor and retained user responses. They complete an old variant without running the proof verifier. A ZK proof on Midnight cannot prevent this because the native target verifies only its ordinary signature. Reading R1 as charter authorization resolves the seizure definition but does not remove this attack.

### Claim D: pending confidentiality

**Adversary:** fewer than `t` decryption-key shares, even with arbitrary network observation. Midnight finality and the honest release gate remain intact.

**Statement:** before finalized `ORDERED`, equal-size honest envelopes hide their plaintexts up to public admission and traffic metadata.

**Argument:** threshold-encryption security hides the content key. Hybrid AEAD hides the payload. Binding the ciphertext and associated data prevents substitution. No honest node contributes decryption material before the finalized order. Public ciphertexts remain vulnerable to later compromise of `t` retained epoch keys. Rotation and erasure bound that exposure but do not erase an adversary's copies.

### Claim E: operator privacy after ordering

**TEE adversary:** arbitrary hosts with intact approved VMs and no successful side channel.

**Non-TEE adversary:** at most `f` corrupt nodes in the stated MPC execution and retry model.

**Statement:** private request fields are indistinguishable for executions with the same public outputs and traffic leakage. The authorized host transaction is an explicit output at broadcast.

**Argument:** TEE isolation and authenticated channels protect plaintext in the first mode. MPC simulation, ZK and hiding commitments protect it in the second. Fixed processing schedules and oblivious storage prevent the implementation from adding secret-dependent access patterns. This is a conditional leakage-based claim, not immunity to global traffic analysis or public-chain inference.

### Claim F: rotation without moving coins

**Adversary:** static corruption within the bound in each participating committee, consistent finalized Midnight state and eventual delivery.

**Statement:** resharing changes the custody participants while preserving `X` and every live slot's single-message binding.

**Argument:** freeze the old epoch at a finalized cut. Finish already reserved signatures on their exact digest. For other state, `t_old` verified dealers reshare their values with Lagrange weights into threshold `t_new`. The combined constant remains unchanged. Publicly verifiable encrypted delivery and data availability cover every new honest recipient, including those outside the initial receipt quorum.

A `Q`-receipt certificate alone is insufficient: at launch `Q-f = 4 < 7`. Activate the new epoch only after verified delivery for all recipients, availability certification and at least `t_new` valid readiness receipts. With eventual delivery, all `n_new-f_new` honest nodes obtain valid shares. Old nodes erase transferred state and retain tombstones. This is a new AVSS/PVSS-based extension, not SCHEME's unproved T1 resharing rule relabeled for T2.

Rotation also transfers pending sealed-response shares, unused presignature state and the envelope-decryption shares needed by pending ciphertexts. Old envelope public keys stop accepting new requests. Their secrets remain shared only while the admitted requests need them, then are erased. Replacing a decryption public key without preserving access to pending envelopes would strand those requests.

Static security does not stop an attacker from collecting a threshold of retained shares across epochs. Mobile corruption requires proactive-security proofs and credible erasure. A compromised retired threshold cannot be cryptographically revoked while the native public key remains unchanged.

## 7. Requirement table

`MET` means under the explicitly stated mode assumptions. `PARTIAL` identifies a material limitation of the literal requirement. These ratings describe the proposed protocol, not deployed functionality.

| Requirement | TEE mode | Non-TEE mode | Reason |
|---|---|---|---|
| R1: no spend without admitted authorization, including all Fenrir nodes | **MET** | **PARTIAL** | Intact measured signers enforce Midnight even against all operators. Total cryptographic-node compromise bypasses policy for retained sealed capabilities. Both preserve confinement to the supplied user messages. |
| R2: every spend requires joint control | **PARTIAL** | **PARTIAL** | Active custody requires user-side authority and Fenrir. Disaster recovery substitutes an independent successor committee, so the original network is not literally required forever. |
| R3: joint network-created addresses and fresh user elements | **MET** | **MET** | Wallet-supplied fresh factors combine with network DKG. No member creates or receives the controlling key. Setup securely supplies private presigning outputs. |
| R4: universal covenants, vetoes, freeze and reversal | **PARTIAL** | **PARTIAL** | Enforced within the registered control domain. Released native signatures cannot be recalled. Arbitrary external assets and destinations do not inherit the covenant. Non-TEE enforcement also needs its corruption bound. |
| R5: two-key launch and funds never trapped | **PARTIAL** | **PARTIAL** | Two algebraic factors remain. Recovery needs independent trustees, Midnight and target inclusion. A live legal hold intentionally blocks the owner. |
| B1: request content and identity hidden from operators | **PARTIAL** | **PARTIAL** | Private payload is protected under the mode assumptions. Public host outputs and network metadata can reveal parts of the requested effect or identity. |
| B2: nothing available for selective censorship | **PARTIAL** | **PARTIAL** | Content is hidden before ordering. Timing, connectivity and later host-chain evidence remain selectable. |
| B3: threshold decryption only after certified order | **MET** | **MET** | `t`-share encryption and a finalized Midnight order gate. No public decryption shares. The claim includes the external finality assumption. |
| B4: TEE launch with a cryptographic continuation | **MET** | **MET** | The same private-execution interfaces, address records and envelopes support MPC. TEE removal requires no coin movement or wallet-message redesign. |
| B5: deposit/egress and initiation-source unlinkability | **NOT MET** | **NOT MET** | Native-chain transaction graphs and recognizable destinations expose links. A separate shielded asset representation is necessary for the full requirement. |
| B6: only the signing set sees the message before inclusion | **PARTIAL** | **PARTIAL** | Secrecy holds before broadcast. Ordinary target-chain relays and validators see the transaction before inclusion. |

Full R1 in non-TEE mode needs an independent mandatory policy co-signer or target-chain verification of the authorization. The former changes the two-key launch. The latter changes the native-address constraint. Full R5 cannot include both unconditional access and an indefinitely enforceable legal hold. Full B5 and literal B6 require changes beyond encryption of Fenrir's board.

## 8. Costs, compatibility and assumptions

### 8.1 Rounds and latency

Address creation pays interactive DKG, trustee provisioning and signing preprocessing. The wallet prepares a bounded slot pool during that session. These costs move work out of the spend's online path.

An online request has one owner message. The network then performs ciphertext availability/order, Midnight order finalization, private opening and validation, authorization proof/finalization, and signature completion. Target inclusion and finality follow. Triggers and external approvers add unbounded waiting when unavailable.

Let `F_O` and `F_A` denote Midnight's order and authorization finalization times, `Delta` a network round, `P` the authorization-proof time and `C` private-execution time. A useful budget is:

```text
latency before broadcast = F_O + F_A + P + C + O(network rounds)
settlement latency      = latency before broadcast + target inclusion/finality
```

TEE mode adds a small number of private share exchanges after each finalization. Non-TEE mode adds the MPC circuit's interactive depth and any retries. Neither inherits SCHEME's one-release-round cost. AKX's documented approximately three-second attestation cost is normally paid in background refresh, not once per spend.

The dishonest-majority execution schedule has `choose(9,7) = 36` possible launch sets and `choose(17,12) = 6,188` later sets. Those are worst-case fallback counts, not expected attempts. A protocol with identifiable abort can reduce retries. The selected generic MPC backend does not justify claiming that improvement automatically.

### 8.2 Wire and CPU budgets

The following numbers are engineering estimates for planning, not measured results. The sample payment has four variants and two inputs, cached setup and short policy witnesses.

| Item | Planning budget or calculation |
|---|---|
| User scalar dealings, launch | Eight polynomials times `6*33 + 9*32` bytes, about 3.8 KiB before nonce points, proofs and transaction bytes. |
| User scalar dealings, later | Eight times `11*33 + 17*32`, about 7.1 KiB before other fields. |
| Public encrypted request | One 64 KiB frame plus KEM, certificate and admission-proof overhead. Larger requests require a separately declared class and leak that class. |
| Threshold decryption traffic | Kilobytes of contributions and proofs per request, carried privately. Exact size depends on the pinned encryption suite. |
| TEE validation and signing CPU | Budget 10–100 ms per participating node for a small payment, excluding proof generation and setup. Benchmark before setting capacity. |
| Authorization proof CPU | Budget 1–30 CPU-seconds per simple proof including wrapping. This is a test budget with no measured support in this project. |
| Non-TEE private execution | Budget 1–100 CPU-seconds per node and 10–500 MiB of interactive traffic before distributed proof generation. Secret decryption, hashes and elliptic-curve work dominate. |
| Non-TEE proof generation | Budget additional tens of seconds to minutes for the initial generic implementation. The distributed prover is a principal feasibility and capacity risk. |
| DKG and resharing | Quadratic participant communication for the conservative implementation, multiplied by addresses and live preprocessing state. Batch only with explicit proofs of correctness. |

The original 3.3 ms/node T2 figure measures open ECDSA line dealing in the prototype. It does not measure joint preprocessing, privacy, policy proofs, Veritee or chain acceptance. It is not a throughput estimate for this enhancement.

Heavy proof work uses a small-field STARK trace with zero-knowledge masking and recursion. One BLS12-381 wrapper presents the statement to Midnight. The Compact circuit checks the wrapper and bounded state updates. No committee circuit exceeds `2^21` rows. Trace segmentation does not excuse an oversized final wrapper. Admission to production requires measured row counts, proof sizes and verification cost for the pinned implementation. If the wrapper does not fit, that proof route does not ship.

The non-TEE implementation needs a distributed prover over shared witnesses. Shipping only a conventional prover in a VM fails B1 in that mode. There is no claim that the inspected Midnight stack already supplies the required STARK wrapper or distributed prover.

### 8.3 What changes and what remains assumed

The enhancement removes existing-address import, the owner-held full key, open user-key dealing, public plaintext requests and public signature partials. It adds setup interaction, DKG, joint presigning, threshold encryption, independent escrows, private execution and authorization finality. An ordinary hardware wallet that exports only completed single-key signatures cannot serve as this wallet without new joint-signing support.

The design retains the conflict pin, sealed fee grid, deterministic variant selection, durable slot ledger, chain-specific signature encoding and freeze-before-handover rule. It retains the distinction between voting quorum and cryptographic threshold.

New assumptions include correct malicious-secure preprocessing and its composition, a sound private authorization proof, confidential and authenticated channels, a consistent Midnight authorization ledger independent of Fenrir, honest required authorities, available and independent trustee groups, and trustworthy chain-state evidence. TEE mode additionally trusts SEV-SNP/vTPM/MAA or raw-report verification, the measured guest and its software supply chain. Non-TEE mode trusts the MPC backend and distributed proof implementation. Anonymity additionally depends on relay non-collusion, traffic shaping and the stated public-chain leakage.

Acceptance tests cover all three host-chain adapters, invalid DKG contributions, fee-variant nonce separation, malicious preprocessing, ciphertext substitution, an order forged without Midnight finality, a hold racing a reservation, repeated crash/restore, cloned instances, private aborts, committee handover and complete committee loss. A successful source review or VM attestation alone does not satisfy these tests.

## 9. Changes to SCHEME.md

| Section | Required change |
|---|---|
| §1 | Describe joint custody and sealed user contributions. Remove the claims of no DKG or presignature protocol for this profile. |
| §2 | Add user/network access structure, setup, trustee roles and separate key domains. Keep `Q=6,t=7` and `Q=t=12`. State TEE and non-TEE adversaries separately. |
| §3.1 | Version the domain labels. Add address-record, ciphertext, policy-state, slot, incarnation and mode-transition bindings. Avoid overloading `q` for quorum and curve order. |
| §§3.2–3.3 | Replace full signatures or full user lines with sealed joint-signing responses. Bind each to a verified preprocessing transcript and distinct slot. Encrypt the complete header and dealing. |
| §3.4 | Separate public admission from private semantic validation. Replace plaintext complaints with private adjudication and ZK evidence. Specify availability independently of ACK counts. |
| §§3.5–3.6 | Add finalized encrypted ordering, private waiting state and independent chain-state evidence. Preserve deterministic anchoring and explicit board cuts. |
| §§3.7–3.8 | Require finalized Midnight reservation before completing either logical signing leg. Disable unrestricted open target-key construction for governed assets. |
| §§3.9–3.10 | Add external rollback fencing, private checkpoints and erasure. Do not release a reservation on timeout while a signed transaction remains valid. Distinguish Solana nonce consumption from payment success. |
| §4 | Require successor-address certificates and charter continuity. Specify EVM calldata and Solana instructions completely. Keep fee ceilings and native sighashes. |
| §5 | Specify AVSS/PVSS-backed T2 resharing, readiness and availability separately. Preserve public keys. Add independent disaster recovery and the retained-old-share limitation. |
| §§6.1–6.9 | Replace `F_OMS` with joint custody, three authorization routes and explicit leakage. Retain the copying impossibility. Prove composition instead of inheriting existing theorems by name. |
| §7 | Replace capacity claims with setup, private execution, proof, finality and retry measurements. |
| §8 | Close owner unilateral spending and plaintext-board exposure within their threat models. Keep public-chain unlinkability, total-compromise policy enforcement and unconditional recovery visibly unresolved. |
| §10 | Add trustee collusion, fake policy roots, rollback clones, prover leakage, secret-dependent I/O, early decryption, public submission and signed-before-hold races. |

## 10. Sources

Public sources below were opened. Contributions are limited to the material read. The ePrint entries are explicitly identified where only their abstracts and revision notices were available.

1. [Ika whitepaper, §§3.1–3.3](https://docs.ika.xyz/whitepaper.pdf). Joint user/network custody, network-created keys, partial-signature submission and the distinction between joint generation and full-key import. It does not establish Fenrir's secrecy, covenant or recovery claims.
2. [2PC-MPC: Emulating Two Party ECDSA in Large-Scale MPC](https://eprint.iacr.org/2024/253). Opened abstract: the privileged-client/network formulation and threshold emulation of one logical party. The PDF was inaccessible. No detailed reduction or performance claim from it is used here.
3. [Practical Zero-Trust Threshold Signatures in Large-Scale Asynchronous Networks](https://eprint.iacr.org/2025/297). Opened abstract and July 2026 revision notice: one-round client interaction and autonomous presigns are relevant alternatives. The revision changes its key model and removes earlier reconfiguration protocols. This proposal does not import those removed protocols or claim that this paper proves its composition.
4. [CGGMP presignature API](https://docs.rs/cggmp21/latest/cggmp21/signing/struct.Presignature.html) and [signing implementation](https://docs.rs/cggmp21/latest/src/cggmp21/signing.rs.html). The concrete presignature/partial-response interface, linear final response and explicit one-use requirement. The proposed distributed logical-party adapter remains additional work.
5. [BIP327: MuSig2](https://bips.dev/327/). BIP340-compatible key aggregation, preprocessing of nonce exchange, tweak handling and partial-verification semantics. Used for the Taproot logical-party interface.
6. [RFC 9591: FROST](https://www.rfc-editor.org/rfc/rfc9591.html). Two-round Schnorr signing, Ed25519 compatibility, nonce handling and limits concerning DKG, robustness and metadata privacy.
7. [Ferveo threshold encryption](https://nikkolasg.github.io/ferveo/tpke-kzg-dkg.html). Ciphertext associated data, validity checks and verifiable threshold-decryption contributions. Used as the encryption interface, with private delivery to protected computation.
8. [Shutter: The Road Towards an Encrypted Mempool](https://docs.shutter.network/docs/shutter/research/the_road_towards_an_encrypted_mempool_on_ethereum). Commit/order-before-decrypt and TEE-gated key-share release. Fenrir adds confidential execution after ordering.
9. [MP-SPDZ documentation](https://mp-spdz.readthedocs.io/en/latest/readme.html). Implemented malicious, dishonest-majority MPC families and preprocessing. Used to select MASCOT/SPDZ for the cryptographic prototype, without claiming production review or measured Fenrir performance.
10. [ERC-3643](https://eips.ethereum.org/EIPS/eip-3643). Native token-level freezing, compliance checks and forced-transfer authority. Its compliance-bypassing administrative paths explain why a separate legal authorization policy is necessary.
11. [Solana permanent delegate](https://solana.com/docs/tokens/extensions/permanent-delegate). Mint-level transfer/burn authority that a token holder cannot revoke. This applies to the token program, not native SOL.
12. [Solana durable nonces](https://solana.com/docs/core/transactions/durable-nonces). Offline transaction lifetime, first-instruction requirement, nonce consumption on execution failure and the documented deprecation caveat.
13. [BIP341: Taproot spending rules](https://bips.dev/341/). Key-path verification, tweaks and transaction commitments. Used to distinguish hidden signing structure from visible transaction flow.
14. [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180.html). Standard key encapsulation, derivation and authenticated-encryption framework behind Veritee's session channel. The local code supplies the exact deployment binding.
15. [dstack key-management protocol](https://docs.phala.com/dstack/design-documents/key-management-protocol). Attestation-gated sealing, migration and on-chain authorization of key-release changes. Used as operational prior art, not as proof of Veritee behavior.
16. [NEAR Chain Signatures documentation](https://docs.near.org/chain-abstraction/chain-signatures). Contract-requested foreign-chain signing and caller/path-derived addresses. It supplies the network-only comparison, which does not replace a privileged user signing factor.

Local material read:

- [SCHEME.md](/home/hoskinson/Projects/mpcexperiments/design/SCHEME.md), including the required sections, and [FACTS.md](/home/hoskinson/Projects/mpcexperiments/requirements/catalogue/FACTS.md). Thresholds, sealed/open guarantees, the copying impossibility, current adapters, rotation limits and benchmark scope.
- [Veritee README](/home/hoskinson/Projects/veritee/veritee-vm/README.md), [attested-channel implementation plan](/home/hoskinson/Projects/veritee/veritee-vm/docs/attested-channel-implementation-plan.md) and [TLS channel-binding design](/home/hoskinson/Projects/veritee/veritee-vm/docs/tls-channel-binding.md). Platform boundaries, intended Warden integration, deployed channel shape and remaining validation items.
- [AKX epoch code](/home/hoskinson/Projects/veritee/veritee-vm/server/akx/src/epoch.rs), [transcript code](/home/hoskinson/Projects/veritee/veritee-vm/server/akx/src/transcript.rs), [session code](/home/hoskinson/Projects/veritee/veritee-vm/server/akx/src/session.rs), [record code](/home/hoskinson/Projects/veritee/veritee-vm/server/akx/src/record.rs) and [epoch manager](/home/hoskinson/Projects/veritee/veritee-vm/server/akx/src/epoch_manager.rs). Exact wire binding, ciphersuite, caching and record behavior.
- [Attestation server](/home/hoskinson/Projects/veritee/veritee-vm/server/azure_attestation_server/src/main.rs) and [epoch attester](/home/hoskinson/Projects/veritee/veritee-vm/server/azure_attestation_server/src/enclave_key.rs). MAA/raw report wrapping, endpoint wiring and the ordinary-file epoch counter.
- [Measured setup](/home/hoskinson/Projects/veritee/veritee-vm/veritee-os/measured_setup/main.py), [egress policy code](/home/hoskinson/Projects/veritee/veritee-vm/veritee-os/measured_setup/egress.py) and [egress-proxy README](/home/hoskinson/Projects/veritee/veritee-vm/server/egress_proxy/README.md). PCR15, image integrity, egress enforcement and guest-root lifecycle-hook trust.

`VERITEE-MODEL.md` was absent. The companion Warden, specification and contract implementations were unavailable. Their required behavior is an explicit assumption in §5.1.