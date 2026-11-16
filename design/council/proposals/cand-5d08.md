## 1. Scheme in one paragraph

**This scheme spends from an existing Taproot address whose key-path secret the owner already controls.** The owner publishes one packet containing an encrypted, publicly verifiable Shamir sharing of that exact spending scalar and a signed transaction-building intent. The committee verifies the import, deterministically constructs the transaction from an agreed chain checkpoint, and permanently locks the request to that transaction **before releasing any signature share**. It then runs a BIP340-compatible FROST signing session. Failed sessions can retry only the locked transaction. Committee changes transfer both the sharing and the request record. This closes the one-message import and offline-owner workflow under static corruption. The single-spend restriction is an **honest-threshold policy**, supported by cryptography and replicated state. It cannot survive corruption of a reconstructing threshold, because that coalition can recover the ordinary spending key.

## 2. Setting and assumptions

Let \(G\) generate the signing group of prime order \(q\). The existing spending key is \(x\), with public key \(X=xG\).

Use:

\[
f=\left\lfloor\frac{n-1}{3}\right\rfloor,\qquad t=f+1.
\]

Here \(f\) is the maximum number of corrupt committee members, and \(t\) is the number of shares needed to reconstruct or sign. The cost examples use \(n=3f+1\).

| Component | Requirement |
|---|---|
| Owner | Honest during packet creation. Holds a sufficiently strong existing key and uses secure randomness. Sends one application message. |
| Committee | At most \(f\) statically corrupt members. Corruption includes malicious behavior and unavailable nodes. |
| Network | Synchronous authenticated links with known delivery bound \(\Delta\), allowing a stated processing allowance. |
| Request log | A Byzantine fault-tolerant replicated log with agreement, durable storage, data availability, and safe reconfiguration. |
| Availability | At least \(n-f\) committee members remain available for log progress. Once a signing package is fixed, \(t\) honest signers suffice for its cryptographic completion. |
| Source chain | Honest nodes validate the source chain independently. Accepted checkpoints remain stable, except with the chain’s stated finality-failure probability. |
| Owner packet delivery | The complete packet becomes available to honest nodes before its admission deadline and epoch cutoff. |
| Funding | Selected inputs remain unspent by parties outside this protocol. |
| Inclusion | Eventual confirmation additionally requires adequate fees and eventual inclusion of valid transactions. |
| Storage | Honest nodes preserve request locks and nonce-consumption records across crashes. Randomness remains secure after recovery. |

The corruption model is **static**, including across an authorized sequence of committee changes. A fixed adversarial set must satisfy the corruption bound in every participating committee. This is not a mobile-adversary claim.

Each committee member \(P_i\) registers:

- An authenticated identity key.
- A class-group encryption public key \(K_i\).
- A proof of knowledge of its encryption secret.
- A distinct scalar identifier \(i\).

Registration and parameter generation occur before the owner’s move. The owner reads an authenticated roster. Reading public parameters is not an additional owner message.

The cryptographic assumptions are:

1. The class-group hard-subgroup-membership, low-order, and strong-root assumptions used by cgVSS.
2. Correct generation of the class-group parameters and validation of registered keys.
3. Random oracles for the proof and signing hashes.
4. Discrete-log hardness for the owner’s authorization signature.
5. One-more discrete-log hardness for the threshold Schnorr security argument.
6. Collision resistance for packet, transaction, checkpoint, and state-record commitments.
7. Unforgeability of committee transport and consensus authentication.
8. Correct, consistent implementations of the transaction builder and native signature verifier.

There is no secret setup trapdoor. Public parameter generation must follow the class-group construction, with publicly checkable generation data. The owner is the dealer of an existing secret, not a dealer trusted to create a fresh committee key. [CG]

**Coverage is deliberately explicit.**

| Address type | Coverage |
|---|---|
| Existing Taproot address with a known key-path secret | Complete proposed import, construction, signing, and lifecycle protocol. |
| Existing Ed25519 key | The import and signing backend extend directly as described below. A particular chain still needs its transaction adapter. |
| Existing Bitcoin/Ethereum ECDSA key | The import mechanism applies. An ECDSA signing backend, its composition proof, and its concrete costs remain open in this document. |

FROST does not turn an ECDSA address into a Schnorr address.

## 3. Protocol

### Existing-key preparation

For Taproot, the owner deals the **effective output-key scalar**, after applying any Taproot tweak and the final even-\(y\) normalization.

Given an internal secret \(d_0\):

1. Normalize its internal public key:
   \[
   P=d_0G,\qquad d=
   \begin{cases}
   d_0,&y(P)\text{ even},\\
   q-d_0,&y(P)\text{ odd}.
   \end{cases}
   \]
2. Compute the prescribed Taproot tweak \(\tau\) from the internal x-only key and script-tree commitment.
3. Set \(a=d+\tau\bmod q\), rejecting invalid tweak cases and \(a=0\).
4. Normalize \(Q=aG\):
   \[
   x=
   \begin{cases}
   a,&y(Q)\text{ even},\\
   q-a,&y(Q)\text{ odd}.
   \end{cases}
   \]
5. Set \(X=xG\). Verify that the existing output script is exactly `OP_1 PUSH32 x_coordinate(X)`.

An owner who already holds the effective output secret starts at step 4. The committee applies **no further tweak**. This avoids carrying internal-key parity and tweak state through signing and resharing. The normalization and tweak rules follow the official [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) and [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) specifications.

For Ed25519, hash and prune the seed as specified, interpret the resulting scalar little-endian, and reduce it modulo the subgroup order. Deal that scalar, not the seed or the deterministic-nonce prefix. Verify its public point against the existing account key. [RFC8032, §5.1.5](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5)

### The owner’s message

The message is:

\[
M=(\text{envelope},D).
\]

The envelope contains every authorization field below. All integers, scripts, lists, and hashes have canonical encodings.

| Field | Meaning |
|---|---|
| `format_version` | Packet encoding version. |
| `suite_id` | Signing curve, signing algorithm, and proof suite. |
| `parameters_hash` | Exact class-group and hash parameters. |
| `chain_genesis` | Intended source-chain domain. |
| `board_id` | Intended request-log domain. |
| `initial_epoch`, `roster_hash` | Initial receiving committee and encryption keys. |
| `n`, `t` | Must equal the registered committee profile. |
| `owner_nonce` | Fresh 32-byte request nonce. |
| `source_address` | Exact existing output script or account descriptor. |
| `builder_hash` | Exact transaction-builder version and rules. |
| `admit_from`, `admit_until` | Request-log heights during which initial admission is permitted. |
| `required_anchor` | Source-chain checkpoint that the selected checkpoint must extend. |
| `min_source_height`, `max_state_age` | Bounds on acceptable source-chain state. |
| `recipient_script`, `amount` | Exact payment destination and amount. |
| `change_script` | Exact destination for change. |
| `fee_rule`, `fee_window` | Deterministic fee estimator and its history window. |
| `min_rate`, `max_rate`, `max_fee` | Fee bounds. |
| `dust_limit` | Minimum change and maximum permitted excess donation in the no-change case. |
| `min_confirmations`, `max_inputs` | Input eligibility limits. |
| `input_allowlist` | Up to eight outpoints, or empty to permit eligible outputs at the source address. |
| `tx_version`, `sequence`, `locktime_rule` | Exact transaction-format choices. |
| `sighash_mode` | Fixed to Taproot `SIGHASH_DEFAULT` in this profile. |
| `rotation_rule_hash`, `max_migrations` | Authorized committee succession rule and migration limit. |
| `dealing_hash` | Hash of \(D\). |
| `owner_seal` | Domain-separated Schnorr authorization signature under \(x\). |
| `padding` | Canonical zero padding for the fixed envelope format. |

The request identifier is:

\[
\mathit{rid}=H(\text{“request/v1”},\text{chain_genesis},
\text{board_id},X,\text{owner_nonce}).
\]

It excludes the epoch, ciphertext randomness, proof bytes, and seal bytes. Re-encoding or migrating a request does not create another allowance.

The owner seal signs the complete envelope, excluding the seal itself, including `dealing_hash`. Its challenge domain is distinct from native transaction signing. The committee exposes no endpoint that threshold-signs owner seals.

### Address-bound dealing

The owner samples:

\[
p(z)=x+a_1z+\cdots+a_{t-1}z^{t-1},
\qquad a_j\leftarrow\mathbb F_q.
\]

Let:

\[
s_i=p(i),\qquad A_j=a_jG,\qquad A_0=X.
\]

Use cgVSS with its plaintext modulus set to the **signing scalar order \(q\)**. Its commitment group is the signing curve, not a pairing curve with a different scalar field. [CG, §§3.3 and 5.2]

Write the class-group encryption bases as \(h\) and \(u\), where \(u\) generates the order-\(q\) subgroup with an efficient discrete-log solver. Recipient \(i\) has \(K_i=h^{d_i}\).

The ciphertexts are:

\[
R_{\rm enc}=h^r,\qquad C_i=K_i^r u^{s_i}.
\]

The dealing is:

\[
D=(R_{\rm enc},C_1,\ldots,C_n,A_0,\ldots,A_{t-1},\pi).
\]

The proof \(\pi\) establishes that all ciphertexts encrypt evaluations of the polynomial committed by the \(A_j\). It includes the envelope’s authorization context in its Fiat–Shamir domain.

For clarity, its compact structure is:

\[
\begin{aligned}
\gamma&=H_{\rm agg}(\mathrm{context},\mathrm{instance}),\\
K&=\prod_i K_i^{[\gamma^i]_q},&
S&=\sum_i s_i\gamma^i\bmod q,\\
W&=h^\rho,&U&=\alpha G,&V&=u^\alpha K^\rho,\\
c&=H_{\rm proof}(\mathrm{context},\gamma,W,U,V),\\
z_r&=\rho+cr\quad\text{over }\mathbb Z,&
z_s&=\alpha+cS\quad\text{over }\mathbb F_q .
\end{aligned}
\]

The proof is \((W,U,V,z_r,z_s)\). Verification checks:

\[
h^{z_r}=WR_{\rm enc}^{c},
\]

\[
z_sG=
U+c\sum_{j=0}^{t-1}A_j
\left(\sum_{i=1}^{n}i^j\gamma^i\bmod q\right),
\]

\[
u^{z_s}K^{z_r}
=
V\left(\prod_i C_i^{[\gamma^i]_q}\right)^c .
\]

Class-group exponent arithmetic must preserve the prescribed **integer** representatives. It must not reduce unknown-order exponents modulo \(q\).

The public verifier additionally checks:

- The authenticated roster and proof parameters.
- All encodings and prescribed group-validation rules.
- The proof’s response bounds.
- \(A_0=X\).
- The mapping from \(X\) to the claimed existing address.
- The owner seal.

The proof establishes correctness and key binding. It does not prove that the owner sampled its polynomial coefficients honestly. Privacy assumes an honest owner.

### Committee execution

The log enforces:

```text
UNSEEN -> LOCKED(rid, packet_hash, checkpoint, T, epoch)
       -> COMPLETE(rid, T, result)

UNSEEN -> REJECTED_OR_EXPIRED

LOCKED never returns to UNSEEN.
LOCKED never changes T.
```

Reject malformed packets before reserving their request identifiers.

| Phase | Committee action |
|---|---|
| Local validation | Verify the packet. Each node decrypts \(s_i\) and checks \(s_iG=\sum_j i^jA_j\). |
| Log decision 1: `LOCK` | Agree on admission, checkpoint, complete transaction \(T\), previous-output data, and input reservations. |
| Signing round 1 | Selected signers generate fresh FROST nonce pairs and send authenticated commitments. |
| Log decision 2: `PACKAGE` | Agree on the signer list, commitments, nonce identifiers, input index, and locked transaction digest. Consume the nonce identifiers for this package. |
| Signing round 2 | Each selected signer recomputes the native sighash and releases one signature share for that package. |
| Output | Aggregate, verify with the native verifier, assemble witnesses, publish the transaction, and retain a result receipt. |

A `COMPLETE` log entry is useful for retrieval and cleanup. Safety does not wait for it. The earlier `LOCK` already prohibits another transaction.

For signing set \(S\), derive Lagrange coefficients \(\lambda_i\). Each signer has fresh nonces \(d_i,e_i\) and commitments \(D_i=d_iG,E_i=e_iG\). Compute FROST binding factors \(\rho_i\) over the public key, native message, and canonical commitment list.

Let:

\[
R_0=\sum_{i\in S}(D_i+\rho_iE_i).
\]

For BIP340, set \(\nu=1\) when \(R_0\) has even \(y\), otherwise \(\nu=-1\). Set \(R=\nu R_0\), then:

\[
c=H_{\rm BIP340/challenge}(R_x\|X_x\|m)\bmod q,
\]

\[
z_i=\nu(d_i+\rho_i e_i)+c\lambda_i s_i.
\]

Verify:

\[
z_iG=\nu(D_i+\rho_iE_i)+c\lambda_iY_i,
\qquad
Y_i=\sum_j i^jA_j.
\]

Finally:

\[
z=\sum_{i\in S}z_i,\qquad \sigma=R_x\|\operatorname{bytes}_{32}(z).
\]

The resulting signature satisfies the BIP340 verification equation.

For Ed25519, use the RFC 9591 Ed25519 suite without BIP340 parity normalization. Its verification-compatible randomized signatures do not require the seed’s nonce prefix. [F]

**Retries use fresh nonces and the same \(T\).** A bad share identifies a faulty signer. Under synchrony, a nonresponding selected signer can be excluded through the log. After exclusion, select another set and repeat.

Persist nonce consumption before sending a share. A retransmission may resend the identical stored share. It must not recompute a share under a different package using the same nonces.

## 4. Transaction construction

The first implementation supports a narrow Bitcoin template:

- Taproot key-path inputs, all controlled by the imported output key.
- One exact payment output.
- Optional change to the owner-specified script.
- At most eight inputs.
- No annex, script-path spend, additional outputs, or permissive sighash flags.

The request log contains an ordered feed of validated source checkpoints. A request uses the latest eligible checkpoint preceding its admission position. The checkpoint must satisfy the owner’s ancestry, height, and age constraints.

Bitcoin headers do not commit to a native UTXO-set root. Each honest replica therefore reconstructs the relevant state through a validated full-node view. A relayer’s claimed UTXO list is insufficient.

Define the builder as a pure function:

\[
T=B(\mathrm{intent},\mathrm{checkpoint\ state},\mathrm{reservations}).
\]

Its algorithm is:

1. Identify confirmed, unspent, unreserved outputs with the exact source script.
2. Apply the allowlist, if present.
3. Sort by a specified canonical outpoint ordering.
4. Compute an integer target feerate from the prescribed historical window. For example, take the ceiling of the median transaction feerate over the preceding 100 blocks, then apply the authorized bounds.
5. Examine input prefixes in order, stopping at `max_inputs`.
6. For each prefix, compute the exact signed transaction weight using 64-byte Taproot signatures.
7. First attempt a payment-plus-change transaction.
8. If change would be below `dust_limit`, attempt the authorized no-change case. Bound the excess donation and total fee.
9. Select the first valid result. Return failure if none exists.
10. Set every remaining transaction field according to the envelope and builder version.

Use integer arithmetic throughout. Check monetary bounds and overflow.

For \(k\) inputs and two P2TR outputs, this restricted template has:

\[
\mathrm{weight}=386+230k,
\qquad
\mathrm{vsize}=\left\lceil\frac{386+230k}{4}\right\rceil.
\]

A one-input, two-output transaction is therefore 154 virtual bytes. Actual serialization must confirm this calculation.

Every signer independently verifies:

\[
\sum \mathrm{inputs}
=
\mathrm{payment}+\mathrm{change}+\mathrm{fee},
\]

the exact destination scripts, fee bounds, reservations, and all sighash inputs. Taproot `SIGHASH_DEFAULT` commits to the transaction’s inputs and outputs under the specified rules. [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

**The builder never changes a locked transaction.** A fee increase, stale input, or deep reorganization can make that transaction unusable. The committee cannot silently substitute another spend.

For an account-chain extension, the corresponding lock must include the account nonce, exact call or transfer, gas limit, fee fields, and chain domain. That adapter is outside the complete Taproot profile.

The admission deadline limits when the request can first become active. It is not a native transaction expiry. Once signatures exist, this protocol cannot make Bitcoin reject them merely because an off-chain deadline passed.

## 5. Committee change

The owner chooses one of two policies through `rotation_rule_hash`.

**Drain the original committee.** The original committee completes admitted requests before retiring the required nodes and encryption keys. Unadmitted packets naming a retired epoch are rejected.

**Permit migration.** The owner authorizes a precisely identified succession rule and a maximum number of migrations. A governance rule authorizing future rosters is an additional trust decision expressed in the owner’s message.

Migration proceeds as follows:

1. Commit a freeze point in the request log.
2. Transfer the complete request state, including:
   - Original owner packet.
   - Admission checkpoint.
   - Locked transaction and previous-output data.
   - Input reservations.
   - Completed-result records and replay tombstones.
   - Consumed signing-package identifiers.
3. Each participating old member deals its old scalar share to the new committee using the same verifiable-encryption mechanism.
4. For old dealer \(i\), require its new polynomial’s constant commitment to equal its old verification key \(Y_i\).
5. Agree on a valid old-dealer subset \(S\) of size \(t_{\rm old}\).
6. Compute:
   \[
   s'_j=\sum_{i\in S}\lambda_i^S p_i'(j).
   \]
7. Verify the new constant commitment:
   \[
   A'_0=\sum_{i\in S}\lambda_i^S Y_i=X.
   \]
8. Obtain new-committee readiness and activate through safe log reconfiguration.
9. Discard old signing attempts. Generate fresh nonce material for the new sharing.

The owner does nothing.

The new committee must retain the same locked \(T\), even if the old committee might already have completed a signature privately. A fresh signature on that same transaction is permissible. A different transaction is not.

State transfer and key transfer are separate obligations. Correct resharing alone does not preserve authorization.

This construction requires enough old members to transfer the sharing. If they have disappeared before handover, the original ciphertexts cannot simply be decrypted by the new committee. The request can stall permanently.

This is static-security resharing. It does not establish proactive security against an attacker who accumulates old decryption keys over time.

## 6. Security

### Ideal functionality

Define an ideal functionality \(\mathcal F_{\rm owner\text{-}spend}\), parameterized by a source-chain interface, request log, builder, signature scheme, and succession rule.

The honest owner calls:

\[
\operatorname{Authorize}(x,I)
\]

once. The functionality publishes \(X=xG\), the authorized intent \(I\), and permitted public metadata. The owner then takes no further part.

For each request, the functionality maintains:

\[
(\mathit{rid},X,I,\mathrm{epoch},S,T,\mathrm{status}).
\]

Its operations are:

- **Admit:** Check the authorization, epoch, freshness bounds, and request uniqueness.
- **Lock:** Choose the log-determined admissible state \(S\). Compute \(T=B(I,S)\). Reserve its inputs and make \(T\) immutable.
- **Sign:** Release valid native signatures only for the inputs of \(T\).
- **Retry:** Permit another signing attempt for the same \(T\).
- **Rotate:** Transfer the record to an owner-authorized successor without changing \(T\).
- **Complete:** Publish the transaction and preserve its replay record.

The functionality models one transaction’s effects, not one unique signature string. Retries can produce different signatures for the same unsigned transaction.

For fewer than \(t\) corrupt members, it leaks public metadata and their permitted share state. If a reconstructing threshold is corrupt, it permits disclosure of \(x\) and arbitrary signing. Omitting that escape condition would describe a functionality this construction cannot realize.

The following are proof sketches for the proposed composition. They are not a claim that an existing paper proves this complete spending protocol.

### Claim 1: The import is bound to the existing address

An accepted proof establishes that ciphertext plaintexts are evaluations of a polynomial with coefficient commitments \(A_j\). The explicit equality \(A_0=X\) fixes its constant term to \(x\), since multiplication by \(G\) is injective over \(\mathbb F_q\).

The address check fixes \(X\) to the actual spending public key. Registered encryption keys ensure honest recipients can decrypt their corresponding shares.

This proves decryptable, consistent delivery under the encryption and proof assumptions. It does not prove that an unavailable machine has already processed the packet.

### Claim 2: A subthreshold coalition learns no additional key information

The privacy statement is computational and relative to the public key \(X\), public commitments, and authorized outputs.

For at most \(f=t-1\) corrupt recipients, Shamir shares can be simulated consistently with \(X\). The remaining coefficient commitments can be constructed through interpolation in the exponent. Zero knowledge hides the proof witnesses, and encryption hides honest recipients’ shares.

This follows the structure of cgVSS’s static privacy argument. It does not provide information-theoretic secrecy in the presence of public discrete-log commitments. [CG, Appendix E]

### Claim 3: A subthreshold coalition cannot obtain an unauthorized signature

Define the authorized transaction set:

\[
\mathcal A(I)=\{B(I,S):S\text{ satisfies the owner’s state constraints}\}.
\]

The log selects at most one \(T\in\mathcal A(I)\).

An honest signer issues a share only for a committed package referring to that \(T\). A successful attack must therefore do at least one of the following:

- Forge an owner authorization.
- Break log agreement or state integrity.
- Find a relevant hash collision.
- Exploit inconsistent transaction interpretation.
- Forge a threshold signature without sufficient authorized participation.

The threshold-signature reduction uses FROST’s binding factors and one-use nonces. For BIP340, the publicly determined sign \(\nu\) is applied consistently to every nonce contribution. The final verification equation is exact. A complete reduction covering this parity adaptation and the import composition remains a required formal deliverable.

The Ed25519 signing variant uses the existing RFC suite unchanged. [F]

### Claim 4: Replaying a request cannot authorize another spend

The request identifier is stable across copies, re-encodings, retries, and migration.

The log records the transaction lock before any share is released. Replaying the packet finds the same record. A failed signing attempt cannot reopen it. Migration carries the same record and tombstone.

Within a stable canonical Bitcoin history, repeated publication of the same transaction cannot consume its inputs twice.

This guarantee excludes replay onto another compatible fork whose native consensus rules also accept the transaction.

### Claim 5: Honest nodes finish without the owner

A valid dealing gives every honest recipient a usable signing share. No complaint-resolution or conversion step calls the owner.

After an honest log leader and sufficient available replicas establish a package, an all-honest signing set completes FROST. A faulty selected signer either supplies a valid share or causes an identifiable failure or timeout. Excluding faulty signers eventually yields an honest set.

Under stable synchrony, at most \(f\) such exclusions are necessary, apart from negligible cryptographic failure events. Log leader changes add the selected consensus protocol’s recovery cost.

This guarantees production and publication of a valid transaction under the stated funding and chain-state conditions. Confirmation additionally depends on source-chain inclusion.

### Claim 6: Rotation preserves the key and authorization

Lagrange interpolation gives:

\[
\sum_{i\in S}\lambda_i^S s_i=x.
\]

Each old dealer’s proof binds its new polynomial to that old share. Consequently the new sharing has constant \(x\).

Authenticated, atomic state transfer preserves the immutable transaction record. Together these establish key preservation and policy preservation under the static corruption bounds.

### Why a cryptographic single-use restriction is unavailable here

A coalition holding \(t\) shares computes:

\[
x=\sum_{i\in S}\lambda_i^S s_i.
\]

It can then invoke the ordinary native signing algorithm on any message.

Neither a signed intent, a zero-knowledge proof, a counter, nor a claimed erasure prevents that computation. This is an incompatibility between **reconstructible full-key import** and **restriction against a reconstructing coalition**.

A stronger design must change a premise: retain an indispensable owner contribution, use an external enforcement mechanism, change the account’s validation rules, or avoid delivering reconstructible signing-key state.

## 7. Costs

### Concrete encoding profile

The following are calculated application-level sizes and operation counts, **not measurements**.

Use a conservative fixed-width class-group profile:

- Signing scalars: 32 bytes.
- Signing-curve point slots: 33 bytes.
- Class-group elements: 512 bytes.
- Integer proof response \(z_r\): 384 bytes.
- Scalar proof response \(z_s\): 32 bytes.
- Complete authorization envelope: 1,024 bytes.

The envelope fields listed above occupy 854 bytes in the bounded Taproot format, including eight outpoint slots and a 65-byte owner seal. The remaining 170 bytes are zero padding.

For the class-group representation, encode the two necessary coefficients of a reduced quadratic form in fixed 256-byte slots, recovering the third from the public discriminant. Require a discriminant bound that makes these slots sufficient.

A suitable parameter profile uses the prescribed class-group generation with a roughly 3072-bit base discriminant and the signing-field conductor. Require a public unknown-order subgroup bound below \(2^{1920}\). Sampling encryption exponents from \([0,2^{2048})\) then provides at least 128 bits of statistical smoothing.

The proof mask range is \(q2^{2048}2^{128}\). Thus \(z_r<2^{2433}\), which fits the reserved 384 bytes. These bounds must be checked by the parameter implementation.

This deliberately avoids treating the paper’s compressed benchmark encoding as a complete serialization specification for a different curve and parameter profile.

### Owner packet and cryptographic work

There are:

- \(n+1\) class-group ciphertext elements.
- Two additional class-group proof elements.
- \(t\) coefficient commitments.
- One curve proof element.
- Two proof responses.

Therefore:

\[
|M|=1024+512(n+3)+33(t+1)+384+32.
\]

| Quantity | \(n=16\) | \(n=64\) | \(n=256\) |
|---|---:|---:|---:|
| Fault bound \(f\) | 5 | 21 | 85 |
| Signing threshold \(t\) | 6 | 22 | 86 |
| Owner packet, bytes | 11,399 | 36,503 | 136,919 |
| Owner packet, KiB | 11.13 | 35.65 | 133.71 |
| Owner class-group exponentiation terms | 35 | 131 | 515 |
| Owner curve multiplication terms | 8 | 24 | 88 |
| Owner Horner field multiplications | 80 | 1,344 | 21,760 |
| Import verification/decryption class-group terms per node | 37 | 133 | 517 |
| Curve terms per selected node, import plus one signature | 68 | 580 | 7,748 |

A “term” counts one base–exponent pair before multiexponentiation optimization. It is not a claim that all terms take equal time.

**Owner derivation.**

- \(n+1\) class-group exponentiations for encryption.
- Two long exponentiations for proof commitments.
- One \(n\)-term class-group multiexponentiation.
- Total: \(2n+3\) terms.
- Additionally, \(n+1\) efficient powers in the easy order-\(q\) subgroup.
- \(t\) curve coefficient commitments, one proof commitment, and one owner-seal commitment: \(t+2\) curve terms.
- Horner evaluation: \(n(t-1)\) field multiplications.

Key preparation adds at most a small constant number of curve operations and hashes. An uncached roster also requires its certificate validation and, if independently checked, \(n\) encryption-key proof verifications.

**Receiver derivation.**

Verify two \(n\)-term class-group multiexponentiations and four single exponentiations, then perform one decryption exponentiation:

\[
2n+5.
\]

Also perform one easy-subgroup discrete-log recovery.

The curve count uses a deliberately straightforward implementation:

- Derive \(t\) selected verification keys with \(t\)-term multiscalar multiplications.
- Verify the dealing’s curve equation and owner seal.
- Check the local decrypted share.
- Generate nonce commitments.
- Compute the group nonce.
- Verify all selected signature shares and the final signature.

This gives:

\[
t^2+4t+8
\]

curve multiplication terms. Transport-signature verification is additional.

Field work for proof weights is \(O(nt)\). Lagrange computation is \(O(t^2)\) without caching. Hashing and parsing are linear in packet size.

### Rounds

| Work | Rounds |
|---|---|
| Public parameter generation | Local setup computation. |
| Epoch encryption-key registration | One publication phase plus roster agreement. |
| Request-specific offline MPC | None required. |
| Owner | One posted message. |
| Successful committee attempt | Two log decisions and two FROST communication rounds. |

For an illustrative normal-case log implementation with three message delays per decision:

\[
3+1+3+1=8
\]

message delays after packet and source-state availability, plus computation.

At \(\Delta=100\) ms, this contributes approximately 0.8 seconds of network delay. It is not an end-to-end latency prediction.

With an honest leader, an explicit exclusion decision after each failed attempt gives at most:

\[
1\ \mathrm{LOCK}+(f+1)\ \mathrm{PACKAGE}+f\ \mathrm{EXCLUDE}
\]

log decisions and \(2(f+1)\) signing rounds. The illustrative delay budget is \(8(f+1)\) slots, excluding leader replacement and chain waiting.

### Communication per node

For one input:

- Nonce-commitment packet: 194 bytes.
- Signature-share packet: 160 bytes.
- Combined signing traffic per signer: 354 bytes per destination.

These include 128-byte authenticated headers.

Budget each log decision at three 128-byte control transmissions per peer, with proposal bodies counted separately. Two decisions therefore cost at most \(768(n-1)\) control bytes sent and received per node.

Use a 512-byte lock proposal and an \(84t\)-byte signing-package body.

| Application traffic | \(n=16\) | \(n=64\) | \(n=256\) |
|---|---:|---:|---:|
| Signing bytes sent by each selected signer | 5,310 | 22,302 | 90,270 |
| Signing bytes received from other selected signers | 1,770 | 7,434 | 30,090 |
| Two-decision log control budget, per direction | 11,520 | 48,384 | 195,840 |
| Selected nonleader total sent | 16,830 | 70,686 | 286,110 |
| Selected leader total sent, including proposal bodies | 32,070 | 219,366 | 2,258,790 |
| Selected node total received, including owner packet | 25,705 | 94,681 | 370,585 |

Derivations:

\[
\begin{aligned}
\mathrm{nonleader\ send}&=1122(n-1),\\
\mathrm{leader\ send}&=(1634+84t)(n-1),\\
\mathrm{selected\ receive}&=|M|+768(n-1)+354(t-1)+512+84t.
\end{aligned}
\]

An unselected observer can receive one additional signer’s 354-byte contribution. It does not send signing contributions.

The transport-authentication verification budget is at most 102, 422, and 1,702 verifications respectively under this accounting.

Add \(W\) bytes per node for any source-state data absent from its validated local cache. \(W\) depends on the chain and checkpoint, not just \(n\). Initial blockchain synchronization, TCP/TLS framing, consensus recovery, and source-chain broadcast are outside these application-byte totals.

Multiple input signatures can run in parallel. They require independent nonce material. Dealing verification is paid once, while signing work and package payloads scale with the number of inputs.

### Setup and migration costs

An epoch registration record with a 512-byte encryption key, 416-byte proof, and 128-byte header is 1,056 bytes. Direct dissemination costs each node \(1056(n-1)\) bytes per direction, plus roster agreement.

A simple migration lets all old members publish new dealings. For equal-sized committees, the cryptographic payload is:

\[
n\bigl(|M|-1024\bigr).
\]

That is 166,000 bytes, 2,270,656 bytes, and 34,789,120 bytes respectively, before handover headers and state transfer. Each new node receiving all dealings pays that download cost.

Selecting only \(t_{\rm old}\) cooperative dealers reduces the normal-case payload, but needs a retry schedule for faulty dealers. Migration is substantially more expensive than signing.

## 8. Gaps closed and left open

| REPORT.md §5.1 gap | Result |
|---|---|
| **1. Address-bound import in one message** | Closed in the static model: target-field encryption, target-curve commitments, \(A_0=X\), address validation, and one owner packet. Adaptive security remains open. |
| **2. Dealt shares to signing state** | Closed for the Schnorr path. The decrypted shares and verification keys are directly usable. ECDSA backend integration remains open. |
| **3. Single-transaction capability** | Enforced by honest-threshold policy and immutable request state. Cryptographic restriction against a reconstructing coalition is incompatible with this full-key import. |
| **4. Committee transaction construction** | Specified for the restricted Taproot template. Other transaction types and account-chain adapters remain open. |
| **5. Joined formal model** | A functionality and claim-by-claim reduction outline are supplied. A complete composition proof, including the BIP340 adaptation, remains open. |
| **6. Requests across committee change** | Specified through drain or authorized migration, including transaction locks and replay records. Liveness requires old-share availability and safe reconfiguration. |

Among the report’s additional gaps, the proposal addresses key-format handling. It does not establish adaptive committee sizing, enforce destruction of the owner’s original key, provide request privacy, or supply measured end-to-end latency.

## 9. Comparison with Form A and Form B

| Property | Form A in the report | Form B in the report | This proposal |
|---|---|---|---|
| Signing authority | Committee collectively holds the full key. | Owner retains an indispensable share. | Committee collectively holds the imported full key. |
| Owner move | Authenticated request to an existing signing service. | Transaction-bound partial signature, using available signing preparation. | One packet combining import and a construction intent. |
| Existing address | Requires a separate import mechanism. | Imported-key flow described in the report has additional enrollment steps. | Direct import of the existing Taproot output scalar. |
| Transaction bytes | Supplied to the service. | Bound before the owner’s final contribution. | Constructed afterward from authorized rules and agreed state. |
| Full-threshold collusion | Can sign arbitrary messages. | Cannot replace the required owner contribution for another message. | Can sign arbitrary messages. |
| Replay prevention | Application policy. | Partial-signature binding plus application and native-chain rules. | Immutable transaction lock, permanent request identity, and native input consumption. |
| Owner cost | Small once enrolled. | Depends on the owner-share protocol and preparation. | Linear in committee size. |
| Committee change | Service-specific lifecycle. | Must also preserve compatible pending signing material. | Transfer key sharing and request state together. |

This is a concrete extension of **Form A**, with its custody assumption preserved.

Form B remains preferable when resistance to a malicious network threshold is essential and the owner can bind the exact transaction before leaving. Allowing the committee to choose previously unknown transaction bytes requires an additional restricted-signing construction. A transaction-bound partial signature alone does not provide that freedom.

The local Ika future-signing documentation confirms that its stored partial signature is tied to supplied message bytes and a consumed presignature. Its imported-key documentation also distinguishes the ECDSA preparation path. These documents support the workflow comparison, not an independently checked end-to-end cryptographic theorem. [I1, I2]

## 10. Risks and attacks you considered

- **Threshold collusion:** Recovers \(x\). It defeats authorization, single use, and any off-chain expiry. This design does not stop it.
- **Later compromise of encryption keys:** Public ciphertexts remain decryptable using retained epoch secrets. Erasing signing shares alone does not solve this.
- **Owner-key compromise:** The original owner key remains valid. Import neither revokes it nor proves its destruction.
- **Cross-fork replay:** Bitcoin signatures do not enforce the envelope’s chain identifier. An already signed transaction may also be valid on a compatible fork.
- **Deep reorganization or external double spend:** Can invalidate the pinned transaction. The committee must not rebuild a different spend.
- **Fee changes:** A fixed authorized transaction may cease to be economically attractive. Automatic replacement is outside the single-transaction policy.
- **Hidden completed signature:** A faulty aggregator may conceal completion and request a retry. The immutable \(T\) makes retries safe at the transaction-effect level.
- **Nonce reuse and snapshot rollback:** Can expose signing shares. Global package consumption, durable local records, and secure fresh randomness are necessary.
- **Rogue recipient keys:** Addressed through authenticated registration and knowledge proofs. Skipping registration validation invalidates the security argument.
- **Malformed class-group objects or oversized responses:** Require canonical parsing, parameter checks, response bounds, and computational limits before expensive verification.
- **Wrong Taproot scalar:** Importing the internal key instead of the effective output key fails address binding. Applying the tweak twice also fails.
- **Ed25519 subgroup errors:** Require strict subgroup and canonical-encoding checks throughout the import and signing interface.
- **Builder disagreement:** Different serialization, fee rounding, UTXO ordering, or previous-output interpretation can break safety. Nodes must agree on executable builder semantics.
- **Malicious checkpoint selection:** The owner’s bounds constrain admissible states. They do not guarantee the most favorable price or fee within those bounds.
- **Rotation without request history:** Can recreate spending authority. Key resharing without replay-state transfer is unsafe.
- **Request-channel abuse:** Size limits and cheap authorization checks reduce verification attacks. Service admission and resource charging still need implementation.
- **Metadata exposure:** The public packet reveals the address, intent, committee, and policy. Request privacy is not provided.

## 11. Experiment plan

Build the prototype in stages, beginning with the imported scalar and native verification boundary.

1. **Implement the target-field dealing.**  
   Add an experimental module under `experiments/owner_move/`. Instantiate class-group encryption with the secp256k1 scalar order. Serialize the complete packet and independently verify its equations. Measure actual sizes against the fixed-width budget.

2. **Demonstrate an existing-address spend.**  
   Fund a Taproot address in Bitcoin regtest before creating any committee state. Exercise both public-key parities and both empty and nonempty script-tree commitments. Create the owner packet, terminate the owner process, and let committee processes produce a transaction accepted by Bitcoin Core.

3. **Connect dealt shares to signing without reconstruction.**  
   Load only each node’s own decrypted scalar and public verification data. Check that no node or coordinator receives \(x\). Test threshold subsets, invalid shares, silent signers, and fresh-nonce retries.

4. **Implement the deterministic builder.**  
   Use fixed checkpoint fixtures covering UTXO ordering, fee bounds, change, dust donation, insufficient funds, conflicting reservations, and multiple inputs. Compare independently serialized transaction bytes and native sighashes.

5. **Implement the request state machine.**  
   Inject crashes before and after `LOCK`, `PACKAGE`, share transmission, and publication. Replay the original packet after every crash. Test an aggregator that completes a signature but reports failure.

6. **Implement committee transfer.**  
   Start with disjoint committees. Migrate during import, after transaction locking, and after possible hidden completion. Verify that the new public key is identical and that the transaction lock never changes.

7. **Measure \(n=16,64,256\).**  
   Record owner computation, every serialized component, per-node CPU time, memory, bytes sent and received, and wall-clock completion. Separate setup, import, agreement, signing, retries, source-state acquisition, and migration.

8. **Complete the security reduction.**  
   Formalize the authorization game and the BIP340 FROST adaptation. Treat cgVSS-to-signing composition and reconfiguration as explicit proof obligations.

The design is falsified if any of these occurs under its stated assumptions:

- An accepted dealing decrypts to inconsistent shares or a key different from the existing address key.
- At most \(f\) corrupt members produce a signature outside the locked transaction.
- One owner packet causes two distinct transaction locks, including after migration or recovery.
- Nonce material is consumed by two different signing packages.
- Available honest nodes cannot finish after all faulty selected signers are excluded.
- Completion requires another owner message.
- A purported valid output fails the native chain verifier.

An encoding that exceeds the specified bounds falsifies the cost profile. Poor measured performance can reject the efficiency choice without constituting a cryptographic break.

## 12. References

**[R] State-of-the-art report — read in full (local path).**  
[research/REPORT.md](research/REPORT.md). Defines Form A, Form B, and the gap list used here. Detailed lane findings informed the selection and lifecycle questions.

**[CG] Aniket Kate, Easwar Vivek Mangipudi, Pratyay Mukherjee, Hamza Saleem, and Sri AravindaKrishnan Thyagarajan. _Non-interactive VSS using Class Groups and Application to DKG_ — read in full (local path).**  
[research/sources/eprint/2023-451.pdf](research/sources/eprint/2023-451.pdf). The 23-page local version, including appendices. Figures 1 and 4 specify the dealing and proof. Table 1 separates class-group and curve costs. This is the newer local paper, rather than the anonymous draft used in the report.

**[F] RFC 9591. _The Flexible Round-Optimized Schnorr Threshold Protocol for Two-Round Schnorr Signatures_ — read in full (local path).**  
[research/sources/lifecycle/rfc9591.txt](research/sources/lifecycle/rfc9591.txt). Includes the complete specification, security considerations, dealer construction, and test vectors.

**[I1] Ika documentation, _Future Signing_ — read in full (local path).**  
[future-signing.mdx](research/sources/owner-share/docs/move-integration__protocols__future-signing.mdx).

**[I2] Ika documentation, _Key Importing_ — read in full (local path).**  
[key-importing.mdx](research/sources/owner-share/docs/move-integration__protocols__key-importing.mdx).

The BIP340, BIP341, and RFC8032 specification clauses linked inline were checked on their official online sources. They are not represented as full local reads. No research-paper claim in this document relies on an abstract-only citation.