# One-Shot Address-Bound Threshold Spend (OBTS)

## 1. Scheme in one paragraph

**OBTS works directly on existing cryptocurrency addresses**—plain secp256k1 ECDSA keys (Bitcoin P2PKH/P2WPKH, Ethereum EOAs), secp256k1 BIP-340 Schnorr keys (Bitcoin Taproot P2TR), and Ed25519 keys (Solana, Sui, Aptos, NEAR)—without pre-creating a committee-controlled address or requiring a second owner interaction. The owner normalizes the existing address secret into its canonical curve scalar $x_{\text{eff}} \in \mathbb{F}_q$ (applying SHA-512 clamping modulo $\ell$ for Ed25519 or BIP-340 even-$y$ parity and Taproot tweaking for P2TR), publishes a single non-interactive **Address-Bound Class-Group Verifiable Secret Sharing (`AB-cgVSS`)** message over a transparent Castagnos–Laguillaumie class group $\hat{\mathbb{G}} = \mathbb{G}_q \oplus \mathbb{F}$ whose easy-discrete-log subgroup $\mathbb{F}$ has prime order $q$ equal to the signature curve's scalar field, fixes the constant Feldman commitment directly to the on-chain public key ($A_0 = X_{\text{eff}}$), binds a bounded spending `Intent` into both the Fiat–Shamir proof of correct sharing (`PoCS`) and an outer native signature $\sigma_{\text{auth}}$ under $x_{\text{eff}}$, and goes permanently offline. Upon observing this single message, a committee of $n$ MPC nodes filters spam in $50\,\mu\text{s}$ via $\sigma_{\text{auth}}$, publicly verifies $A_0 = X_{\text{eff}}$ and `PoCS`, locally decrypts plain Shamir shares $x_i \in \mathbb{F}_q$ with zero owner-assisted state conversion, commits a finalized target-chain snapshot `AnchorCert` via BFT consensus so every honest node deterministically constructs the exact same transaction and `sighash`, and completes threshold signing in **one post-anchor online round** from pre-stocked, key-independent presignatures—using **FROST + ROAST** for BIP-340 and Ed25519, or **Trout++ + ROAST** over the exact same class group $\hat{\mathbb{G}}$ for secp256k1 ECDSA.

---

## 2. Setting and assumptions

### 2.1 Parties and decoupled thresholds

- **Owner ($\mathcal{O}$)**: Holds the secret material $\mathsf{sk}_{\mathcal{O}}$ of an existing target-chain address $\mathsf{addr}$ (a 32-byte secp256k1 scalar for ECDSA/Taproot or a 32-byte RFC 8032 seed for Ed25519). $\mathcal{O}$ reads public parameters and epoch committee public keys, posts one message $\mathsf{Msg}_{\mathcal{O}}$ to a public request channel (host BFT chain or gossip bulletin board), and goes permanently offline. $\mathcal{O}$ never reads presignatures or live committee state prior to posting.
- **Committee ($\mathcal{C}_e = \{P_1, \dots, P_n\}$)**: A set of $n$ MPC servers active in epoch $e$, indexed by distinct public evaluation points $i \in \{1, \dots, n\} \subset \mathbb{F}_q^\times$.
- **Target blockchain ($\mathcal{L}_{\text{target}}$)**: An unmodified external L1 (e.g., Bitcoin, Ethereum, Solana) that validates standard single-key ECDSA, BIP-340 Schnorr, or Ed25519 transactions and knows nothing about the committee.
- **Decoupled fault and reconstruction thresholds**:
  - **Byzantine fault bound**: $f = \lfloor (n - 1)/3 \rfloor$ (so $n \ge 3f + 1$; for $n = 16, 64, 256$, $f = 5, 21, 85$). Up to $f$ nodes may behave arbitrarily while preserving consensus safety, liveness, and asynchronous signing termination.
  - **Shamir reconstruction / signing threshold**: $t \in [f + 1, n - f]$, meaning a polynomial of degree $t - 1$ requires $t$ shares to reconstruct or sign. Following ROAST and Trout++, our **primary configuration** sets
    $$t = n - f = \lceil (2n + 1)/3 \rceil \quad (11\text{-of-}16,\; 43\text{-of-}64,\; 171\text{-of-}256).$$
    Decoupling $t = n - f$ from $f < n/3$ gives asymmetric protection: **liveness holds against $f < n/3$ Byzantine faults**, while **key secrecy and cryptographic intent enforcement hold against up to $t - 1 = n - f - 1 \approx \frac{2}{3}n$ corruptions** ($10, 42, 170$ nodes), because every signing quorum $S$ of size $t$ intersects any honest set of size $\ge f + 1$ in at least one honest node. Where an operator prioritizes lower online quorum verification CPU under a strict $< n/3$ corruption ceiling, OBTS also supports the **fast-quorum configuration** $t_{\text{fast}} = f + 1$ ($6\text{-of-}16,\; 22\text{-of-}64,\; 86\text{-of-}256$).

### 2.2 Network model

OBTS separates its network assumptions cleanly by layer:

1. **Owner submission**: One-shot non-interactive broadcast. $\mathsf{Msg}_{\mathcal{O}}$ must reach at least one honest committee node (or be included in a host-chain block) prior to `Intent.expiry_height`.
2. **Chain-state anchoring and request ordering (`AnchorCert`)**: **Partially synchronous** BFT state-machine replication (SMR, e.g., HotStuff or Mysticeti with $f < n/3$): consensus safety and single-spend exclusion hold unconditionally across arbitrary network partitions; liveness holds after Global Stabilization Time (GST), where messages between honest nodes arrive within unknown bounded delay $\Delta$. *(Note: If the committee instead runs an Asynchronous Common Subset [ACS] protocol over finalized target-chain light-client headers, anchoring is also asynchronous with $f < n/3$.)*
3. **Offline presigning and online threshold signing (`FROST + ROAST` and `Trout++ + ROAST`)**: **Fully asynchronous** authenticated point-to-point channels among committee nodes with eventual delivery and no timing assumptions. Guaranteed output delivery (robustness) holds against $f < n/3$ malicious nodes via publicly verifiable identifiable abort (PVIA).

### 2.3 Corruption model and erasures

- **Proven corruption model**: **Malicious, static** adversary $\mathcal{A}$ that selects a set $\mathcal{K} \subset \mathcal{C}_e$ of corrupt nodes prior to epoch key registration, with $|\mathcal{K}| \le f$ for end-to-end safety and liveness, and $|\mathcal{K}| \le t - 1$ for key secrecy and intent unforgeability. Static corruption is the strongest model in which standard-assumption proofs exist for `cgVSS`, `FROST`/`ROAST`, and `Trout++` without interactive per-dealing non-committing encryption or double-blind Pedersen share commitments.
- **Erasure model (proactive / post-spend hygiene)**: Honest nodes are **erasure-capable**. Immediately after observing a finalized spend (or `expiry_height`) for `req_id`, each honest $P_i$ overwrites and zeroizes the transient Shamir share $x_i$ and ECDSA key-setup randomness $\delta_i$. Upon epoch rotation $e \to e + 1$, each honest $P_i$ zeroizes its epoch decryption scalar $\mathsf{sk}_{e,i}$. These erasures are not needed for the static-security reductions, but provide forward secrecy against post-spend and post-epoch compromise.
- **Adaptive corruption posture and sizing**: Under fully adaptive corruptions without interactive mask exchange, simulation of `AB-cgVSS` ciphertexts faces the standard selective-opening / non-committing encryption barrier, and Feldman commitments $X_i = x_i E$ prevent equivocating newly corrupted signing shares (analyzed in Section 10.4). Operationally, against a global adaptive/covert adversary capable of corrupting a fraction $\beta \in \{0.20, 0.25\}$ of the validator population before spend completion, sampling $\mathcal{C}_e$ of size $n = 256$ with $t = 171$ ($t/n = 0.668$) bounds the probability that $|\mathcal{K}| \ge t$ via Hoeffding/Chernoff to $< 2^{-108}$ for $\beta = 0.25$ and $< 2^{-139}$ for $\beta = 0.20$, while keeping $\Pr[|\mathcal{K}| > f = 85] \le 2.4 \times 10^{-3}$ at $\beta = 0.25$ ($1.2 \times 10^{-6}$ at $\beta = 0.20$). Full liveness security $< 2^{-40}$ at $\beta = 0.25$ requires either $n \approx 900$ or hardware-attested erasure.

### 2.4 Setup, public parameters, and cryptographic assumptions

1. **Transparent public parameters ($\mathsf{pp}$, zero trusted setup)**:
   For each supported scalar field order $q \in \{q_{\text{secp256k1}}, \ell_{\text{ed25519}}\}$ ($|q| \approx 256\text{ bits}, |q| \text{ prime}$):
   - $(\mathbb{E}, q, E)$: the target elliptic-curve group of prime order $q$ with canonical generator $E$ (`secp256k1` generator $G$ for ECDSA/BIP-340; `edwards25519` basepoint $B$ of prime order $\ell$ for Ed25519).
   - $(\hat{\mathbb{G}}, \mathbb{G}_q, \mathbb{F}, \Delta_K, G_q, H)$: a Castagnos–Laguillaumie (CL) imaginary quadratic class group of fundamental discriminant $\Delta_K = -q \cdot \tilde{q} \equiv 1 \pmod{4}$, where $\tilde{q}$ is chosen deterministically via a nothing-up-my-sleeve hash (`SHAKE256("OBTS-CL-DISC-v1" || curve_name)`) as the smallest prime $\tilde{q}$ with $q \cdot \tilde{q} \equiv 3 \pmod 4$, $(\frac{q}{\tilde{q}}) = -1$, and $|\Delta_K| = 1827\text{ bits}$ ($\lambda = 128$-bit security against Hafner–McCurley index calculus). No secret trapdoor exists even to the parameter generator. Here $\hat{\mathbb{G}} = \mathbb{G}_q \oplus \mathbb{F}$, where $\mathbb{F} = \langle H \rangle$ has known prime order $q$ with polynomial-time discrete-log algorithm $\mathsf{DLsolve}_{\mathbb{F}} : \mathbb{F} \to \mathbb{F}_q$, and $\mathbb{G}_q = \langle G_q \rangle$ has unknown order $s \approx \frac{1}{2\pi}\sqrt{|\Delta_K|}/q$ coprime to $q$. Let $\tilde{s} := \lceil \sqrt{|\Delta_K|} \rceil$ be the public upper bound on $|\hat{\mathbb{G}}|$.
2. **Epoch committee key registration (once per epoch $e$, non-interactive)**:
   Each committee member $P_i \in \mathcal{C}_e$ samples $\mathsf{sk}_{e,i} \xleftarrow{\$} [0, \tilde{s} \cdot 2^\lambda]$ and posts $Y_{e,i} = \mathsf{sk}_{e,i} \cdot G_q \in \mathbb{G}_q$ together with a Schnorr-over-unknown-order NIZK proof of knowledge $\pi_{e,i}^{\text{Kex}} \leftarrow \Pi_{\text{Kex}}.\mathsf{Prove}((G_q, Y_{e,i}); \mathsf{sk}_{e,i})$ bound to `(epoch = e, party_id = i)`. Anyone verifies $\pi_{e,i}^{\text{Kex}}$ before epoch $e$ activates; this defeats rogue-key attacks. Nodes also hold standard Ed25519/BLS consensus transport keys.
3. **Summary of assumptions**:
   - **Curve / signature hardness**: Discrete Logarithm (`DL`) and One-More Discrete Logarithm (`OMDL`) in $(\mathbb{E}, q, E)$ for BIP-340 and Ed25519 (via FROST/ROAST); existential unforgeability under chosen-message attack (`EUF-CMA`) of centralized single-signer ECDSA on secp256k1 (via Trout++ Theorem 7).
   - **Class-group hardness** in $\hat{\mathbb{G}}(\Delta_K)$: Hard Subgroup Membership / CL Indistinguishability (`HSM` / `CL-IND`: $(r G_q, r Y + x H)$ hides $x \in \mathbb{F}_q$ when $Y = \mathsf{sk} \cdot G_q$), **Low Order** (infeasible to find $U \neq 1_{\hat{\mathbb{G}}}$ and $d > 1$ with $d \cdot U = 1_{\hat{\mathbb{G}}}$ outside $\mathbb{F}$), and **Strong Root** (infeasible to find $(U, d > 1)$ with $d \cdot U = G_q$).
   - **Random Oracle Model (`ROM`)**: Domain-separated hash functions $\mathsf{H}_{\text{pocs}}, \mathsf{H}_{\text{auth}}, \mathsf{H}_{\text{req}}, \mathsf{H}_{\text{frost}}, \mathsf{H}_{\text{cl}}$ modeled as random oracles.
   - **Target-chain finality**: Blocks on $\mathcal{L}_{\text{target}}$ buried under $k_{\text{final}}$ confirmations (e.g., 6 blocks on Bitcoin, 2 finalized epochs on Ethereum, 32 rooted slots on Solana) do not reorganize.

---

## 3. Protocol

### 3.1 Key normalization for existing addresses

Real cryptocurrency addresses store secrets in incompatible conventions (raw scalars, parity-normalized x-only tweaked keys, or hashed/clamped seeds). Before dealing, the owner locally runs deterministic $\mathsf{NormalizeKey}(\mathsf{scheme\_id}, \mathsf{sk}_{\mathcal{O}}, \mathsf{addr\_ctx}) \to (x_{\text{eff}}, X_{\text{eff}})$ so that in **all three schemes** $x_{\text{eff}} \in \mathbb{F}_q^\times$ satisfies $X_{\text{eff}} = x_{\text{eff}} \cdot E \in \mathbb{E}$, and $X_{\text{eff}}$ is publicly checkable against the existing on-chain address $\mathsf{addr}$:

1. **Plain secp256k1 ECDSA (`scheme_id = 0x01`, Bitcoin P2PKH/P2WPKH, Ethereum EOA)**:
   - Input: secret scalar $x \in [1, q-1]$.
   - Output: $x_{\text{eff}} := x \in \mathbb{F}_q^\times$, $X_{\text{eff}} := x_{\text{eff}} \cdot G$ (33-byte SEC1 compressed point).
   - Public address check: for Bitcoin P2PKH/P2WPKH, $\mathsf{HASH160}(X_{\text{eff}}) = \mathsf{addr}_{20}$; for Ethereum EOA, $\mathsf{Keccak256}(\mathsf{uncompressed}(X_{\text{eff}})[1..65])[12..32] = \mathsf{addr}_{20}$.
2. **secp256k1 BIP-340 Schnorr / Taproot (`scheme_id = 0x02`, Bitcoin P2TR)**:
   - Input: internal secret scalar $x' \in [1, q-1]$ and optional Taproot script-tree Merkle root $m_{\text{tap}} \in \{0,1\}^{256} \cup \{\varepsilon\}$ (or pre-tweaked scalar if wallet already tweaked).
   - Step 1 (internal even-$y$ normalization): Let $P = x' \cdot G$. Set $d := x'$ if $y(P) \bmod 2 = 0$, else $d := q - x'$. Then $y(d \cdot G)$ is even and $x(d \cdot G) = P_x$.
   - Step 2 (Taproot tweak): Compute $t_{\text{tap}} := \mathsf{H}_{\text{TapTweak}}(P_x \,\|\, m_{\text{tap}}) \bmod q$ (or $t_{\text{tap}} := 0$ for raw BIP-340 key without tweak), and let $Q = (d + t_{\text{tap}} \bmod q) \cdot G \neq \mathcal{O}$.
   - Step 3 (output even-$y$ normalization): Set
     $$x_{\text{eff}} := \begin{cases} (d + t_{\text{tap}}) \bmod q & \text{if } y(Q) \bmod 2 = 0, \\ q - ((d + t_{\text{tap}}) \bmod q) & \text{if } y(Q) \bmod 2 = 1. \end{cases}$$
     Set $X_{\text{eff}} := x_{\text{eff}} \cdot G = \mathsf{lift\_x}(Q_x)$ (33-byte point with prefix `0x02` followed by $Q_x$).
   - Public address check: on Bitcoin P2TR, the on-chain UTXO `scriptPubKey` is literally `OP_1 (0x51) || 0x20 || Q_x`. Every verifier checks $X_{\text{eff}}[0] = \text{0x02}$ and $X_{\text{eff}}[1..33] = Q_x$ directly—no Taproot script tree needs to be transmitted on the wire. Moreover, because $y(X_{\text{eff}})$ is already even, committee shares $x_i$ never need conditional sign-flipping on $x_{\text{eff}}$ during signing!
3. **Ed25519 (`scheme_id = 0x03`, Solana, Sui, Aptos, NEAR)**:
   - Input: existing 32-byte RFC 8032 secret seed $\mathsf{seed} \in \{0,1\}^{256}$.
   - Step 1 (RFC 8032 SHA-512 expansion and bit clamping): Compute $h = \mathsf{SHA\text{-}512}(\mathsf{seed}) \in \{0,1\}^{512}$. Copy $b := h[0..32]$ (little-endian byte array), set `b[0] &= 248`, `b[31] &= 127`, `b[31] |= 64`, and interpret $b$ as an unsigned 256-bit little-endian integer $s_{\text{clamped}} \in [2^{254}, 2^{255}-8]$. *(Note: the upper half $h[32..64]$ used by deterministic single-signer Ed25519 nonce hashing is safely discarded because threshold FROST generates fresh distributed random nonces $R = \sum (D_i + \rho_i E_i)$, producing standard RFC 8032-verifiable `(R, z)` pairs.)*
   - Step 2 (reduction modulo subgroup order $\ell$): Since the Ed25519 basepoint $B$ has prime order $\ell = 2^{252} + 27742317777372353535851937790883648493$, set
     $$x_{\text{eff}} := s_{\text{clamped}} \bmod \ell \in \mathbb{F}_\ell^\times, \qquad X_{\text{eff}} := x_{\text{eff}} \cdot B.$$
     Because $\ell \cdot B = \mathcal{O}$, $x_{\text{eff}} \cdot B = s_{\text{clamped}} \cdot B = A$, which is byte-for-byte identical to the existing 32-byte Ed25519 public key / Solana address $\mathsf{addr}_{32}$!
   - Public address check: verifiers check $X_{\text{eff}} = \mathsf{addr}_{32}$, $X_{\text{eff}} \neq \mathcal{O}$, and $\ell \cdot X_{\text{eff}} = \mathcal{O}$ (rejecting small-torsion cofactor points per RFC 9591 §6.1).

### 3.2 Owner's single message ($\mathsf{Msg}_{\mathcal{O}}$)

The owner constructs a single self-contained byte string $\mathsf{Msg}_{\mathcal{O}}$ of exact length **$1,310 + 225n + 33(t - 1)$ bytes** on secp256k1 (subtract $t - 1$ bytes on Ed25519 if unpadded, or keep fixed 33-byte point slots for parser uniformity):

| Field | Symbol | Size (bytes) | Contents and role |
|---|---|---:|---|
| Protocol header | $\mathsf{hdr}$ | $40$ | `version` (1 B = `0x01`), `scheme_id` (1 B $\in \{\text{1,2,3}\}$), `tx_mode` (1 B: `0x01` sweep, `0x02` exact-amount), `guard_mode` (1 B: `0x00` dynamic, `0x01` pinned UTXO, `0x02` nonce floor), `epoch` (8 B `u64`), `expiry_height` (8 B `u64`), `min_confs` (4 B `u32`), `nonce_salt` (16 B random) |
| Target chain ID | $\mathsf{chain\_id}$ | $32$ | Canonical 32-byte chain digest (`SHA256(CAIP-2_id \|\| genesis_hash)`) |
| Address public key | $X_{\text{eff}}$ | $33$ | Normalized public key (`33 B` SEC1 on secp256k1; `0x00 \|\| 32 B` compressed Edwards point on Ed25519); serves directly as constant Feldman commitment $A_0 := X_{\text{eff}}$ |
| Spending intent | $\mathsf{Intent}$ | $140$ | `recipient` (36 B: 1 B len + 35 B canonical `scriptPubKey`/address), `amount` (16 B `u128`, `0` in sweep mode), `max_fee` (16 B `u128` in base units/wei/lamports), `change_dest` (36 B: 1 B len + 35 B canonical script/address), `guard_ref` (36 B: `0^36`, pinned `(txid:32B, vout:4B)`, or `(nonce_floor:8B, 0^28)`) |
| CL randomness header | $R_{\text{deal}}$ | $225$ | $R_{\text{deal}} = r \cdot G_q \in \mathbb{G}_q$ (batched multi-receiver CL ElGamal header) |
| Encrypted shares | $\{E_i\}_{i=1}^n$ | $225n$ | $E_i = r \cdot Y_{e,i} + x_i \cdot H \in \hat{\mathbb{G}}$ for each committee node $P_i \in \mathcal{C}_e$ |
| Feldman commitments | $\{A_j\}_{j=1}^{t-1}$ | $33(t-1)$ | $A_j = a_j \cdot E \in \mathbb{E}$ for non-constant polynomial coefficients $a_1, \dots, a_{t-1}$ ($A_0 = X_{\text{eff}}$ omitted to avoid duplication) |
| Sharing NIZK proof | $\pi_{\text{CS}}$ | $776$ | Intent-bound `PoCS` proof $(W \in \hat{\mathbb{G}} [225\text{ B}], X_{\text{prf}} \in \hat{\mathbb{G}} [225\text{ B}], Y_{\text{prf}} \in \mathbb{E} [33\text{ B}], z_r \in \mathbb{Z} [261\text{ B}], z_s \in \mathbb{F}_q [32\text{ B}])$ |
| Outer authorization sig | $\sigma_{\text{auth}}$ | $64$ | Native Schnorr (BIP-340 / Ed25519) or compact ECDSA $(R_x, s)$ signature under $x_{\text{eff}}$ over $\mathsf{H}_{\text{auth}}(\text{"OBTS-AUTH-v1"} \,\|\, \mathsf{Msg}_{\mathcal{O}}[0..\text{end}-64])$ |

#### `AB-cgVSS` dealing and Intent-bound `PoCS` equations

Let $\mathsf{ctx} := \mathsf{H}_{\text{pocs}}(\text{"OBTS-POCS-v1"} \,\|\, \mathsf{hdr} \,\|\, \mathsf{chain\_id} \,\|\, X_{\text{eff}} \,\|\, \mathsf{Intent} \,\|\, \{Y_{e,i}\}_{i=1}^n)$.

```text
Algorithm 1: OwnerDealAndAuthorize(pp, {Y_{e,i}}_{i=1}^n, sk_O, hdr, chain_id, Intent) -> Msg_O
-----------------------------------------------------------------------------------------------
1. (x_eff, X_eff) <- NormalizeKey(hdr.scheme_id, sk_O, Intent)
2. Sample a_1, ..., a_{t-1} <-$ F_q and define P(Z) := x_eff + sum_{j=1}^{t-1} a_j Z^j in F_q[Z].
3. For j = 1..t-1: A_j := a_j * E in E.   // Implicitly A_0 := X_eff = x_eff * E
4. For i = 1..n:   x_i := P(i) mod q;  X_i := X_eff + sum_{j=1}^{t-1} (i^j mod q) * A_j.
5. Sample r <-$ [0, s_tilde * 2^lambda]; compute R_deal := r * G_q in G_q.
6. For i = 1..n:   E_i := r * Y_{e,i} + x_i * H in G_hat.
7. // Batched Proof of Correct Sharing (PoCS) bound to ctx (adapting cgVSS Fig. 3):
   Derive alpha_1, ..., alpha_n <-$ [0, 2^lambda - 1] from H_pocs("LIN" || ctx || R_deal || {E_i} || {A_j}).
   Compute combined witnesses and instances:
     Y_agg := sum_{i=1}^n alpha_i * Y_{e,i};   E_agg := sum_{i=1}^n alpha_i * E_i;
     s_agg := (sum_{i=1}^n alpha_i * x_i) mod q.
   Sample k_r <-$ [0, s_tilde * 2^(2*lambda)], k_s <-$ F_q.
   Compute W := k_r * G_q,  X_prf := k_r * Y_agg + k_s * H,  Y_prf := k_s * E.
   c <- H_pocs("CHAL" || ctx || R_deal || {E_i} || {A_j} || W || X_prf || Y_prf) mod 2^lambda.
   z_r := k_r + c * r  (over Z);   z_s := (k_s + c * s_agg) mod q.
   pi_CS := (W, X_prf, Y_prf, z_r, z_s).
8. body := hdr || chain_id || X_eff || Intent || R_deal || {E_i}_{i=1}^n || {A_j}_{j=1}^{t-1} || pi_CS.
9. sigma_auth := NativeSign(hdr.scheme_id, x_eff, H_auth("OBTS-AUTH-v1" || body)).
10. Zeroize(x_eff, {a_j}, {x_i}, r, k_r, k_s) from transient buffers; return Msg_O := body || sigma_auth.
```

The request identifier is $\mathsf{req\_id} := \mathsf{H}_{\text{req}}(\text{"OBTS-REQ-v1"} \,\|\, \mathsf{Msg}_{\mathcal{O}}) \in \{0,1\}^{256}$. Once $\mathsf{Msg}_{\mathcal{O}}$ is posted, $\mathcal{O}$ goes permanently offline.

### 3.3 Committee offline precomputation (100% key-, intent-, and quorum-independent)

Before any owner message arrives, committee nodes maintain stocked pools of **key-independent** presignature material in the background:

- **Schnorr pool (`scheme_id` $\in \{2, 3\}$, RFC 9591 FROST Round 1)**:
  Each node $P_i$ generates batches of random nonce pairs $(d_{i,\ell}, e_{i,\ell}) \xleftarrow{\$} (\mathbb{F}_q^\times)^2$, stores $(d_{i,\ell}, e_{i,\ell})$ locally indexed by slot $\ell$, and broadcasts $(D_{i,\ell}, E_{i,\ell}) = (d_{i,\ell} E, e_{i,\ell} E) \in \mathbb{E}^2$ (`66 B` per slot on secp256k1; `64 B` on Ed25519).
- **ECDSA pool (`scheme_id = 1`, Trout++ Protocol 5 Round 1 `Presign`)**:
  Each node $P_i$ samples $(k_{i,\ell}, \gamma_{i,\ell}) \xleftarrow{\$} (\mathbb{F}_q^\times)^2$ and class-group randomness $(\alpha_{i,\ell}, \beta_{i,\ell})$, computes
  $$\Gamma_{i,\ell} := \gamma_{i,\ell} G \in \mathbb{E}, \qquad K_{i,\ell} := \alpha_{i,\ell} G_q + k_{i,\ell} H \in \hat{\mathbb{G}}, \qquad G'_{i,\ell} := \beta_{i,\ell} G_q + \gamma_{i,\ell} H \in \hat{\mathbb{G}},$$
  together with $\Pi_{\text{Log}}^*$ NIZK proofs that $G'_{i,\ell}$ encrypts the discrete log of $\Gamma_{i,\ell}$ and $K_{i,\ell}$ is well-formed (`1,350 B` total per slot per node). Crucially, unlike CGGMP21/DKLs23 presignatures—which multiply secret key shares $x_i$ during preprocessing and therefore cannot run before the owner deals $x$—**Trout++ `Presign` does not touch $x_i$, $X_{\text{eff}}$, the signing set $S$, or the message $m$**.

### 3.4 Committee online steps by round, signing, and output

When $\mathsf{Msg}_{\mathcal{O}}$ arrives on the request channel, each honest node $P_i \in \mathcal{C}_e$ executes the following pipeline without a trusted coordinator:

#### Gate 0 — Fast spam & replay filter (local, $\sim 50\,\mu\text{s}$, zero class-group ops)
1. Parse $\mathsf{Msg}_{\mathcal{O}}$, check exact byte length, verify `hdr.epoch == e`, check `Spent[req_id] == false`, and check current target-chain finalized height $\le \text{hdr.expiry\_height}$.
2. For Ed25519, check $X_{\text{eff}} \neq \mathcal{O}$ and $\ell \cdot X_{\text{eff}} = \mathcal{O}$; for BIP-340, check $X_{\text{eff}}[0] = \text{0x02}$.
3. Verify the outer native signature $\sigma_{\text{auth}}$ under $X_{\text{eff}}$ over $\mathsf{H}_{\text{auth}}(\text{"OBTS-AUTH-v1"} \,\|\, \mathsf{body})$. Any forged or malformed packet is dropped in $\sim 50\,\mu\text{s}$ before touching class-group arithmetic.

#### Gate 1 — Public `AB-cgVSS` verification and local share decryption (local, zero rounds)
1. Recompute $\alpha_1, \dots, \alpha_n$ and $c$ using $\mathsf{ctx}$ (with $A_0 := X_{\text{eff}}$ explicitly pinned!).
2. **Single-$t$-MSM verifier optimization**: Instead of computing $n$ separate $t$-term curve evaluations $X_i = \sum_{j=0}^{t-1} i^j A_j$ before forming $\sum_{i=1}^n \alpha_i X_i$, compute scalar weights $\beta_j := \left(\sum_{i=1}^n \alpha_i \cdot i^j\right) \bmod q$ in $\mathbb{F}_q$ for $j \in \{0, \dots, t-1\}$ and evaluate
   $$X_{\text{agg}} := \beta_0 X_{\text{eff}} + \sum_{j=1}^{t-1} \beta_j A_j \in \mathbb{E}$$
   via a **single $t$-point multi-scalar multiplication** in $\mathbb{E}$!
3. Compute $Y_{\text{agg}} = \sum_{i=1}^n \alpha_i Y_{e,i}$ and $E_{\text{agg}} = \sum_{i=1}^n \alpha_i E_i$ via two $n$-wide small-exponent ($\lambda$-bit) multi-exponentiations in $\hat{\mathbb{G}}$, check the integer range bound $z_r \in [0, \tilde{s} \cdot 2^{2\lambda + 1}]$, and verify the three `PoCS` equations:
   $$z_r G_q \stackrel{?}{=} W + c R_{\text{deal}}, \qquad z_r Y_{\text{agg}} + z_s H \stackrel{?}{=} X_{\text{prf}} + c E_{\text{agg}}, \qquad z_s E \stackrel{?}{=} Y_{\text{prf}} + c X_{\text{agg}}.$$
4. **Local share decryption**: Node $P_i$ computes $M_i := E_i - \mathsf{sk}_{e,i} \cdot R_{\text{deal}} \in \mathbb{F}$, recovers $x_i := \mathsf{DLsolve}_{\mathbb{F}}(M_i) \in \mathbb{F}_q$, and sanity-checks $x_i \cdot E = X_i := X_{\text{eff}} + \sum_{j=1}^{t-1} i^j A_j$. Now $(x_i, X_i, X_{\text{eff}})$ is a standard `dlog-sss-correct` $(t, n)$ Shamir sharing of $x_{\text{eff}}$!

#### Online Round A — BFT `AnchorCert` commit, deterministic `BuildTx`, and piggybacked ECDSA `Setup`
1. Consensus orders `req_id` and commits an `AnchorCert = (req_id, anchor_height, anchor_block_hash, median_fee_rate, presig_slot, S_0)` once `Spent[req_id] == false` and `anchor_height <= hdr.expiry_height`, atomically setting `Spent[req_id] := true` and reserving unused presignature slot `presig_slot` and initial $t$-signer subset $S_0 \subseteq \mathcal{C}_e$.
2. **Piggybacked ECDSA key commitment (`scheme_id = 1` only)**: During the `AnchorCert` vote/broadcast, each node $P_i$ attaches its verbatim **Trout++ Protocol 2 (`Setup`)** message (`720 B`) for `req_id`:
   $$C_i := \delta_i G_q + x_i H \in \hat{\mathbb{G}}, \qquad \pi_i^{\text{setup}} \leftarrow \Pi_{\text{Log}}^*.\mathsf{Prove}\big((G_q, H, E, C_i, X_i); (\delta_i, x_i)\big),$$
   bound to `req_id`. Peers in $S_0$ verify $\pi_j^{\text{setup}}$ against the publicly known Feldman share point $X_j = X_{\text{eff}} + \sum_{u=1}^{t-1} j^u A_u$. *(For Schnorr `scheme_id` $\in \{2,3\}$, this 720 B attachment is empty.)*
3. Every honest node runs `(tx_bytes, m) <- BuildTx(hdr, chain_id, X_eff, Intent, ChainSnapshot(anchor_block_hash), median_fee_rate)` (Section 4). If `BuildTx` returns $\bot$ (e.g., insufficient funds or `min_fee > Intent.max_fee`), honest nodes refuse to sign. Let $\mathsf{sid} := \mathsf{H}_{\text{req}}(\text{"OBTS-SIGN-v1"} \,\|\, \mathsf{req\_id} \,\|\, \mathsf{anchor\_block\_hash} \,\|\, m)$.

#### Online Round B — One-round threshold signing with asynchronous ROAST robustness
For a session quorum $S \subseteq \mathcal{C}_e$ of size $|S| = t$ (initially $S = S_0$ from `AnchorCert`), let $\lambda_{i,S} := \prod_{j \in S \setminus \{i\}} \frac{j}{j - i} \bmod q$ be the Lagrange coefficient of $P_i \in S$:

- **Case 1: Schnorr (`scheme_id = 0x02` BIP-340 Taproot or `scheme_id = 0x03` Ed25519) via FROST + ROAST**:
  1. From slot $\ell = \text{presig\_slot}$ and ordered commitment list $B = \langle (j, D_{j,\ell}, E_{j,\ell}) \rangle_{j \in S}$, each $P_i \in S$ derives binding factors $\rho_j := \mathsf{H}_{\text{frost}}(\text{"rho"} \,\|\, \mathsf{sid} \,\|\, j \,\|\, m \,\|\, B) \in \mathbb{F}_q$ and group nonce $R := \sum_{j \in S} (D_{j,\ell} + \rho_j E_{j,\ell}) \in \mathbb{E}$ (aborting/re-slotting on the $2^{-255}$ event $R = \mathcal{O}$).
  2. **BIP-340 vs Ed25519 challenge and nonce parity**:
     - For **BIP-340 (`0x02`)**: If $y(R) \bmod 2 = 1$, each $P_i \in S$ negates its effective nonce scalars $(d'_i, e'_i) := (q - d_{i,\ell}, q - e_{i,\ell})$, else $(d'_i, e'_i) := (d_{i,\ell}, e_{i,\ell})$. Let $R_x$ be the 32-byte big-endian x-coordinate of $R$; compute $c_{\text{sig}} := \mathsf{H}_{\text{BIP0340/challenge}}(R_x \,\|\, X_{\text{eff}}[1..33] \,\|\, m) \bmod q$. *(Because $X_{\text{eff}}$ already has even $y$, $x_i$ is never negated.)*
     - For **Ed25519 (`0x03`)**: Set $(d'_i, e'_i) := (d_{i,\ell}, e_{i,\ell})$, encode $R_{\text{enc}} := \mathsf{ Enc}_{32}(R)$, and compute $c_{\text{sig}} := \mathsf{SHA\text{-}512}(R_{\text{enc}} \,\|\, X_{\text{eff}}[1..33] \,\|\, m) \bmod \ell$.
  3. Node $P_i$ zeroizes $(d_{i,\ell}, e_{i,\ell})$ **before** sending on the network, computes $z_i := (d'_i + \rho_i e'_i + \lambda_{i,S} \cdot c_{\text{sig}} \cdot x_i) \bmod q$, and broadcasts `(z_i [32 B], next_commitment [66 B])`.
  4. **Aggregation and PVIA**: Once all $j \in S$ deliver $z_j$, any node computes $z := \sum_{j \in S} z_j \bmod q$. If native verification passes, output $\sigma = (R_x, z)$ (BIP-340) or $(R_{\text{enc}}, z)$ (Ed25519). If verification fails, check each share individually via $z_j E \stackrel{?}{=} R_j^{\text{eff}} + (\lambda_{j,S} c_{\text{sig}}) X_j$ (where $R_j^{\text{eff}} = \pm(D_{j,\ell} + \rho_j E_{j,\ell})$); every failing $j$ is publicly culpable! Under **ROAST**, nodes maintain at most $f + 1$ disjoint active $t$-subsets excluding blamed/stalled signers, guaranteeing valid output in $\le f + 1$ asynchronous rounds ($1$ round on the happy path).

- **Case 2: secp256k1 ECDSA (`scheme_id = 0x01`) via Trout++ + ROAST**:
  1. Using valid presignatures $\{(\Gamma_{j,\ell}, K_{j,\ell}, G'_{j,\ell})\}_{j \in S}$ and setup ciphertexts $\{C_j\}_{j \in S}$, every node computes the aggregate nonce point and shared ciphertexts:
     $$\Gamma := \sum_{j \in S} \Gamma_{j,\ell} \in \mathbb{E}, \quad r_x := x(\Gamma) \bmod q, \quad K := \sum_{j \in S} K_{j,\ell} \in \hat{\mathbb{G}}, \quad C_S := \sum_{j \in S} \lambda_{j,S} C_j \in \hat{\mathbb{G}}.$$
     *(Standard Trout++ presignature re-randomization shift $\tau := \mathsf{H}_{\text{cl}}(\text{"rerand"} \,\|\, \mathsf{sid} \,\|\, \Gamma)$ replaces $\Gamma \leftarrow \Gamma + \tau G$ and $G'_{j,\ell} \leftarrow G'_{j,\ell}$ with deterministic offset on slot $\ell$ to harden against presignature-manipulation attacks.)*
  2. Each $P_i \in S$ executes **Trout++ Protocol 5 Round 2 (`Sign`)**: computes partial ciphertexts and masked scalar shares encoding $w_i = k_{i,\ell} \gamma \quad\text{and}\quad u_i = k_{i,\ell}(m + r_x \cdot x_{\text{eff}})$ in the exponent of $H$ (`U_i := k_{i,\ell} C_S + m \cdot K_{i,\ell}` masked under CL randomness, plus $\Pi_{\text{Aff}}$ and $\Pi_{\text{Lin}}$ NIZK proofs in identifiable-abort `IA` mode, `2,505 B` total), zeroizes $(k_{i,\ell}, \gamma_{i,\ell})$, and broadcasts $\mathsf{sig\_msg}_i$.
  3. **Combine, low-$s$ normalization, and PVIA**: Upon collecting $\{\mathsf{sig\_msg}_j\}_{j \in S}$, nodes run `Trout++.Combine`: sum the class-group masks, extract discrete logs in $\mathbb{F} = \langle H \rangle$ via $\mathsf{DLsolve}_{\mathbb{F}}$ to obtain $\tilde{w} = k \cdot \gamma \bmod q$ and $\tilde{u} = \gamma(k m + r_x k x_{\text{eff}}) \bmod q$ (using the masked linear combination of Trout++ Fig. 6), set $s' := \tilde{u} \cdot \tilde{w}^{-1} \bmod q$, and enforce **BIP-62 / EIP-2 low-$s$ canonicalization**:
     $$s := \min(s',\; q - s').$$
     If $\mathsf{ECDSA.Verify}(X_{\text{eff}}, m, (r_x, s)) = 1$, attach $(r_x, s)$ (and recovery bit `v` for EVM) to `tx_bytes`, broadcast the signed transaction to $\mathcal{L}_{\text{target}}$, and zeroize $(x_i, \delta_i)$ once finalized. If `Verify` fails, verify $\Pi_{\text{Aff}}$ and $\Pi_{\text{Lin}}$ per signer $j \in S$ to identify the corrupt signer publicly and advance the ROAST wrapper over the remaining honest-inclusive $t$-quorum.

---

## 4. Transaction construction

### 4.1 Consensus-anchored chain snapshot (`AnchorCert`)

A committee cannot threshold-sign a transaction unless all honest signers derive the exact same `sighash` $m$. Every node runs a light client (or full/RPC-verified header follower) of $\mathcal{L}_{\text{target}}$ tracking blocks finalized at depth $k_{\text{final}}$. When proposing `AnchorCert` for an unspent `req_id`, the BFT leader selects the highest finalized target-chain block $B_{\text{anc}}$ at height $h_{\text{anc}}$ known to at least $n - f$ nodes, satisfying $h_{\text{anc}} \le \text{hdr.expiry\_height}$, and derives `median_fee_rate` deterministically from the finalized block headers $[h_{\text{anc}} - W_{\text{fee}} + 1 .. h_{\text{anc}}]$ (e.g., $W_{\text{fee}} = 6$ blocks on Bitcoin using the 50th-percentile feerate of transactions in those blocks; on EIP-1559 chains, directly from $B_{\text{anc}}.\text{baseFeePerGas}$ plus the 50th-percentile priority tip in $B_{\text{anc}}$). Every BFT validator checks that $B_{\text{anc}}$ is finalized at depth $\ge \max(k_{\text{final}}, \text{hdr.min\_confs})$ and recomputes `median_fee_rate` from the block data before voting for `AnchorCert`.

### 4.2 Deterministic UTXO builder (Bitcoin P2PKH, P2WPKH, and Taproot P2TR)

Given `AnchorCert` and the canonical UTXO set $\mathsf{UTXOs}(B_{\text{anc}}, \mathsf{script}(X_{\text{eff}}))$ of unspent outputs confirmed at height $\le h_{\text{anc}} - \text{hdr.min\_confs} + 1$:

1. **Candidate filtering and canonical sorting**:
   - If `hdr.guard_mode == 0x01` (pinned UTXO), restrict candidates to the exact outpoint `(txid, vout)` in `Intent.guard_ref` (aborting if already spent at $B_{\text{anc}}$).
   - Otherwise (`0x00` dynamic), collect all mature spendable UTXOs paying to $\mathsf{script}(X_{\text{eff}})$ and sort them in strict total order:
     $$\text{sort key}(u) := (-\text{value}(u),\; u.\text{txid\_be},\; u.\text{vout\_u32}).$$
2. **Exact integer weight and fee calculation (zero floating point)**:
   - Let $\rho_{\text{fee}} := \text{AnchorCert.median\_fee\_rate}$ in integer **satoshis per kiloweight (`sat/kw`)**. Compute transaction weight $w(k_{\text{in}}, k_{\text{out}})$ in exact BIP-141 weight units (e.g., P2TR key-path input $= 230\text{ wu}$, P2WPKH input $= 272\text{ wu}$, P2TR output $= 172\text{ wu}$, P2WPKH output $= 124\text{ wu}$, header $= 42\text{ wu}$), and fee:
     $$\mathsf{fee}(w) := \lceil w \cdot \rho_{\text{fee}} / 1000 \rceil = (w \cdot \rho_{\text{fee}} + 999) \;\text{div}\; 1000.$$
     Clamp $\mathsf{fee}_{\text{eff}} := \min(\mathsf{fee}(w),\; \text{Intent.max\_fee})$, **provided** $\mathsf{fee}_{\text{eff}} \ge \mathsf{fee}_{\text{relay\_floor}}(w)$ (`1 sat/vB`); if $\text{Intent.max\_fee} < \mathsf{fee}_{\text{relay\_floor}}(w)$, abort (`FeeCeilingTooLow`).
3. **Coin selection, dust rule, and canonical serialization**:
   - **Sweep mode (`tx_mode = 0x01`, recommended for imported keys)**: Select **all** candidate UTXOs (up to a protocol cap $K_{\max} = 32$ inputs), set `k_out = 1`, compute $\mathsf{val}_{\text{out}} := \sum_{u} \text{value}(u) - \mathsf{fee}(w(|U|, 1))$, verify $\mathsf{val}_{\text{out}} > \mathsf{dust}(\text{Intent.recipient})$ (`330 sat` for P2TR, `294 sat` for P2WPKH), and emit a single output `(Intent.recipient, val_out)` with zero change left on the imported key!
   - **Exact-amount mode (`tx_mode = 0x02`)**: Accumulate sorted UTXOs $u_1, \dots, u_k$ until the smallest $k \ge 1$ satisfying $\sum_{j=1}^k \text{value}(u_j) \ge \text{Intent.amount} + \mathsf{fee}(w(k, 2))$. Let $\Delta := \sum_{j=1}^k \text{value}(u_j) - \text{Intent.amount} - \mathsf{fee}(w(k, 2))$. If $\Delta \ge \mathsf{dust}(\text{Intent.change\_dest})$, emit two outputs (`Intent.recipient` and `Intent.change_dest`, ordered lexicographically by `(amount ASC, scriptPubKey ASC)` per BIP-69); otherwise fold dust $\Delta$ into the fee as long as $\mathsf{fee}(w(k, 1)) + \Delta \le \text{Intent.max\_fee}$ (else fold excess only up to `Intent.max_fee` if change is non-dust at 1-output fee).
   - Set `nVersion = 2`, `nLockTime = h_anc` (anti-fee-sniping), `nSequence = 0xfffffffd` (RBF-compatible only via new owner move, fixed deterministically), sort inputs by `(txid_le, vout)`, and compute the exact BIP-143 (P2WPKH) or BIP-341 `SIGHASH_DEFAULT` (`0x00`, P2TR) digest $m$ per input. *(For $k > 1$ inputs, the single `AnchorCert` deterministically reserves $k$ consecutive presignature slots $[\ell, \dots, \ell + k - 1]$ and signs all $k$ input sighashes in parallel inside the same single online round!)*

### 4.3 Deterministic account-model builder (Ethereum EIP-1559 and Solana Ed25519)

1. **Ethereum / EVM (`scheme_id = 0x01`, Type-2 EIP-1559 transaction)**:
   - Read finalized account state $(\mathsf{bal}, \mathsf{nonce})$ of $\mathsf{addr}_{20}(X_{\text{eff}})$ at $B_{\text{anc}}$. If `hdr.guard_mode == 0x02` and $\mathsf{nonce} < \text{guard\_ref.nonce\_floor}$ (or if `guard_mode == 0x01` pinned nonce and $\mathsf{nonce} \neq \text{guard\_ref.nonce}$), abort.
   - Set `gasLimit := 21_000` (plain ETH transfer), `maxPriorityFeePerGas := AnchorCert.median_priority_fee`, and `maxFeePerGas := min(2 * B_anc.baseFeePerGas + maxPriorityFeePerGas, Intent.max_fee / 21_000)`. Require `maxFeePerGas >= B_anc.baseFeePerGas` (else defer anchoring until basefee drops or `expiry_height` passes).
   - In **sweep mode**, set `value := bal - 21_000 * maxFeePerGas` (requiring `value > 0`); in **exact mode**, set `value := Intent.amount` (requiring `bal >= value + 21_000 * maxFeePerGas`).
   - Encode RLP payload `0x02 || RLP([chain_id_num, nonce, maxPriorityFeePerGas, maxFeePerGas, 21000, recipient_20, value, "", []])` and set $m := \mathsf{Keccak256}(\text{payload})$.
2. **Solana (`scheme_id = 0x03`, Ed25519 SystemProgram Transfer)**:
   - Read finalized account lamports $\mathsf{bal}$ of $X_{\text{eff}}$ and finalized blockhash $\mathsf{bh} := B_{\text{anc}}.\text{blockhash}$ (valid for 150 slots $\approx 60\text{ s}$ on Solana, comfortably exceeding OBTS's $< 1\text{ s}$ post-anchor signing latency; for multi-minute horizons, `guard_ref` names a durable-nonce account).
   - Base fee is deterministic (`5,000 lamports` + optional priority `computeUnitPrice` from `AnchorCert` capped at `Intent.max_fee`). Build canonical v0 `Message` transferring `Intent.amount` (or `bal - fee` in sweep mode, closing the account to zero rent-exempt dust) to `Intent.recipient` with `recent_blockhash = bh`; serialize message bytes as $m$.

### 4.4 Agreement without a trusted coordinator

No coordinator ever supplies raw transaction bytes to signers. Instead, consensus agrees **only** on the compact 120-byte `AnchorCert`, and every honest signer $P_i$ runs pure function `BuildTx` locally on `(Msg_O, ChainSnapshot(anchor_block_hash), median_fee_rate)` and embeds `(anchor_block_hash, m)` into the signing session ID $\mathsf{sid}$. Even if $f$ Byzantine nodes propose bogus transactions, two honest nodes with the same `AnchorCert` derive bit-identical `m` and $\mathsf{sid}$, and any honest node refuses to emit a signature share for any other digest.

---

## 5. Committee change

### 5.1 Epoch tagging and lifecycle states

Committee membership rotates across discrete epochs $e = 1, 2, \dots$ governed by the host BFT state machine. Each epoch $\mathcal{C}_e = (n_e, t_e, \{Y_{e,i}\}_{i=1}^{n_e})$ transitions through three consensus-tracked states:
$$\mathsf{Active}(e) \longrightarrow \mathsf{HandoverGrace}(e \to e+1) \longrightarrow \mathsf{Retired}(e).$$
Every owner message $\mathsf{Msg}_{\mathcal{O}}$ names both `hdr.epoch = e` (the encryption target $\{Y_{e,i}\}$) and a target-chain deadline `hdr.expiry_height`.

### 5.2 Matched (anchored) vs unmatched (pending) requests across rotation

When epoch $e + 1$ keys $\{Y_{e+1, k}\}_{k=1}^{n_{e+1}}$ are registered and handover begins at host block $H_{\text{rot}}$:

1. **`Spent` nullifier table replication**: The consensus state of $\mathcal{C}_{e+1}$ inherits the complete `Spent` nullifier set (pruned only of entries whose `expiry_height` lies deeper than $k_{\text{final}}$ in the finalized past, since expired requests are permanently invalid by rule). Thus a request executed under $\mathcal{C}_e$ can never be re-executed under $\mathcal{C}_{e+1}$.
2. **In-flight (`Anchored`) requests drain in $\mathcal{C}_e$**: Any `req_id` that already received an `AnchorCert` before $H_{\text{rot}}$ has only **one online signing round** remaining. Old committee $\mathcal{C}_e$ stays online during a short $\mathsf{HandoverGrace}$ window (e.g., 30 seconds) to finish Round B for all anchored requests using $\mathcal{C}_e$'s already-reserved presignature slots, broadcasts the resulting target-chain transactions, and zeroizes shares.
3. **Unmatched (`Pending`, unanchored) valid requests reshare non-interactively to $\mathcal{C}_{e+1}$**: Suppose $\mathsf{Msg}_{\mathcal{O}}$ passed Gate 0 and Gate 1 under $\mathcal{C}_e$ and has `current_height < hdr.expiry_height`, but was delayed from anchoring (e.g., waiting for target-chain `baseFeePerGas` to dip below `Intent.max_fee` or waiting for `hdr.min_confs` confirmations). A consensus-selected subset $S_{\text{hand}} \subseteq \mathcal{C}_e$ of $t_e$ (or $f_e + 1$ with threshold $t_e$) nodes reshares $x_{\text{eff}}$ to $\mathcal{C}_{e+1}$ **without the owner**:
   - Each $P_i \in S_{\text{hand}}$ computes its Lagrange-weighted additive share $w_i := \lambda_{i, S_{\text{hand}}} x_i \bmod q$ (with public commitment $W_i = \lambda_{i, S_{\text{hand}}} X_i$, which every verifier computes from $\mathsf{Msg}_{\mathcal{O}}$'s Feldman commitments!) and posts a `cgVSS` dealing of $w_i$ of degree $t_{e+1} - 1$ encrypted to $\{Y_{e+1, k}\}_{k=1}^{n_{e+1}}$ with constant commitment $A_{i,0} = W_i$.
   - Once $t_e$ valid sub-dealings (or an ACS-selected valid handover batch when $t_e = f_e + 1$; for $t_e = n_e - f_e$, up to $f_e$ missing/corrupt dealers in $\mathcal{C}_e$ are seamlessly bypassed by picking any $t_e$ of the $\ge n_e - f_e = t_e$ honest nodes!) are posted on the host chain, each new member $P'_k \in \mathcal{C}_{e+1}$ sums its decrypted sub-shares $x'_k := \sum_{i \in S_{\text{hand}}} w_{i \to k} \bmod q$. By linearity, $\{x'_k\}$ is a fresh degree-$(t_{e+1}-1)$ Shamir sharing of $\sum_{i \in S_{\text{hand}}} w_i = x_{\text{eff}}$ with constant commitment $\sum W_i = X_{\text{eff}}$, still bound to the original immutable $\mathsf{Msg}_{\mathcal{O}}$ and `Intent`!
   - **Zero presignature discard**: Because $\mathcal{C}_{e+1}$'s stocked FROST nonce commitments and Trout++ ECDSA presignatures are 100% key-independent, $\mathcal{C}_{e+1}$ spends the reshared key immediately using its existing presignature pool—avoiding the Internet Computer's key-transcript presignature invalidation penalty (`REPORT.md` §4 `[P9]`).

### 5.3 Forward secrecy and late owner messages

Once `HandoverComplete(e -> e+1)` is committed on the host chain:
- Every honest $P_i \in \mathcal{C}_e$ **permanently erases** its epoch secret key $\mathsf{sk}_{e,i}$ and all reshared/spent $x_i$ shares, entering $\mathsf{Retired}(e)$.
- Any owner message $\mathsf{Msg}_{\mathcal{O}}$ arriving *after* $\mathsf{Retired}(e)$ that still encrypts to retired keys $\{Y_{e,i}\}$ is **deterministically rejected** (and undecryptable by honest nodes since $\mathsf{sk}_{e,i}$ is erased); an adversary who later compromises all of $\mathcal{C}_e$ learns nothing about past keys or late messages. If an offline owner's message missed epoch $e$ entirely without ever entering `Pending` before retirement, no funds are lost on $\mathcal{L}_{\text{target}}$; the owner simply posts a fresh $\mathsf{Msg}_{\mathcal{O}}$ under epoch $e' > e$ when next online.

---

## 6. Security

### 6.1 Ideal functionality $\mathcal{F}_{\text{OBTS}}$

Existing formal models capture isolated pieces: Groth–Shoup orders requests by consensus without an authorization predicate, zkLogin checks a stateless witness predicate without a threshold committee, and TSaaS (`2026-814.pdf`) models an online single client without chain-state transaction construction. Below we define $\mathcal{F}_{\text{OBTS}}$, parameterized by curve $(\mathbb{E}, q, E)$, committee epochs $\{\mathcal{C}_e\}$, thresholds $(f, t)$ with $f < n/3$ and $f + 1 \le t \le n - f$, deterministic predicate $\mathsf{ValidBuild}(\mathsf{hdr}, \mathsf{chain\_id}, X_{\text{eff}}, \mathsf{Intent}, \mathsf{st}, \mathsf{tx}, m) \in \{0, 1\}$, and target-chain finality oracle $\mathcal{O}_{\text{chain}}$:

```text
Ideal Functionality F_OBTS (interacting with Owner O, Committee {P_1..P_n}, Chain Oracle O_chain, Adversary S)
--------------------------------------------------------------------------------------------------------------
State:
  EpochState[e] in {Active, Grace, Retired};  Spent : Map<ReqID, Bool> default false;
  Pending : Map<ReqID, (e, hdr, chain_id, X_eff, x_eff, Intent, CompromisedFlag)>.

1. One-Shot Owner Authorize-and-Depart:
   On input (AUTHORIZE, sk_O, e, hdr, chain_id, Intent) from O:
     Compute (x_eff, X_eff) <- NormalizeKey(hdr.scheme_id, sk_O, Intent).
     Assign unique req_id; leak public tuple (req_id, e, hdr, chain_id, X_eff, Intent) to S.
     // Note: O terminates immediately and takes no further inputs or outputs.
     If EpochState[e] == Retired: ignore.
     Let K_e be the set of corrupted nodes in C_e.
     compromised := (|K_e| >= t).
     If compromised: send x_eff to S (modeling algebraic share reconstruction at >= t corruptions).
     Record Pending[req_id] := (e, hdr, chain_id, X_eff, x_eff, Intent, compromised).

2. Consensus Chain-Anchor & Spend Execution:
   On input (EXECUTE, req_id, anchor_block_hash) when Pending[req_id] exists and Spent[req_id] == false:
     Retrieve st <- O_chain.FinalizedState(chain_id, anchor_block_hash).
     Require st != bot and st.height <= hdr.expiry_height and EpochState[Pending[req_id].e] != Retired.
     If |K_e| <= f:
       // Honest consensus enforces atomic single-spend exclusion:
       Spent[req_id] := true.
     (tx_bytes, m) <- BuildTx(hdr, chain_id, X_eff, Intent, st, st.median_fee_rate).
     If (tx_bytes, m) == bot or ValidBuild(hdr, chain_id, X_eff, Intent, st, tx_bytes, m) == 0:
       Output (ABORT_INVALID_INTENT, req_id) to all honest parties; halt this execution.
     // Signing phase:
     If |K_e| <= f:
       // Guaranteed asynchronous output delivery within bounded message steps:
       Produce valid native signature sigma <- Sign_ideal(hdr.scheme_id, x_eff, m) (adversarial nonce bias
       modeled per FROST/Trout++ simulator, valid under NativeVerify(X_eff, m, sigma) == 1).
       Output (SIGNED_TX, req_id, tx_bytes, sigma) to all honest nodes and O_chain.
     Else if f < |K_e| < t:
       // Consensus safety may fail, so S may delay delivery or propose multiple anchors,
       // BUT S still cannot forge sigma on any (tx*, m*) violating ValidBuild(..., Intent, ...):
       Allow S to choose whether honest nodes receive sigma on valid (tx_bytes, m) or no output.

3. Epoch Handover (e -> e+1):
   On input (ROTATE, e, e+1) when |K_e| <= f and |K_{e+1}| <= f:
     Set EpochState[e] := Grace, EpochState[e+1] := Active.
     For each unspent req_id in Pending with height <= hdr.expiry_height:
       Update Pending[req_id].e := e+1;
       If |K_{e+1}| >= t: Pending[req_id].compromised := true; send x_eff to S.
     On (COMPLETE_ROTATE, e): set EpochState[e] := Retired (honest C_e erases epoch state).
```

### 6.2 Security claims and proof sketches

**Claim 1 (Public Verifiability & Address-Bound Key Completeness).** *Under the `LowOrder` and `StrongRoot` assumptions in $\hat{\mathbb{G}}(\Delta_K)$ and the Random Oracle Model, no PPT adversary (including a malicious requester) can produce a message $\mathsf{Msg}_{\mathcal{O}}$ accepted by Gate 1 (`AB-cgVSS.Ver = 1`) with public key $X_{\text{eff}}$ unless the decrypted honest shares $\{x_i = \mathsf{DLsolve}_{\mathbb{F}}(E_i - \mathsf{sk}_{e,i} R_{\text{deal}})\}$ lie on a unique degree-$\le(t-1)$ polynomial $P(Z) \in \mathbb{F}_q[Z]$ whose constant term $P(0) = x_{\text{eff}}$ satisfies $x_{\text{eff}} \cdot E = X_{\text{eff}}$, except with probability $\le 2^{-\lambda + 2} + \mathsf{negl}(\lambda)$.*

*Proof sketch.* In `AB-cgVSS.Ver`, the verifier sets $A_0 := X_{\text{eff}}$ directly from the public address field (never from an untrusted commitment separate from $X_{\text{eff}}$) and defines $X_i := X_{\text{eff}} + \sum_{j=1}^{t-1} i^j A_j$ for $i = 1, \dots, n$. Thus the curve vectors $(X_1, \dots, X_n)$ are *algebraically guaranteed* to be Reed–Solomon / Shamir evaluations of a degree-$\le(t-1)$ polynomial in the exponent of $\mathbb{E}$ whose $Z=0$ value is $X_{\text{eff}}$. By two-point special soundness (rewinding on challenge $c$) of `PoCS` under `LowOrder` and `StrongRoot` (`cgVSS` Theorem 1, `2023-451.pdf` §4 & App. C), acceptance of $(W, X_{\text{prf}}, Y_{\text{prf}}, z_r, z_s)$ implies an extractor outputs rational/integer witnesses $(r, s_{\text{agg}})$ satisfying $R_{\text{deal}} = r G_q$, $E_{\text{agg}} = r Y_{\text{agg}} + s_{\text{agg}} H$, and $X_{\text{agg}} = s_{\text{agg}} E$ (any torsion discrepancy in $\hat{\mathbb{G}} \setminus \mathbb{F}$ yields a `LowOrder` or `StrongRoot` break). Finally, since $\alpha_1, \dots, \alpha_n \xleftarrow{\$} [0, 2^\lambda - 1]$ are derived via $\mathsf{H}_{\text{pocs}}$ *after* $(R_{\text{deal}}, \{E_i\}, \{A_j\}, X_{\text{eff}})$ are fixed, if for any $i \in \{1, \dots, n\}$ the ciphertext $E_i - r Y_{e,i}$ failed to equal $x_i H$ where $x_i E = X_i$, the linear equation $\sum_{i=1}^n \alpha_i (E_i - r Y_{e,i} - x_i H) = 0_{\hat{\mathbb{G}}}$ holds with probability at most $2^{-\lambda}$ by Schwartz–Zippel / subgroup projection. Since $Y_{e,i} = \mathsf{sk}_{e,i} G_q$ (guaranteed by $\Pi_{\text{Kex}}$), $E_i - \mathsf{sk}_{e,i} R_{\text{deal}} = E_i - r Y_{e,i} = x_i H$, so every honest $P_i$ recovers $x_i = P(i)$ with $P(0) E = X_{\text{eff}}$. $\square$

---

**Claim 2 (Sub-Threshold Key Secrecy).** *Assume static corruption of $|\mathcal{K}| \le t - 1$ committee nodes, `HSM`/`CL-IND` in $\hat{\mathbb{G}}(\Delta_K)$, `DL` in $\mathbb{E}$, and `ROM`. For any honestly generated secret $x_{\text{eff}}$ dealt by $\mathcal{O}$, the joint view of $\mathcal{A}$ across $\mathsf{Msg}_{\mathcal{O}}$, offline presigning, online signing, and epoch resharing reveals zero computational information about $x_{\text{eff}}$ beyond $(X_{\text{eff}}, \sigma_{\text{auth}}, \sigma_{\text{spend}})$.*

*Proof sketch.* Construct a simulator $\mathcal{S}$ given only $(X_{\text{eff}}, \sigma_{\text{auth}}, \sigma_{\text{spend}})$:
1. For corrupt parties $j \in \mathcal{K}$ ($|\mathcal{K}| \le t - 1$), $\mathcal{S}$ samples uniform shares $x_j \xleftarrow{\$} \mathbb{F}_q$. Because $|\mathcal{K}| \le t - 1$, $X_{\text{eff}} = P(0) E$ and $\{x_j E\}_{j \in \mathcal{K}}$ uniquely determine all remaining Feldman commitments $\{A_u\}_{u=1}^{t-1}$ and honest public share points $\{X_i\}_{i \notin \mathcal{K}}$ via Lagrange interpolation in the exponent of $\mathbb{E}$ without knowing $x_{\text{eff}}$.
2. $\mathcal{S}$ simulates $\pi_{\text{CS}}$ in zero-knowledge by programming the random oracle $\mathsf{H}_{\text{pocs}}(\text{"CHAL"} \,\|\, \dots) := c$ (sampling $z_r, z_s$ and computing $W = z_r G_q - c R_{\text{deal}}$, $X_{\text{prf}} = z_r Y_{\text{agg}} + z_s H - c E_{\text{agg}}$, $Y_{\text{prf}} = z_s E - c X_{\text{agg}}$, statistically indistinguishable within $2^{-\lambda}$).
3. By multi-receiver `CL-IND` (`HSM` with random self-reducibility over $\{Y_{e,i}\}_{i \notin \mathcal{K}}$, `2023-451.pdf` Lemma 1), replacing honest share ciphertexts $\{E_i = r Y_{e,i} + x_i H\}_{i \notin \mathcal{K}}$ with $\{r Y_{e,i} + 0 \cdot H\}_{i \notin \mathcal{K}}$ is computationally indistinguishable because $\mathcal{A}$ lacks $\{\mathsf{sk}_{e,i}\}_{i \notin \mathcal{K}}$ (and $\Pi_{\text{Kex}}$ extracts $\mathsf{sk}_{e,j}$ for corrupt $j \in \mathcal{K}$).
4. During signing, FROST online shares $\{z_i\}_{i \notin \mathcal{K}}$ are simulated from $\sigma_{\text{spend}}$ and $\{X_i\}$ (`roast.txt` Theorem 4.1), while Trout++ `Setup` ciphertexts $\{C_i\}_{i \notin \mathcal{K}}$ and `Sign` messages are simulated from $\sigma_{\text{spend}}$ via the Trout++ simulator (`2026-1455.pdf` Theorem 7, pp. 22–28). $\square$

---

**Claim 3 (Intent-Bound Unforgeability and Single-Spend Enforcement).** *Assume `OMDL` in $\mathbb{E}$ (for BIP-340/Ed25519) or `EUF-CMA` of single-signer ECDSA + `HSM`/`LowOrder`/`StrongRoot` (for secp256k1 ECDSA), in the `ROM`:*
1. *(Owner authentication, any corruption count)* If $\mathcal{O}$ has not dealt $X_{\text{eff}}$, no PPT adversary (even corrupting all $n$ committee nodes) can spend from $X_{\text{eff}}$.
2. *(Cryptographic + single-honest-node intent binding under $|\mathcal{K}| \le t - 1$)* Even after $\mathcal{O}$ posts $\mathsf{Msg}_{\mathcal{O}}$ for `Intent` and goes offline, no adversary corrupting $|\mathcal{K}| \le t - 1$ nodes ($|\mathcal{K}| \le n - f - 1 \approx \frac{2}{3}n$ in primary mode) can produce a valid signature under $X_{\text{eff}}$ on **any** message $m^*$ that was not produced by `BuildTx` on a finalized target-chain snapshot satisfying `Intent` before `expiry_height` (aside from $\sigma_{\text{auth}}$, which uses the domain-separated prefix `"OBTS-AUTH-v1"` invalid as a chain transaction).
3. *(Single-spend finality under $|\mathcal{K}| \le f < n/3$)* When $|\mathcal{K}| \le f$, at most **one** target-chain transaction is ever signed for each `req_id`.

*Proof sketch.* Part (1) is immediate because $\mathcal{C}_e$ holds zero state for $X_{\text{eff}}$ prior to $\mathsf{Msg}_{\mathcal{O}}$. For Part (2), suppose $|\mathcal{K}| \le t - 1$ and $\mathcal{A}$ outputs a valid chain transaction signature $\sigma^*$ on $m^*$ violating `Intent`. Because $|\mathcal{K}| \le t - 1$, **every** subset $S$ of size $t$ contains at least one honest node $P_{i^*} \in S \setminus \mathcal{K}$. Every honest node verifies $\sigma_{\text{auth}}$ and `PoCS` (whose Fiat–Shamir context $\mathsf{ctx}$ commits to `hdr`, `chain_id`, `X_eff`, and `Intent`—so altering a single bit of `Intent` invalidates both $\sigma_{\text{auth}}$ and $\pi_{\text{CS}}$) and refuses to output an online share (`z_{i^*}` in FROST or `Sign` message in Trout++) for any digest $m^*$ not output by `BuildTx(..., Intent, ...)`. Therefore no honest node ever signs $m^*$. Using the simulatability of $\mathsf{Msg}_{\mathcal{O}}$ from Claim 2, a reduction embeds an `OMDL` challenge (via ROAST Theorem 4.1, `roast.txt` §4) for Schnorr—or embeds a single-signer **ECDSA EUF-CMA signing oracle** on $X_{\text{eff}}$ (via Trout++ Theorem 7, `2026-1455.pdf` p. 16 & App. B, answering allowed `Intent`-compliant signing queries via the ECDSA oracle and simulating $\sigma_{\text{auth}}$ on `"OBTS-AUTH-v1"` via ROM/signing oracle)—and outputs $(m^*, \sigma^*)$ as a fresh forgery on $m^* \notin Q_{\text{queried}}$, contradiction! For Part (3), when $|\mathcal{K}| \le f < n/3$, BFT SMR safety guarantees at most one `AnchorCert` can ever be committed before `Spent[req_id]` transitions permanently from `false` to `true`, and honest nodes sign only for a valid `AnchorCert` (`2f + 1` quorum certificate, requiring $\ge f + 1$ honest BFT votes), so honest nodes participate in signing at most one digest $m$ for `req_id`. $\square$

---

**Proposition 1 (Offline-Builder Single-Spend Barrier at $\ge t$ Corruptions).** *Suppose an owner posts one non-interactive message $\mathsf{Msg}_{\mathcal{O}}$ and goes offline, and a signing committee with reconstruction threshold $t$ must be able to construct and sign a valid native ECDSA/Schnorr transaction whose `sighash` $m(\mathsf{st})$ depends on target-chain state $\mathsf{st}$ realized **after** $\mathcal{O}$ goes offline (e.g., finalized blockhash, dynamic fee rate, or account balance) without trusted hardware or validator-assisted witness encryption. Then any coalition $\mathcal{K}$ of $|\mathcal{K}| \ge t$ corrupt committee nodes can produce valid signatures on **two distinct transactions** $m(\mathsf{st}_1) \neq m(\mathsf{st}_2)$.*

*Proof.* By liveness of the offline-owner protocol, given $\mathsf{Msg}_{\mathcal{O}}$ and the secret states $\{\mathsf{st}_i\}_{i \in \mathcal{K}}$ of any $t$-quorum $\mathcal{K}$ ($|\mathcal{K}| = t$), the nodes in $\mathcal{K}$ can run the committee protocol among themselves (simulating consensus over $\mathcal{K}$ if needed or acting as the active $t$-quorum) on any valid post-owner chain state $\mathsf{st}_1$ to obtain a valid signature $\sigma_1 = (R_1, s_1)$ on $m_1 = m(\mathsf{st}_1) \neq m(\mathsf{st}_2)$. Because $\mathcal{K}$ lives in software, $\mathcal{K}$ snapshots its memory before the online step, runs the protocol on $\mathsf{st}_1$ to obtain $(R_1, s_1)$ on $m_1$, **rewinds** to the snapshot, and runs the protocol on a second valid candidate state $\mathsf{st}_2$ (e.g., different `recent_blockhash` or fee level within `Intent.max_fee`) to obtain a valid signature $(R_2, s_2)$ on $m_2 \neq m_1$:
- If $R_2 \neq R_1$, $\mathcal{K}$ already holds two distinct valid signatures $(R_1, s_1)$ and $(R_2, s_2)$ on $m_1 \neq m_2$.
- If $R_2 = R_1$ (as in deterministic or presignature-locked partial signatures where the nonce $R$ is fixed inside $\mathsf{Msg}_{\mathcal{O}}$), two valid Schnorr/ECDSA signatures $(R, s_1), (R, s_2)$ on $m_1 \neq m_2$ solve directly for the full secret key $x_{\text{eff}}$ via linear algebra ($x_{\text{eff}} = (s_1 - s_2)(c_1 - c_2)^{-1}$ for Schnorr; $k = (m_1 - m_2)(s_1 - s_2)^{-1}$ then $x_{\text{eff}} = r_x^{-1}(s_1 k - m_1)$ for ECDSA), letting $\mathcal{K}$ sign arbitrary transactions! $\square$

*(Remark: Form B [Ika `future sign`] evades Proposition 1 only by fixing the exact `sighash` $m$ **before** the owner goes offline—sacrificing committee-side transaction construction! Stambler's $T+1$-eWEB [`2025-1064.pdf`] evades it only if target-chain validators sign every bit of state root $T+1$ with one-time BLS keys inside a garbled circuit, which does not exist on Bitcoin, Ethereum, or Solana.)*

---

**Claim 4 (Asynchronous Signing Liveness & End-to-End Termination).** *Under $|\mathcal{K}| \le f < n/3$ Byzantine nodes, after GST (with valid, funded, fee-feasible $\mathsf{Msg}_{\mathcal{O}}$ arriving sufficiently before `expiry_height`), the committee outputs a valid signed target-chain transaction in $O(1)$ post-GST consensus rounds plus at most $f + 1$ asynchronous signing rounds ($1$ post-anchor round when the initial quorum $S_0$ has no active disrupters).*

*Proof sketch.* After GST, partially synchronous BFT SMR with $\ge n - f \ge 2f + 1$ honest nodes commits `AnchorCert` within $O(\Delta)$ time. Every honest node passes Gate 0/Gate 1 (by completeness of `AB-cgVSS`) and computes identical `(tx_bytes, m)` via deterministic `BuildTx`. In Round B, both FROST (`rfc9591.txt` §5.4) and Trout++ (`2026-1455.pdf` Theorem 8, PVIA via $\Pi_{\text{Log}}^*, \Pi_{\text{Aff}}, \Pi_{\text{Lin}}$) satisfy **soundness and completeness of publicly verifiable blame**: an honest node is never blamed, and any malformed message in `Setup`, `Presign`, or `Sign` carries a publicly checkable proof fail attributing fault to a specific $P_j \in \mathcal{K}$. By ROAST Theorem 4.3 (`roast.txt` §4.2), since $n - f \ge t$ (for every $t \le n - f$), maintaining disjoint active $t$-quorums and permanently sidelining blamed signers guarantees that at most $f$ sessions can be disrupted before an all-responsive $t$-quorum completes a valid signature without any synchronous timeout. $\square$

---

## 7. Costs

### 7.1 Concrete cost table for $n = 16, 64, 256$

We evaluate OBTS at security level $\lambda = 128$ ($|\Delta_K| = 1827\text{ bits}$) under our **primary decoupled threshold** $t = n - f$ where $f = \lfloor (n-1)/3 \rfloor$, giving $(n, f, t) \in \{(16, 5, 11),\; (64, 21, 43),\; (256, 85, 171)\}$. Parenthetical notes show the **fast-quorum setting** $t_{\text{fast}} = f + 1 \in \{6, 22, 86\}$ and **optimistic `no-IA` ECDSA mode** (where $\Pi_{\text{Aff}}, \Pi_{\text{Lin}}$ proofs are sent only if `ECDSA.Verify` fails).

| Metric | Formula in $(n, t)$ | $n = 16$ ($t = 11$) | $n = 64$ ($t = 43$) | $n = 256$ ($t = 171$) |
|---|---|---|---|---|
| **Owner message size** $\|\mathsf{Msg}_{\mathcal{O}}\|$ (secp256k1)\* | $1{,}310 + 225n + 33(t - 1)\text{ B}$ | **$5{,}240\text{ B}$** (`5.12 KiB`) | **$17{,}096\text{ B}$** (`16.70 KiB`) | **$64{,}520\text{ B}$** (`63.01 KiB`) |
| *(Fast-quorum $t_{\text{fast}} = f + 1$ message size)* | $1{,}310 + 225n + 33f\text{ B}$ | *`5,075 B` (`4.96 KiB`)* | *`16,403 B` (`16.02 KiB`)* | *`61,715 B` (`60.27 KiB`)* |
| **Owner computation** (1 core, 2.4–2.6 GHz) | $8 + 2.9n + 0.03t\text{ ms}$ | **`55 ms`** | **`195 ms`** | **`755 ms`** |
| **Schnorr rounds** (offline / online MPC)\*\* | $1\text{ offline} \;/\; 1\text{ post-anchor}$ | **`1 / 1`** (+1 BFT anchor) | **`1 / 1`** (+1 BFT anchor) | **`1 / 1`** (+1 BFT anchor) |
| **ECDSA rounds** (offline / online MPC)\*\* | $1\text{ offline} \;/\; 2\text{ online (1 post-anchor)}$ | **`1 / 2`** (`Setup` on anchor + `1`) | **`1 / 2`** (`Setup` on anchor + `1`) | **`1 / 2`** (`Setup` on anchor + `1`) |
| **Schnorr offline comm / node** (tx / pool rx) | `66 B` tx / $66(n-1)\text{ B}$ rx | `66 B` / **`0.97 KiB`** | `66 B` / **`4.06 KiB`** | `66 B` / **`16.44 KiB`** |
| **Schnorr online comm / active signer** (tx / peer rx)\*\*\* | `98 B` tx / $32(t-1)\text{ B}$ peer rx | `98 B` / **`0.31 KiB`** (`5.7 KiB` w/ $\mathsf{Msg}_{\mathcal{O}}$) | `98 B` / **`1.31 KiB`** (`18.3 KiB` w/ $\mathsf{Msg}_{\mathcal{O}}$) | `98 B` / **`5.31 KiB`** (`68.6 KiB` w/ $\mathsf{Msg}_{\mathcal{O}}$) |
| **Schnorr compute / node** (offline / online, 1 core) | $<0.1\text{ ms}$ / $4.9 + 1.25n + 0.045t\text{ ms}$ | `< 0.1 ms` / **`25.4 ms`** | `< 0.1 ms` / **`86.8 ms`** | `< 0.1 ms` / **`332.6 ms`** |
| **ECDSA offline comm / node** (tx / pool rx) | `1,350 B` tx / $1{,}350(n-1)\text{ B}$ rx | `1.32 KiB` / **`19.78 KiB`** | `1.32 KiB` / **`83.06 KiB`** | `1.32 KiB` / **`336.18 KiB`** |
| **ECDSA online comm / active signer** (`IA` mode, tx / peer rx)\*\*\* | `3,225 B` tx / $3{,}225(t-1)\text{ B}$ peer rx | `3.15 KiB` / **`31.49 KiB`** (`36.9 KiB` w/ $\mathsf{Msg}_{\mathcal{O}}$) | `3.15 KiB` / **`132.28 KiB`** (`149.3 KiB` w/ $\mathsf{Msg}_{\mathcal{O}}$) | `3.15 KiB` / **`535.40 KiB`** (`598.7 KiB` w/ $\mathsf{Msg}_{\mathcal{O}}$) |
| *(ECDSA online comm / signer, optimistic `no-IA`)* | `1,207 B` tx / $1{,}207(t-1)\text{ B}$ peer rx | *`1.18 KiB` / `11.79 KiB`* | *`1.18 KiB` / `49.51 KiB`* | *`1.18 KiB` / `200.38 KiB`* |
| **ECDSA offline compute / node** (`Presign` + $(t-1)$ checks, 1 core) | $103 + 17.5(t - 1)\text{ ms}$ | **`278 ms`** | **`838 ms`** | **`3,078 ms`** (`3.08 s`) |
| **ECDSA online compute / signer** (`IA` unbatched, 1 core) | $\mathsf{DealRx} + 364 + 37(t - 1)\text{ ms}$ | **`759 ms`** (`0.76 s`) | **`2,003 ms`** (`2.00 s`) | **`6,981 ms`** (`6.98 s`) |
| *(ECDSA online compute / signer, optimistic `no-IA` + batched `Setup`)* | $\mathsf{DealRx} + 368 + 1.5(t - 1)\text{ ms}$ | ***`408 ms`** (`0.41 s`)* | ***`516 ms`** (`0.52 s`)* | ***`950 ms`** (`0.95 s`)* |

*\*On Ed25519 without 1-byte point slot padding, subtract $(t + 1)$ bytes ($5{,}228\text{ B}$, $17{,}052\text{ B}$, $64{,}348\text{ B}$).*  
*\*\*Online MPC rounds are shown for the synchronous/happy path; under worst-case active disruption by $f$ Byzantine signers, ROAST runs at most $f + 1$ asynchronous 1-round signing sessions concurrently/sequentially without timeouts. BFT `AnchorCert` adds 1 consensus commit (2–3 message delays in Mysticeti/HotStuff), and ECDSA `Setup` (`720 B`) rides inside the `AnchorCert` vote.*  
*\*\*\*Online communication lists pure peer-to-peer signing bytes received from $(t - 1)$ quorum peers first, followed in parentheses by total ingress including reading $\mathsf{Msg}_{\mathcal{O}}$ once plus the `~280 B` `AnchorCert`.*

### 7.2 Derivations from local primary benchmarks

1. **Element sizes and owner message bytes**:
   In `cgVSS` (`2023-451.pdf` §8, Table 1) and `Trout++` (`2026-1455.pdf` §7, p. 19) at $|\Delta_K| = 1827\text{ bits}$, a compressed reduced binary quadratic form in $\hat{\mathbb{G}}$ takes `225 B` (`1,800 bits`), a compressed secp256k1 point takes `33 B`, a scalar in $\mathbb{F}_q$ takes `32 B`, and the integer `PoCS` response $z_r \in [0, \tilde{s} \cdot 2^{2\lambda+1}]$ takes $\lceil (914 + 257)/8 \rceil + 15 = 261\text{ B}$. Summing the fixed envelope (`hdr` `40 B` + `chain_id` `32 B` + `X_eff` `33 B` + `Intent` `140 B` + $\sigma_{\text{auth}}$ `64 B` = `309 B`), `R_deal` (`225 B`), `PoCS` $\pi_{\text{CS}}$ ($2 \times 225 + 33 + 261 + 32 = 776\text{ B}$), $n$ share ciphertexts (`225n B`), and $t - 1$ non-constant Feldman commitments (`33(t-1) B`) yields $309 + 225 + 776 + 225n + 33(t - 1) = 1{,}310 + 225n + 33(t - 1)\text{ B}$.
2. **Owner dealing and node `AB-cgVSS` verification CPU**:
   `cgVSS` (`2023-451.pdf` §8 & App. J, measured single-threaded in C++/PARI-BICYCL on a 2.4 GHz Xeon E5-2680 v4) reports **`0.62 s` dealer time** and **`0.25 s` public verification time** at $n = 200$ (`t = 100`). Dealer work is $(n + 3)$ full CL exponentiations (`r Y_{e,i}`, `r G_q`, `k_r G_q`, `k_r Y_agg`) plus $n$ easy-subgroup `x_i H` embeddings and $(t - 1)$ secp256k1 fixed-base multiplications (`~30 µs` each), giving $\approx 2.9\text{ ms}$ per receiver plus `8 ms` fixed `PoCS` overhead ($8 + 2.9n + 0.03t\text{ ms}$: `55 ms` at $n=16$, `195 ms` at $n=64$, `755 ms` at $n=256$; at $n=200$ this gives `591 ms`, matching `0.62 s`). Verifier work uses two $n$-wide $\lambda$-bit small-exponent CL multi-exponentiations (`Y_agg`, `E_agg`), four CL exponentiations (`1.25 ms/party` slope, giving `254 ms` at $n=200$, matching `0.25 s`), our **single $t$-wide secp256k1 MSM** (`~0.015t ms` via Pippenger/Strauss), and one local CL decryption `E_i - sk_{e,i} R_deal` + `DLsolve` (`~3.5 ms`), giving $\mathsf{DealRx}(n, t) = 4.5 + 1.25n + 0.015t\text{ ms}$.
3. **Schnorr (`FROST + ROAST`) communication and CPU**:
   Each RFC 9591 FROST commitment (`D_i, E_i`) is $2 \times 33 = 66\text{ B}$, and each online share $z_i$ is `32 B` (`98 B` sent when bundling the next commitment). NEAR's `threshold-signatures` benchmark (`near-benches-results.md`) measures full 16-party Ed25519 FROST signing at `1.74 ms` total (`< 0.4 ms` online step with presign). Adding `0.03t ms` for the $t$-wide group-nonce MSM $R = \sum_{j \in S} (D_j + \rho_j E_j)$ and PVIA share verification check yields $0.4 + 0.03t\text{ ms}$ beyond $\mathsf{DealRx}(n,t)$.
4. **ECDSA (`Trout++ + ROAST`) communication and CPU**:
   `Trout++` (`2026-1455.pdf` §7 Tables 2 & 3, measured single-threaded in Rust + `BICYCL` on an AMD EPYC 9B14 at 2.6 GHz) reports exact per-party wire sizes of **`1,350 B` (`Presign`)** and **`2,505 B` (`Sign`, `IA`)** or **`487 B` (`Sign`, `no-IA`)**, plus `~720 B` for `Protocol 2 (Setup)` ($C_i$ [`225 B`] + $\Pi_{\text{Log}}^*$ [`495 B`]), totaling `3,225 B` online tx in `IA` mode (`1,207 B` in `no-IA`). For single-core CPU (using `BICYCL` variable-time wNAF CL arithmetic as reported in `2026-1455.pdf` Table 3): 1-party base costs are `103 ms` (`Presign`) and `303 ms` (`Sign`). Across `34-of-50` (`33` peers) and `67-of-100` (`66` peers), `Trout++` Table 3 reports `1,608 ms` and `2,599 ms` combined `Presign + Sign` (`(1608 - 406)/33 = 36.4 ms/peer`), which splits into `~17.5 ms/peer` for $\Pi_{\text{Log}}^*$ verification (`Presign` and `Setup`) and `~19.5 ms/peer` for $\Pi_{\text{Aff}} + \Pi_{\text{Lin}}$ verification (`Sign`). Batching the $(t - 1)$ $\Pi_{\text{Log}}^*$ checks in `Setup` with random 128-bit weights (identical to `cgVSS`) and running `Sign` in optimistic `no-IA` mode reduces online slope to `~1.5 ms/peer`, bringing 256-node online ECDSA CPU under **`1.0 s`** on a single core!
   - *Constant-time witness disclosure*: As `Trout++` (`2026-1455.pdf` Table 3) documents transparently, enabling naive bit-by-bit constant-time exponentiation on secret witnesses in `BICYCL` adds `~3.5 s` to `Presign` and `~8.5 s` to `Sign` (`15.2 s` total at $t=34$ on 1 core), whereas **public** peer-proof verifications remain fast (`~36 ms/peer`) because proof inputs are public. On an 8-core server, running the 6 independent witness exponentiations in parallel reduces constant-time online `Sign` overhead to `~1.6 s`.

---

## 8. Gaps closed and left open

Against `REPORT.md` Section 5.1 (primary gaps 1–6, one line each):

1. **Gap 1 — Address-bound key import in one message**: **CLOSED (under static corruption)** — `AB-cgVSS` deals the normalized scalar $x_{\text{eff}}$ of an existing ECDSA, BIP-340 Taproot, or Ed25519 address in one message with $A_0 = X_{\text{eff}}$ publicly verified against the on-chain address; adaptive-corruption proof without erasures remains open.
2. **Gap 2 — Dealt shares to signing state**: **CLOSED** — `AB-cgVSS` decrypts directly to plain `dlog-sss-correct` Shamir shares $x_i \in \mathbb{F}_q$ that feed FROST (Schnorr) and Trout++ (ECDSA over the same class group $\hat{\mathbb{G}}$) with zero owner-assisted conversion and 100% key-independent presignatures.
3. **Gap 3 — Single-transaction capability without an owner share**: **CLOSED BELOW THRESHOLD ($< t$ corruptions); OPEN AT OR ABOVE THRESHOLD ($\ge t$ corruptions, policy only)** — any $< t$ corrupt nodes (`< 2n/3` in primary mode) cannot sign a second or unauthorized tx, whereas $\ge t$ corrupt nodes can reconstruct $x_{\text{eff}}$ (proved unavoidable when post-owner chain state enters `sighash` in Proposition 1).
4. **Gap 4 — Committee-side transaction construction**: **CLOSED** — consensus commits a 120-byte `AnchorCert` fixing finalized chain height and median feerate, from which every honest node deterministically constructs identical UTXO (Bitcoin/Taproot) or account (EIP-1559/Solana) transactions and `sighash` bytes locally.
5. **Gap 5 — Formal model**: **CLOSED** — $\mathcal{F}_{\text{OBTS}}$ (Section 6.1) unifies one-shot offline owner dealing, address-key normalization, consensus chain-state anchoring, deterministic `ValidBuild` intent predicates, single-spend `Spent` freshness, and epoch rotation.
6. **Gap 6 — Requests across a committee change**: **CLOSED** — owner messages carry `(epoch, expiry_height)`, anchored requests drain in 1 round during `HandoverGrace`, and unanchored pending requests reshare non-interactively to $\mathcal{C}_{e+1}$ via Lagrange-weighted `cgVSS` without discarding $\mathcal{C}_{e+1}$'s key-independent presignatures.

*Secondary items in `REPORT.md` §5.1 (7–11), one line each:*
- **Gap 7 (Committee size under adaptive corruption)**: **PARTIALLY CLOSED** — Section 2.3 gives explicit tail bounds at $20\%\text{–}25\%$ corruption ($< 2^{-108}$ secrecy breach at $n=256, t=171$), though full adaptive simulation without erasures remains open.
- **Gap 8 (Imported keys stay live)**: **MITIGATED OPERATIONALLY (OPEN CRYPTOGRAPHICALLY)** — the owner still knows the pre-existing key, so OBTS specifies single-output **Sweep Mode (`tx_mode = 0x01`)** to drain the entire address balance in one shot and leave zero change behind.
- **Gap 9 (Key formats of real addresses)**: **CLOSED** — Section 3.1 specifies exact scalar normalization for RFC 8032 clamped Ed25519 seeds and BIP-340 even-$y$ + Taproot-tweaked keys so $X_{\text{eff}} = x_{\text{eff}} E$ holds across dealing, signing, and resharing.
- **Gap 10 (Request-channel abuse and request privacy)**: **ABUSE CLOSED / PRIVACY OPTIONAL** — `Gate 0` filters forged packets in $50\,\mu\text{s}$ via outer signature $\sigma_{\text{auth}}$ before any class-group math; `Intent` is public by default (encryptable via threshold CL ElGamal if MEV-sensitive).
- **Gap 11 (Measured end-to-end latency)**: **OPEN PENDING PROTOTYPE** — Section 7 derives concrete projections from measured `cgVSS`, `FROST`, and `Trout++` benchmarks, and Section 11 defines the harness to measure end-to-end WAN latency in this repo.

---

## 9. Comparison with Form A and Form B

| Dimension | Form A (`REPORT.md` §1: Standing Key + Auth Request, e.g., HOT + Groth–Shoup / NEAR) | Form B (`REPORT.md` §1: Owner Share + `future sign`, e.g., Ika 2PC-MPC) | **OBTS (This Design: `AB-cgVSS` + Anchored `BuildTx` + `FROST` / `Trout++` + `ROAST`)** |
|---|---|---|---|
| **Works on an existing address in 1 owner move?** | **No.** Committee-born addresses need 0 import moves; existing addresses require a separate prior dealing + no address-binding proof in published systems. | **No.** Key import takes 2 owner transactions + registration (`REPORT.md` `[B6]`), plus a separate `future sign` move. | **Yes.** Single `5.1–63.0 KiB` message imports and authorizes an existing ECDSA, BIP-340 Taproot, or Ed25519 address with public proof $A_0 = X_{\text{eff}}$. |
| **Owner reads live committee / presig state first?** | No (for standing keys). | **Yes.** `future sign` requires reading an active committee presignature and chain nonce/UTXO state before posting. | **No.** Owner needs only static epoch public keys $\{Y_{e,i}\}$ and goes permanently offline. |
| **Committee builds the transaction?** | **No.** Caller supplies raw bytes or hash; nodes do not select UTXOs, nonces, or fees. | **No.** Owner's partial signature locks the exact message digest $m$ before owner goes offline. | **Yes.** Consensus `AnchorCert` + deterministic `BuildTx` selects UTXOs/nonce, fee, and change after owner is offline. |
| **Single-spend & intent limit** | Honest-threshold policy at $\ge t$ corruptions; single-honest-signer check below $t$ (in HOT). | **Cryptographic** (even $n$-of-$n$ corrupt committee cannot sign a 2nd message without user share $x_A$). | **Cryptographic below $t$** (up to $\approx \frac{2}{3}n$ corruptions cannot sign unauthorized tx); **honest-threshold policy at $\ge t$** (optimal by Proposition 1). |
| **Key-to-signing state conversion** | Standing DKG creates shares directly; Paillier/OT systems cannot ingest dealt Shamir shares without owner. | Encrypted user/network split (`2PC-MPC` CL ciphertexts + 8 proofs). | **Zero conversion.** Plain Shamir shares $x_i$ feed FROST and Trout++ directly; presignatures are 100% key-independent. |
| **Online committee MPC rounds** | `1` (Groth–Shoup / FROST w/ presign) or `3` (NEAR OT-ECDSA). | `O(1)` network rounds over Mysticeti broadcast after `future sign` approval. | **`1` post-anchor round** for both Schnorr (`FROST+ROAST`) and ECDSA (`Trout+++ROAST`, with `Setup` on anchor). |
| **Behavior across committee rotation** | IC discards in-creation presigs on reshare; NEAR runs 11.5-round PedPop+ reshare. | Bound to Sui validator stake epochs. | Drains anchored spends in 1 round; reshares pending spends via `cgVSS` with **zero presignature invalidation**. |

*Note on a class-group-free Schnorr variant (`OBTS-Golden`):* If only Schnorr addresses (BIP-340 Taproot and Ed25519) are targeted and an operator wishes to eliminate class-group assumptions entirely, `AB-cgVSS` can be swapped for **Golden** (`2025-1924.pdf`: non-interactive DDH eVRF pad encryption + Bulletproofs over `secp256k1`/`edwards25519` directly, pinning $A_0 = X_{\text{eff}}$), shrinking $\mathsf{Msg}_{\mathcal{O}}$ at $n = 256$ from `63 KiB` to `~20 KiB` under pure discrete-log assumptions—at the cost of losing the shared class group $\hat{\mathbb{G}}$ that powers 1-post-anchor-round Trout++ ECDSA.

---

## 10. Risks and attacks you considered

### 10.1 Attacks OBTS stops

1. **Rogue-address / Bait-and-Switch Dealing**: A malicious requester posts a valid dealing of some scalar $x' \neq x_{\text{eff}}$ while claiming `X_eff` in the header so committee nodes waste presignatures or sign with the wrong key. *Stopped*: `AB-cgVSS.Ver` hardwires $A_0 := X_{\text{eff}}$ (never reading $A_0$ separately) and checks $\mathsf{addr}(X_{\text{eff}})$ on-chain.
2. **Intent Stripping / Replay / Cross-Chain Splicing**: An attacker strips `Intent` from $\mathsf{Msg}_{\mathcal{O}}$ and attaches a new `Intent'` paying the attacker while reusing `(R_deal, {E_i}, {A_j})`. *Stopped twice*: `Intent`, `chain_id`, `epoch`, and `nonce_salt` are hashed inside the Fiat–Shamir `PoCS` context $\mathsf{ctx}$ (so changing `Intent` invalidates $\pi_{\text{CS}}$) **and** signed by $\sigma_{\text{auth}}$ under $x_{\text{eff}}$.
3. **Public Request-Channel CPU Exhaustion (`REPORT.md` Gap 10)**: An attacker floods the bulletin board with $64\text{ KiB}$ garbage class-group elements to force nodes into `327 ms` CL multi-exponentiations. *Stopped*: `Gate 0` verifies the 64-byte native signature $\sigma_{\text{auth}}$ under $X_{\text{eff}}$ in `~50 µs` before a single class-group operation runs (and on a host chain, submitting $\mathsf{Msg}_{\mathcal{O}}$ pays calldata gas).
4. **Presignature Reuse, Additive-Tweak Forgery, and Implementation Attacks (`BitForge`, `TSSHOCK`, `CVE-2025-66017`)**:
   - Reusing a FROST or ECDSA presignature across two digests leaks $x_{\text{eff}}$ immediately. *Stopped*: `AnchorCert` atomically binds `presig_slot` to `req_id` in BFT consensus, and each node **zeroizes** $(d_{i,\ell}, e_{i,\ell})$ or $(k_{i,\ell}, \gamma_{i,\ell})$ in RAM *before* writing its online share to the socket.
   - `Groth–Shoup (2021/1330)` / `Lockness CVE-2025-66017` presignature + BIP-32 additive key derivation attacks on raw hashes. *Stopped*: OBTS never applies post-presignature BIP-32 key tweaks, never signs caller-supplied raw hashes (nodes hash full constructed transactions inside `BuildTx`), and incorporates Trout++ deterministic nonce shift $\tau$.
   - `BitForge` (`bf.txt`, Paillier small-factor / missing range proofs in GG18/GG20/Lindell17) and `TSSHOCK` (`tsshock.txt`, ambiguous unframed Fiat–Shamir concatenations, alpha-shuffle replay, missing Ed25519 torsion checks). *Stopped*: OBTS uses **zero Paillier keys**, enforces canonical fixed-width length-prefixed domain tags on every hash (`H_pocs`, `H_auth`, `H_req`, `H_frost`), and checks $\ell \cdot X_{\text{eff}} = \mathcal{O}$ on Ed25519.
5. **Byzantine Griefing / Stalled Signing Sessions**: Up to $f$ corrupt nodes send malformed shares or go silent during Round B. *Stopped*: FROST share verification and Trout++ $\Pi_{\text{Log}}^*, \Pi_{\text{Aff}}, \Pi_{\text{Lin}}$ provide non-interactive PVIA, and ROAST routes around up to $f$ faulty signers asynchronously.

### 10.2 Attacks and residual risks OBTS does NOT stop

1. **Collusion of $\ge t$ Committee Nodes (`>= 11` of `16`, `>= 43` of `64`, `>= 171` of `256`)**: A corrupt coalition of size $\ge t$ can decrypt $t$ Shamir shares, interpolate $x_{\text{eff}}$ silently in memory, ignore `Intent` and `Spent[req_id]`, steal all funds on $\mathsf{addr}$, and keep $x_{\text{eff}}$ forever regardless of honest erasure rules. By Proposition 1, preventing a second spend against $\ge t$ corruptions while keeping committee-side dynamic transaction construction is cryptographically impossible without external state-witness encryption or owner co-signing.
2. **Owner Self-Front-Running and Post-Import Key Retention (`REPORT.md` Gap 8)**: Because $x_{\text{eff}}$ originates on the owner's device, the owner still knows $x_{\text{eff}}$ unless erased locally:
   - *Self-front-running*: A malicious owner can post $\mathsf{Msg}_{\mathcal{O}}$ and simultaneously broadcast a conflicting single-signer spend directly to Bitcoin/Ethereum/Solana. This **cannot steal anyone else's funds**—the committee's spend simply fails on $\mathcal{L}_{\text{target}}$ as a double-spent input/nonce—but it wastes one committee presignature and `~0.03–2.0 s` of node CPU. Host-chain submission fees price this griefing cost above committee compute cost.
   - *Residual change exposure*: If the owner uses `exact-amount` mode (`0x02`) and sends change back to the *same* imported address $\mathsf{addr}$, a later compromise of the owner's old backup seed compromises that change (and requires trusting honest committee nodes to have erased $x_i$). **Mitigation**: Always default to **Sweep Mode (`0x01`)** (or direct `change_dest` to a fresh hardware/committee-born address) so the imported address holds `0` balance permanently after the spend.
3. **Public Intent Visibility / Mempool Orderflow Leakage**: Plain $\mathsf{Msg}_{\mathcal{O}}$ exposes `recipient`, `amount`, and `max_fee` before the target-chain transaction lands. For standard native transfers (BTC/ETH/SOL sends) there is no sandwichable AMM slippage, but for future DeFi contract-call intents, `Intent` would leak MEV unless encrypted under a threshold CL public key $Y_{\text{comm}}$ decrypted only inside `AnchorCert`.
4. **Side-Channel Leakage in Variable-Time Class-Group Arithmetic**: Fast (`0.76–2.0 s`) Trout++ timings use `BICYCL`'s variable-time wNAF reduction; on co-tenant cloud VMs vulnerable to cache/branch timing attacks, nodes must either run dedicated bare-metal hosts or enable constant-time witness blinding/parallelization (`~1.6 s` on 8 cores).
5. **Fee Spikes Past `expiry_height` or Deep L1 Reorgs ($> k_{\text{final}}$)**: If target-chain base fees exceed `Intent.max_fee` continuously until `expiry_height`, OBTS **fails closed** (no spend occurs; the offline owner must post a new message later). If $\mathcal{L}_{\text{target}}$ suffers a catastrophic $> k_{\text{final}}$ reorganization after `Spent[req_id] = true` and share erasure, the committee cannot re-sign for the reorged branch without a new owner move.

---

## 11. Experiment plan

### 11.1 What to build first in `.`

Build in three incremental Rust crates plus one formal Quint model, ordered to retire the newest cryptographic and systems risks earliest:

1. **Phase 1 — `crates/obts-deal` + `crates/obts-schnorr` (Highest-signal prototype, build first)**:
   - Implement `NormalizeKey` for **BIP-340 Taproot** (testing all four parity combinations of internal key $P$ and tweaked output key $Q$, with and without a script-tree Merkle root) and **RFC 8032 Ed25519** (32-byte seed $\to$ SHA-512 $\to$ clamp $\to \bmod\;\ell$).
   - Implement `AB-cgVSS` (`OwnerDealAndAuthorize`, `Gate 0`, and `Gate 1` with our single-$t$-MSM optimization) over $|\Delta_K| = 1827\text{-bit}$ CL groups (`bicycl` FFI wrapper) paired with `k256` and `curve25519-dalek`, feeding decrypted shares directly into `frost-secp256k1-tr` (with BIP-340 odd-$R$ nonce negation) and `frost-ed25519` wrapped in a 250-line asynchronous `ROAST` coordinator/peer state machine.
   - Validate end-to-end against local **`bitcoind -regtest`** (spending a real pre-existing P2TR UTXO) and **`solana-test-validator`** (spending a real pre-existing Ed25519 account).
   - Benchmark owner message bytes, owner CPU, `Gate 1` verify+decrypt CPU, and end-to-end committee wall-clock latency at $n \in \{16, 64, 256\}$ under simulated `100 ms` WAN RTT (directly comparable to NEAR's harness in `research/sources/lifecycle/repos/near-benches-results.md`).
2. **Phase 2 — `crates/obts-txbuilder` + `specs/obts_lifecycle.qnt` (Deterministic builder & formal lifecycle check)**:
   - Implement integer-only deterministic `BuildTx` for Bitcoin P2WPKH/P2TR and Ethereum EIP-1559 (`alloy-primitives` / RLP).
   - Model `AnchorCert`, `Spent[req_id]`, `HandoverGrace`, and $\mathcal{C}_e \to \mathcal{C}_{e+1}$ pending-request resharing in **Quint** (`quint verify`), checking invariants `NoDoubleSpend`, `NoUnauthorizedDigest`, and `EventuallySpentOrExpired` across epoch boundaries with up to $f < n/3$ Byzantine processes.
3. **Phase 3 — `crates/obts-ecdsa` (`AB-cgVSS` $\to$ `Trout++` secp256k1 bridge)**:
   - Implement `Trout++` (`Setup`, stocked `Presign`, and `Sign` in both `IA` and optimistic `no-IA` modes) sharing the exact `obts-deal` $|\Delta_K| = 1827\text{-bit}$ `secp256k1` class group, and validate a live EIP-1559 spend on `anvil` and P2WPKH spend on `bitcoind -regtest`.

### 11.2 What would prove this design wrong (explicit falsifiers)

1. **Algebraic / Address-Compatibility Falsifier**: Any existing Bitcoin P2TR wallet key (odd-$y$ internal key or script-tree tweaked output key) or standard 32-byte Solana/Sui Ed25519 seed where `NormalizeKey` + `AB-cgVSS` ($A_0 = X_{\text{eff}}$) + `FROST` produces a signature rejected by unmodified `bitcoind` or `solana-test-validator`.
2. **Class-Group Verification Scaling Falsifier**: If single-core `Gate 1` (`AB-cgVSS.Ver` + 1 `DLsolve`) at $n = 256, t = 171$ exceeds **`1.0 s`** (more than $3\times$ our `327 ms` derivation from `cgVSS`), or if constant-time hardening of `Trout++` witness operations cannot complete an $n = 64$ ECDSA spend in under **`5.0 s`** wall-clock on an 8-core machine—which would prove that Golden (`2025-1924.pdf`) + Groth–Shoup/OT-ECDSA dominates class groups in practice.
3. **Determinism Divergence Falsifier**: Any fuzzing input `(Msg_O, B_anc)` on which two honest nodes running `BuildTx` across x86_64 and aarch64 produce distinct `tx_bytes` or `sighash` values, or produce non-standard transactions rejected by `bitcoind` policy rules (dust, weight, `MINIMALIF` / low-$s$).
4. **Lifecycle Safety/Liveness Falsifier**: A counterexample trace in `quint verify` where $\le f$ Byzantine nodes plus arbitrary network delays prior to GST cause either (a) both $\mathcal{C}_e$ and $\mathcal{C}_{e+1}$ to emit online signing shares for the same `req_id` (double-spend / key-leak via presig clash), or (b) a funded request arriving well before `expiry_height` to be dropped across epoch handover.

---

## 12. References

### 12.1 Primary sources read in full from local repository copies

1. **Design Brief** — *Design brief: one owner move, then a committee spends*. **read in full (`design/BRIEF.md`)**.
2. **State-of-the-Art Report** — *One owner move, then a committee signs: the state of the art* (2026-11-13). **read in full (`research/REPORT.md`)**.
3. **cgVSS** — A. Kate, E. V. Mangipudi, P. Mukherjee, H. Saleem, S. A. K. Thyagarajan, *Non-interactive VSS using Class Groups and Application to DKG*, ACM CCS 2024 / IACR ePrint 2023/451 (23 pp.). **read in full (`research/sources/eprint/2023-451.pdf`)**.
4. **Trout** — H. Dahari-Garbian, A. Nof, L. Parker, *Trout: Two-Round Threshold ECDSA from Class Groups*, ACM CCS 2025 / IACR ePrint 2025/1666 (14 pp.). **read in full (`research/sources/eprint/2025-1666.pdf`)**.
5. **Trout++** — A. Nof, L. Parker, *Trout++: Robust Asynchronous Two-Round ECDSA for Arbitrary Thresholds*, ESORICS 2026 / IACR ePrint 2026/1455 (29 pp.). **read in full (`research/sources/eprint/2026-1455.pdf`)**.
6. **Lyu et al.** — Y. Lyu, Z. Li, H.-S. Zhou, X. Deng, *Threshold ECDSA in Two Rounds*, ACM CCS 2025 / IACR ePrint 2025/1696 (14 pp.). **read in full (`research/sources/eprint/2025-1696.pdf`)**.
7. **Golden** — B. Bünz, K. Choi, C. Komlo, *Golden: Lightweight Non-Interactive Distributed Key Generation*, CRYPTO 2026 / IACR ePrint 2025/1924 (63 pp.). **read in full (`research/sources/eprint/2025-1924.pdf`)**.
8. **Janus** — R. Baecker, P. Gerhart, S. Jarecki, P. Nazarian, D. Rausch, D. Schröder, *Adaptive Distributed Key Generation for Discrete-Log Cryptosystems*, IACR ePrint 2026/892 (38 pp.). **read in full (`research/sources/eprint/2026-892.pdf`)**.
9. **FROST (RFC 9591)** — D. Connolly, C. Komlo, I. Goldberg, C. A. Wood, *The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol for Two-Round Schnorr Signatures*, IRTF RFC 9591, June 2024. **read in full (`research/sources/lifecycle/rfc9591.txt`)**.
10. **ROAST** — T. Ruffing, V. Ronge, E. Jin, J. Schneider-Bensch, D. Schröder, *ROAST: Robust Asynchronous Schnorr Threshold Signatures*, ACM CCS 2022 / IACR ePrint 2022/550. **read in full (`research/lanes/terra-threshold-schnorr-bls-deep-read/sources/roast.txt`)**.
11. **HOT Protocol** — P. Volnov, A. Kuksa, N. Zhevlakov, *HOT Protocol: Decentralized MPC Network for Stateful Smart-Contract Signing*, arXiv:2512.02287v1, 2025. **read in full (`research/sources/hot.txt`)**.
12. **Stambler ($T+1$-eWEB)** — L. Stambler, *Achieving Blockchain-Secured Cryptographic Primitives from Signature-Based Witness Encryption*, IACR ePrint 2025/1064 (21 pp.). **read in full (`research/sources/eprint/2025-1064.pdf`)**.
13. **Budgeted Threshold Signatures (BTS)** — H. Chen, Y. Zhang, Y. Cheng, *Budgeted Threshold Signatures: Protocol-Native Spending Limits with Zero On-Chain Footprint*, IACR ePrint 2026/2176 (19 pp.). **read in full (`research/sources/eprint/2026-2176.pdf`)**.
14. **Threshold Signatures as-a-Service (TSaaS)** — M. Rambaud, S. Roth, A. Urban, *Threshold Signatures as-a-Service: Achieving Threshold ML-DSA in One Online Round*, IACR ePrint 2026/814 (30 pp.). **read in full (`research/sources/eprint/2026-814.pdf`)**.
15. **Threshold Cryptography as a Service (TCaaS)** — F. Benhamouda, S. Halevi, H. Krawczyk, P. Miao, T. Rabin, *Threshold Cryptography as a Service (in the Multiserver and YOSO Models)*, ACM CCS 2022 (15 pp.). **read in full (`research/sources/eprint/ccs2022-threshold-cryptography-as-a-service.pdf`)**.
16. **Ika Whitepaper** — O. Sadika, Y. Lachmish, Y. C. Scaly, D. Hussain, *Ika: Fast, Decentralized and Secure Interoperability Powered by 2PC-MPC*, v1.0, October 2024 (11 pp.). **read in full (`research/sources/deployed/ika-whitepaper.pdf`)**.
17. **NEAR MPC Benchmarks** — NEAR `mpc` / `threshold-signatures` benchmark results. **read in full (`research/sources/lifecycle/repos/near-benches-results.md`)**.
18. **BitForge** — N. Makriyannis, O. Yomtov, A. Galansky, *Practical Key-Extraction Attacks in Leading MPC Wallets*, Fireblocks / IACR ePrint 2023/1234, August 2023. **read in full (`research/sources/bf.txt`)**.
19. **TSSHOCK** — D. Nguyen et al., *TSSHOCK: Breaking MPC Wallets — New Key Extraction Attacks on Threshold ECDSA Implementations*, Verichains / Black Hat USA 2023 White Paper. **read in full (`research/sources/tsshock.txt`)**.
20. **Native-Signature Boundary** — P. Porechna, *The Native-Signature Boundary in Post-Quantum Distributed Authorization*, arXiv:2609.03547v1, September 2026. **read in full (`research/sources/native-sig-boundary-2609.03547.txt`)**.

### 12.2 Standards and related literature cited from memory or via `REPORT.md` passages

21. **BIP-340 / BIP-341 / BIP-141 / BIP-143 / BIP-62 / BIP-69** — Bitcoin Improvement Proposals (Schnorr signatures for secp256k1, Taproot key-path tweaking, SegWit weight units & sighash, low-$s$ canonicalization, lexicographic indexing). **from memory, not checked**.
22. **RFC 8032** — S. Josefsson, I. Liusvaara, *Edwards-Curve Digital Signature Algorithm (EdDSA)*, IETF RFC 8032, January 2017 (Ed25519 seed SHA-512 clamping). **from memory, not checked**.
23. **EIP-2 / EIP-155 / EIP-1559** — Ethereum Improvement Proposals (low-$s$ ECDSA malleability fix, replay-protected `chainId`, Type-2 basefee + priority-fee transaction format). **from memory, not checked**.
24. **Groth–Shoup Distributed ECDSA & Presignature Security** — J. Groth, V. Shoup, *Design and analysis of a distributed ECDSA signing service* (IACR ePrint 2022/506) and *On the security of ECDSA with additive key derivation and presignatures* (IACR ePrint 2021/1330); cited via `REPORT.md` `[P1], [P2]`. **from memory, not checked** *(full PDFs not read in full)*.
25. **Castagnos–Laguillaumie Class Groups & Hafner–McCurley Subexponential Bound** — G. Castagnos, F. Laguillaumie, *Linearly Homomorphic Encryption from DDH* (CT-RSA 2015); J. L. Hafner, K. S. McCurley (J. AMS 1989); parameter formulas verified via `cgVSS` (`2023-451.pdf`) and `Trout++` (`2026-1455.pdf`), original papers **from memory, not checked**.
26. **2PC-MPC Formal Papers** — O. Friedman et al., *2PC-MPC: Emulating Two Party ECDSA in Large-Scale MPC* (IACR ePrint 2024/253) and *Practical Zero-Trust Threshold Signatures in Large-Scale Asynchronous Networks* (IACR ePrint 2025/297); Form B mechanics verified via `REPORT.md` `[B5, B6, P12]`, full ePrint PDFs **from memory, not checked**.
