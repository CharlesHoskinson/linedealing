# Testnet end to end: plan (LOOP item 34, phase 1)

Goal: for each network, the split-line committee key derives an address, receives testnet funds and signs a spend that the network confirms. Mainnet is out of scope on every network: each broadcast first asserts the chain identity (table in section 6).

Status: design only. No Cargo.toml, Cargo.lock or tool change is made until the Codex + Opus install check approves the list in section 7.

## 1. Signing path

Use the split-line prototype (`src/split`). It is the subject of LOOP.md, and it is the only path that gives a standard BIP86 Taproot key.

| Suite | Split API used | Message signed | Networks |
|---|---|---|---|
| BIP340 | `request::SchnorrSetup<Secp>` + envelope + `BoardAdapter` (the `split_e2e.rs` flow) | BIP341 key-path sighash | Bitcoin P2TR |
| BIP340 | the same committee, slots and nodes, through the lower `schnorr::Request` / `Node::release` / `schnorr::combine` API | SHA-256(`Intent.signatureData`) | Midnight |
| ECDSA | `request::ecdsa::EcdsaRequest` + envelope + board (the `p2wpkh_k3_l2` flow) | BIP143 sighash | Bitcoin P2WPKH |
| ECDSA | `split::ecdsa::Slot` + `Ticket { slot, hash }` + `contribute` / `partial` / `combine` | EIP-1559 keccak sighash | Ethereum |
| Ed25519 | `request::SchnorrSetup<Edwards>` + envelope + board, suite 3 host message | the raw message bytes | Solana (message), Cardano (blake2b-256 of the body) |

Reasons:
- **Late-bound messages.** A live sighash depends on the funding outpoint, the account nonce or the recent blockhash. The split request flow signs the transactions in `setup.variants`, so each live test builds the real transaction first and then replaces `setup.variants` (k = 1, l = 1) before `build()`. `decode_bitcoin` accepts only version 2 with sequence 0xfffffffd, so the Bitcoin transactions use the builder's subset.
- **P2TR output key.** `SchnorrSuite::output_key` for Secp applies the BIP341 TapTweak with an empty root (the BIP86 form). The base path (`wire::address_for`, addr_type 4) uses the raw even-y key as the output key. That form is consensus-valid, but it is not what BIP86 wallets use.
- **Ethereum and Midnight are not Bitcoin transactions.** Bitcoin decoding is fixed into `EcdsaVariant::bitcoin` and `SpendVariant::messages(suite 2)`. For these two networks, the tests drive the same committee one layer lower and sign a 32-byte hash. The envelope is not used for them. If the lead wants the envelope here too, add a host-hash variant to `EcdsaVariant`/`SpendVariant`. That change is in the protocol code and needs its own Quint check, so this plan does not include it.

What stays simulated, and the report says so:
- All parties run in one process.
- `Committee::generate` and `ActorShares::generate` are trusted dealers inside the fixture.
- ECDSA presignatures come from `Slot::ideal` (ideal F_presig/F_mul).
- The board is the in-memory `BoardAdapter`. No Midnight board write happens.

## 2. Keys and nonces

- `impl/testnet/keys.local` is git-ignored (`impl/testnet/*.local` goes into `.gitignore`), mode 600. It holds one 32-byte seed per suite, created by `OsRng` on first use. Nothing prints it.
- The key draws (committee shares, actor shares, birth seed, tweak) come from a deterministic stream: SHA-256 in counter mode over the seed, tagged "testnet/key". The existing `TestRng` is public, so no key comes from it.
- Nonce material (`CommitteeSlots::generate`, `ActorPool::new`, `Slot::ideal`, transport keys) always comes from a fresh `OsRng` on each run. A rerun with a new sighash therefore never reuses a nonce. This needs one small refactor: `SchnorrSetup::new_with_rngs(key_rng, nonce_rng)`, with `new(rng)` calling it with the same rng, so existing tests keep their exact draws. The ECDSA fixture (`benches/support::ecdsa`) gets the same split.
- The committee key is `SigningKey::output()` (BIP340, Ed25519) or the ECDSA request's `public_key`. It is never a single local signing key.

## 3. Common live-test design

- Gate: every live test is `#[ignore]` and returns early unless `TESTNET_E2E=1`. Plain `cargo test` stays offline. Run one with `TESTNET_E2E=1 cargo test --test testnet -- --ignored bitcoin_p2tr`.
- HTTP: the tests shell out to the installed `curl` (8.23) through `std::process::Command`, and `serde_json` (already a dev-dependency) parses the replies. No new HTTP crate. The alternative, `ureq` with rustls (about 20 crates), is listed in section 7 only as an option.
- Funding contract (Grok lane, `~/testnet-wallets/`):
  - A funding step runs `~/testnet-wallets/bin/fund-<net> <address> <amount>`, where `<net>` is one of `btc-testnet4`, `btc-signet`, `sepolia`, `cardano-preprod`, `solana-devnet` or `midnight-preview`. The script prints the funding txid on stdout and exits 0.
  - `~/testnet-wallets/bin/return-address-<net>` prints the funding wallet's address. The committee spends back to it.
  - The tests never open `~/testnet-wallets/keys/`.
  - If a script is missing, the test prints the committee address and polls the chain for funds (default 30 minutes, `TESTNET_WAIT_SECS` overrides), then exits with a clear message. A rerun finds the funds because the key seed persists.
- Each test does these steps in order: derive the address, check the chain identity, fund, wait for the funding to confirm, build the spend, sign it with the committee, verify it locally (the section 5 checks), broadcast, wait for confirmation, and assert. Then it appends a row to `impl/testnet/RESULTS.md`: network, scheme, address, funding txid, spend txid, block, explorer link, date.

## 4. Per network

### Bitcoin testnet4 (primary) and signet: P2WPKH ECDSA and P2TR BIP340
- Encoder: the existing `builder::UtxoTransaction` (BIP143 and BIP341 sighashes with BIP vectors already in the crate). New hand-written parts:
  - segwit serialization (marker, flag, witness stacks);
  - the witness itself: `[DER(sig)||01, pubkey33]` for P2WPKH, `[sig64]` for P2TR with SIGHASH_DEFAULT;
  - DER encoding of a low-s signature (about 15 lines; checked against `k256::ecdsa::Signature::to_der` in the offline test);
  - bech32 and bech32m (BIP173/BIP350, about 60 lines, with the BIPs' valid and invalid address vectors).
- Address: `tb1q` + hash160(compressed key); `tb1p` + x(Q), where Q is the tweaked output key.
- Endpoint: Esplora at `https://mempool.space/testnet4/api` and `https://mempool.space/signet/api`. The calls are `/address/{a}/utxo`, `/fee-estimates` and `/tx/{id}/status`, and `POST /tx` for broadcast.
- Chain check: the HRP is `tb`, and `/block-height/0` returns the testnet4 genesis `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043` or the signet genesis `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`.
- Spend: one input, one output back to the return address, fee from `/fee-estimates` (at least 1 sat/vB). One confirmation takes about 10 minutes, so the default wait is 60 minutes.
- Explorer: `https://mempool.space/testnet4/tx/<txid>`.

### Ethereum Sepolia: EIP-1559 ECDSA
- Encoder: the existing `builder::Eip1559Transaction::signing_bytes` and `sighash`. New: the signed envelope `0x02 || rlp([... , y_parity, r, s])` (about 20 lines on the existing RLP helpers).
- Address: keccak256(uncompressed key without the 0x04 prefix)[12..], with the EIP-55 checksum when printed.
- Endpoint: `https://ethereum-sepolia-rpc.publicnode.com`, with `https://sepolia.drpc.org` as fallback. The calls are `eth_chainId`, `eth_getTransactionCount` (pending), `eth_getBlockByNumber` (baseFeePerGas), `eth_maxPriorityFeePerGas`, `eth_sendRawTransaction` and `eth_getTransactionReceipt`.
- Chain check: `eth_chainId` is 11155111, and the same value goes into the signed transaction.
- Spend: 21000 gas, max fee = 2 x base fee + tip, value = balance - gas x max fee, sent to the return address.
- Explorer: `https://sepolia.etherscan.io/tx/<hash>`.

### Cardano preprod: Ed25519 enterprise address, Shelley-format transaction
- Encoder: a hand-written CBOR writer for the fixed subset only (unsigned ints, byte strings, arrays, maps, `true`, `null`; about 50 lines).
  - Body: `{0: [[txid, ix]], 1: [[addr, coin]], 2: fee, 3: ttl}`.
  - Witness set: `{0: [[vkey, sig]]}`.
  - Transaction: `[body, witnesses, true, null]`.
  - Conway accepts untagged input arrays and legacy-array outputs.
- Hash: blake2b-256(body) is the txid and the signed message; blake2b-224(vkey) is the payment credential. This needs the `blake2` crate (section 7).
- Address: header `0x60` (enterprise, key hash, network 0) + credential, bech32 `addr_test`.
- Fee: `minFeeA x size + minFeeB` from the protocol parameters, iterated once over the signed size. The output must stay at or above the min-UTxO; the test sweeps to the return address.
- Endpoint: Koios preprod `https://preprod.koios.rest/api/v1` (keyless). The calls are `/tip`, `/cli_protocol_params`, `POST /address_utxos`, `POST /submittx` (body `application/cbor`) and `POST /tx_status`. Phase 2 first makes a read-only probe that the keyless submit works. The fallback is `cardano-cli` from the Grok lane against a Koios or Blockfrost relay; Blockfrost needs a signup, so it is only a fallback.
- Chain check: the Koios `/genesis` network magic is 1.
- Explorer: `https://preprod.cardanoscan.io/transaction/<txid>`.

### Solana devnet: Ed25519 system transfer
- Encoder: hand-written legacy message (about 60 lines):
  - header `[1, 0, 1]`;
  - account keys `[committee, return address, system program 111...1]`;
  - recent blockhash;
  - one instruction: program index 2, accounts `[0, 1]`, data `u32le(2) || u64le(lamports)`.
  - The transaction is `shortvec(1) || sig || message`, sent as base64.
- Address: base58 of the 32-byte key. Base58 and base64 are hand-written, about 40 lines, with known vectors.
- Endpoint: `https://api.devnet.solana.com`. The calls are `getGenesisHash`, `getBalance`, `getLatestBlockhash`, `getFeeForMessage`, `sendTransaction` and `getSignatureStatuses`. `requestAirdrop` is a keyless fallback funder, rate-limited.
- Chain check: `getGenesisHash` is `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`.
- Traps: a blockhash expires after about 60 to 90 seconds, so the test fetches it, signs and sends in one step and refetches on expiry. The spend sweeps to zero (balance - fee), so no rent-exempt remainder is left.
- Explorer: `https://explorer.solana.com/tx/<sig>?cluster=devnet`.

### Midnight Preview: unshielded NIGHT transfer, BIP340
- Scheme, confirmed:
  - From source: ledger `base-crypto/src/schnorr.rs` wraps `k256::schnorr`, and `Verifier::verify` in k256 0.13.4 checks BIP340 over SHA-256(msg).
  - By a run on this machine: a probe against the installed `@midnightntwrk/ledger-v9` 1.0.0 (Preview runs ledger 9.1.0.1) with a throwaway key showed three things. `SignatureVerifyingKey { tag: "schnorr" }` is the 32-byte x-only key. `signData` is BIP340 over SHA-256(data). `verifySignature` accepts a BIP340 signature over SHA-256(`signatureData`) made outside the ledger.
  - The data signed is `Intent.signatureData(segmentId)`. The address is `addressFromKey(vk)`, a 32-byte persistent hash, shown as bech32m `mn_addr_preview1...`.
- Committee key: the split Secp output key Q. Midnight sees an ordinary BIP340 key, so the TapTweak inside Q has no effect on Midnight.
- Build and submit: Node glue in `impl/testnet/midnight/` uses the already-installed packages under `~/Projects/Moriarty/tools/sherlock-sdk/node_modules` (`ledger-v9` 1.0.0, `wallet-sdk` 2.0.0) by absolute import path. That is no install.
  1. `node mn.mjs address <xonly-hex>` prints the address.
  2. `node mn.mjs build ...` queries the committee UTXO through the indexer GraphQL (`https://indexer.preview.midnight.network/api/v4/graphql`). It builds an `Intent` whose `UnshieldedOffer` spends that UTXO to the return address. It prints `signatureData(1)` as hex.
  3. Rust signs SHA-256 of those bytes with the committee and verifies the signature with k256.
  4. `node mn.mjs submit ...` runs `UnshieldedOffer.addSignatures([sig])`. The funding wallet balances the DUST fee only (`balanceUnprovenTransaction` with dust as the token kind; `signRecipe` signs its own segments), then `finalizeRecipe` and `submitTransaction` through `wss://rpc.preview.midnight.network`.
- Fees: the committee address holds no DUST, so the funding wallet must pay the fee. The facade's `balanceUnprovenTransaction` and `signRecipe(recipe, signSegment)` suggest that a foreign signed offer can be balanced. Phase 2 must confirm two things before the live run: that `signatureData` does not change when balancing adds the fee segment, and that the committee signature survives `finalizeRecipe`. If balancing does change it, the order becomes: balance, read `signatureData`, committee signs, insert the signature, prove and bind.
- Runtime needs:
  - The DUST spend needs a proof server. The Sherlock config uses `http://127.0.0.1:6300`, and nothing listens there now. The owner or the Grok lane must start it; Sherlock runs it as a container.
  - Wallet: prefer the Grok lane's Midnight funding wallet in `~/testnet-wallets/` (STATUS: "searching for an existing Preview wallet"). The existing Moriarty Preview wallet (`~/.local/share/moriarty/wallets/preview/`, seed never read by this lane) is the fallback, because a live Sherlock loop may use it and parallel use books the same coins.
- Chain check: `chain_getBlockHash(0)` on `https://rpc.preview.midnight.network` equals `0x3c096de209e06a1a8c52be7bda109ee8c891a42288c0a9db5495f9616dd13796`, and the network id is `preview`.
- Explorer: the indexer transaction query by hash. A Preview explorer link is added if one exists.
- What is faithful: the committee produces the only signature on the NIGHT input, and the ledger verifies it. The DUST fee is paid by the funding wallet in the same transaction. That is a fee payer, not a co-signer of the committee's input.

## 5. Offline tests (always run, no network)

File `impl/tests/testnet.rs`, with the encoders in `impl/tests/testnet/` (test-only modules; no change to `src/` other than the RNG split in section 2). Each test builds a transaction from fixed inputs, signs it with a committee (the deterministic `TestRng` is fine here, since no funds are involved), and checks the result independently:

| Network | Independent checks |
|---|---|
| Bitcoin | BIP143 and BIP341 sighash vectors (already in the crate); a BIP341 `wallet-test-vectors.json` tweak case for the output key; BIP173/BIP350 address vectors; the signature checked by k256 against the recomputed sighash and the output key parsed back out of the address; witness txid vs wtxid recomputed. When the Grok lane's Bitcoin Core is present (`TESTNET_TOOLS=1`), `bitcoind -regtest` `testmempoolaccept` on a regtest-funded copy is the consensus check. |
| Ethereum | RLP of the EIP-1559 signing payload against a published signed type-2 transaction (decode, re-encode, same keccak hash); `ecrecover` of the committee signature returns the derived address; EIP-55 vectors. With the tools present, `cast decode-transaction` returns the same `from`. |
| Cardano | blake2b vectors (RFC 7693); a body hash equal to a txid computed by `cardano-cli latest transaction txid` on a fixture saved from the tools (committed as hex, so the plain test needs no tool); bech32 `addr_test` round trip; `ed25519_dalek::verify_strict` of the witness. |
| Solana | base58 vectors; a message encoding equal to a fixture made once with the Solana CLI or `@solana/web3.js` (committed as hex); `verify_strict` of the signature on the message bytes. |
| Midnight | signature checked by k256 as BIP340 over SHA-256(data); a committed fixture (`signatureData` bytes + the committee signature + `verifySignature` = true) produced by the ledger-v9 probe script. A test under `TESTNET_TOOLS=1` reruns the probe through Node. |

## 6. Chain identity guards

| Network | Assert before broadcast |
|---|---|
| Bitcoin | HRP `tb`; genesis hash = testnet4 or signet (section 4) |
| Ethereum | `eth_chainId` = 11155111 = the signed chain id |
| Cardano | network id 0 in the address header; network magic 1 |
| Solana | `getGenesisHash` = the devnet hash |
| Midnight | genesis = the Preview hash; network id `preview` |

Any mismatch panics before signing.

## 7. New dependencies and tools (for the Codex + Opus install check)

Required:

| Item | Version | License | Kind | Why |
|---|---|---|---|---|
| `blake2` | `=0.10.6` | MIT OR Apache-2.0 | dev-dependency | Cardano txid (blake2b-256) and payment credential (blake2b-224). RustCrypto, same family as the existing `sha2` and `sha3`; it only adds the `blake2` crate on top of `digest`, which is already in the lock. |

Not required (no install):
- **HTTP:** `curl` 8.23, already installed.
- **JSON:** `serde_json`, already a dev-dependency.
- **Encoders:** bech32, bech32m, base58, base64, DER, RLP and CBOR are hand-written.
- **Midnight:** Node v26.13 is installed. The glue imports the Moriarty sherlock-sdk `node_modules` read-only. It runs no `npm ci`.
- **Funding wallets and CLI tools** (Bitcoin Core 32.1, Foundry `cast`, `cardano-cli` 11.1.3, Solana CLI): the Grok lane installs them under `~/testnet-wallets/`. This lane only calls them, and only under `TESTNET_TOOLS=1` or `TESTNET_E2E=1`.

Options the lead may approve instead (not recommended):
- `ureq` 2.x with rustls (MIT OR Apache-2.0), in place of curl, for in-process HTTPS (about 20 transitive crates).
- `minicbor` 0.25 (Apache-2.0), in place of the hand-written CBOR subset.
- `bitcoin` 0.32 (CC0-1.0), dev-only, as a second Rust decoder. Bitcoin Core regtest already covers this check better.

## 8. Requests to the lead

1. Run the install check on section 7. The only required item is `blake2 =0.10.6` as a dev-dependency.
2. Have the Grok lane provide the `fund-<net>` and `return-address-<net>` scripts from section 3, or tell me its interface, and I will match it.
3. Start the Midnight proof server (127.0.0.1:6300) before the Midnight live run, and confirm which Midnight wallet funds it.
4. Confirm the scope choice in section 1: Ethereum and Midnight sign through the split committee below the envelope layer.

## 9. Phase 2 changes to this plan

- Install check: Codex and Opus approved `blake2 =0.10.6` as a dev-dependency only, and rejected `ureq`, `minicbor` and `bitcoin`. The code uses curl, `serde_json` and the hand-written encoders.
- Bitcoin: the funding wallet is on signet, so `TESTNET_BTC` defaults to `signet`. Set `TESTNET_BTC=testnet4` to use testnet4.
- Solana: the devnet RPC `requestAirdrop` now returns HTTP 410. The fallback still tries it, but in practice a person or the funding wallet must fund the committee address.
- Midnight fees: the committee does not depend on the funding wallet to pay DUST. `mn.mjs` starts the SDK's unshielded wallet from the committee public key only (`startWithPublicKey`) and sends every segment to the committee through the SDK's external-signer hook (`SignSegment`). The committee signs a DUST registration of its own NIGHT, which pays its own fee from DUST already generated, and then signs the transfer back. A test-local DUST wallet receives the generated DUST and holds no funds. This keeps the funding contract (`fund-<net>`, `return-address-<net>`), and every signature on the committee's NIGHT comes from the committee.
- Proof server: the Preview pins (`Moriarty qa/sherlock/target-pins.json`) list 9.0.0 and 9.0.1 as accepted for ledger 9.1.0.1. `mn.mjs` refuses any other `/version`.
- Seeds: `keys.local` holds one seed per network label (`btc-p2wpkh`, `btc-p2tr`, `sepolia`, `preprod`, `devnet`, `midnight`, `midnight-fee-a`, `midnight-fee-b`). Nonce material always comes from `OsRng`. `SchnorrSetup::new_with_rngs` separates the key draws from the nonce draws; `new(rng)` keeps its exact draws for the existing tests.
