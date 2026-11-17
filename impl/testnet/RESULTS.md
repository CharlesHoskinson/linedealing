# Testnet end to end: results (LOOP item 34)

Every signature below comes from the split-line committee in `impl/` (9 nodes, threshold 7, one actor leaf). No single local key signs any spend. Plan and design: `PLAN.md`. Code: `impl/tests/testnet.rs`, `impl/tests/testnet/`, `impl/testnet/midnight/mn.mjs`.

## What each network exercises

| Network | Scheme | Committee path |
|---|---|---|
| Bitcoin signet (testnet4 with `TESTNET_BTC=testnet4`) | P2WPKH, ECDSA, BIP143 | full split request: envelope, board, release, `EcdsaRequest::combine` |
| Bitcoin signet | P2TR key path, BIP340, BIP86 tweak | full split request: envelope, board, release, `combine_admitted` |
| Solana devnet | Ed25519 system transfer | full split request (suite 3 host message) |
| Cardano preprod | Ed25519 enterprise address, Shelley-format transaction | full split request (suite 3, message = blake2b-256 of the body) |
| Ethereum Sepolia | EIP-1559, ECDSA | split ECDSA slot algebra (`Slot::ideal`, contributions, partials, combine) |
| Midnight Preview | unshielded NIGHT, BIP340 over SHA-256(`signatureData`) | split Schnorr slot algebra (`InitiatorNonce`, `Node::release`, `schnorr::combine`) |

Gap, stated as the lead decided (marked for owner confirmation): Ethereum and Midnight exercise threshold signing with the same committee and slots, not the envelope. The envelope's host parser accepts only Bitcoin transactions, and adding a host-hash variant is a protocol change that is out of scope here.

What stays simulated in every row: all parties run in one process; the committee and actor shares come from the fixtures' trusted dealer; ECDSA presignatures come from `Slot::ideal` (ideal F_presig/F_mul); the board is the in-memory `BoardAdapter`.

Midnight design (not yet run live): the committee is its own Midnight wallet. `mn.mjs` starts the SDK's unshielded wallet from the committee public key only (`startWithPublicKey`) and routes every segment signature to the committee through the SDK's external-signer hook (`SignSegment`). The committee first signs a DUST registration of its own NIGHT, then signs the transfer back. A test-local DUST wallet receives the generated DUST and pays the fees; it holds no funds. Before any proof, `mn.mjs` checks the Preview genesis hash and that the proof server `/version` is one the Preview pins accept for ledger 9.1.0.1 (9.0.0 or 9.0.1; the running container is 9.0.1). Before each broadcast it runs the facade's full `validateTransaction` (balancing, signatures, limits) on the proven transaction, so a proof server or ledger mismatch stops before submit. That proof is the dry run the lead asked for; it has not run yet, because it needs the committee address funded.

## Offline checks (`cargo test --test testnet`, always run)

| Check | Independent reference |
|---|---|
| bech32/bech32m encode and decode, valid and invalid addresses | BIP350 test vectors |
| P2TR output key from the split `output_key` | BIP86 `m/86'/0'/0'/0/0` vector |
| hash160 program | BIP173 (generator key) |
| base58, base64, BLAKE2b, DER | Bitcoin Core base58 vectors, RFC 4648, RFC 7693, k256 `to_der` |
| EIP-1559 signed encoding, hash, sender recovery | a confirmed Sepolia transfer (block 0xb94eef), re-encoded byte for byte |
| EIP-55 checksum | EIP-55 test cases |
| Cardano body hash and witness rule | a confirmed preprod transaction (`61ed6bc0…07d2`): blake2b-256 of the body is the txid, and its vkey witness verifies over it |
| Cardano enterprise address | CIP-19 type-6 testnet vector |
| Committee P2TR spend | sighash recomputed by the builder, BIP340 verified against the key parsed from the address |
| Committee P2WPKH spend | BIP143 sighash, low-s, k256 verification against the compressed key |
| Committee EIP-1559 transfer | `ecrecover` returns the committee address; low-s |
| Committee Cardano transaction | body cut from the signed CBOR, hashed, witness verified (`verify_strict`) |
| Committee Solana transfer | message layout, `verify_strict` over the message bytes |
| Committee Midnight signature | k256 `Verifier` (SHA-256 then BIP340); with `TESTNET_TOOLS=1`, ledger-v9 `verifySignature` accepts it, and `mn.mjs` derives the pinned Moriarty Preview address from its pinned public key |
| Cardano body txid | `cardano-cli` 11.2.3.0 printed `3ebf92e2…ced6` for a committee body; the always-run test asserts the same txid |
| With `TESTNET_TOOLS=1`: Bitcoin consensus | Bitcoin Core 32.1 regtest: the committee spends a mined coinbase; `testmempoolaccept` allows it (P2WPKH and P2TR), `decoderawtransaction` gives the same vsize, and the spend confirms in a block |
| With `TESTNET_TOOLS=1`: Cardano decoder | `cardano-cli latest transaction txid` reads the committee-signed CBOR as a Conway transaction and returns the signed txid |
| With `TESTNET_TOOLS=1`: Solana decoder | `solana decode-transaction` reports the committee signature as `(pass)`; devnet `simulateTransaction` with `sigVerify` rejects only the unfunded fee payer |
| Key stability and nonce freshness | same seed gives the same key; two signatures of the same message have different nonces |

## Committee addresses (live seeds in the git-ignored `keys.local`)

| Network | Address |
|---|---|
| Bitcoin P2WPKH | `tb1qk33u6alk0mykev0ugnnwz4nk80g2ldnj8fd9x5` |
| Bitcoin P2TR | `tb1p9vsp5mhlj6vna0wrevklj46qkjelqgnxl3z9v56vmk96s7s36fjsjqffs2` |
| Ethereum Sepolia | `0xA0670b2176BF0e00e91e877D5a3452686f790319` |
| Cardano preprod | `addr_test1vphq6jd50l73ra9720vgwc2mhwf46v56wpz9ym8ftenqjpqc3csca` |
| Solana devnet | `CZssFP8WftbW4RcbB4vUnUyiRdoPAAgBX8YfE7595tRp` |
| Midnight Preview | `mn_addr_preview1ndxt4l8spegcxxthasnpxpns23kaxzh078qc2y6uhqxx5c022x0sf4ztm2` |

## Live status (2026-11-16)

| Network | State |
|---|---|
| Bitcoin signet (P2WPKH, P2TR) | passed 2026-11-16 06:09 and 06:20 UTC (rows below) |
| Ethereum Sepolia | passed 2026-11-16 06:21 UTC (row below) |
| Cardano preprod | passed 2026-11-16 06:22 UTC (row below) |
| Solana devnet | passed 2026-11-16 06:23 UTC (row below) |
| Midnight Preview | passed 2026-11-16 03:50 UTC (rows below) |

The owner can also fund the committee addresses above directly; each live test finds existing funds and spends them back to the funding wallet.

## Live run blocks (2026-11-16)

Each spend is signed by the split-line committee and sends the funds back to the funding wallet. Heights checked on mempool.space, publicnode, Koios, Solana devnet RPC and the Midnight indexer.

| Network | Funding tx block | Spend tx block | Spend status |
|---|---|---|---|
| Bitcoin signet P2WPKH | 331086 | 331087 | confirmed |
| Bitcoin signet P2TR | 331088 | 331089 | confirmed |
| Ethereum Sepolia | 12145511 | 12145512 | receipt status 0x1 |
| Cardano preprod | 5418201 | 5418202 | confirmed (Koios `tx_status`) |
| Solana devnet | slot 522816018 | slot 522816069 | finalized, no error |
| Midnight Preview (registration, transfer) | 130797 | 130887, 130891 | SUCCESS |

## Midnight Preview run notes (2026-11-16)

- Funding: `fund-midnight-preview` sent 500000000 raw NIGHT to the committee in block 130797 (tx `c3ecfd1967dffc5b3911b47414b4dcc7f0aaf5d36afb19f71b075f93903d53b4`). The script still exited 1 with `submit did not return a transaction id`: in `bin/lib/midnight-fund.mjs`, `transactionHash` is not a function on the finalized transaction. The funding id above comes from the indexer.
- DUST registration: block 130887, status SUCCESS, signed by the committee (split Schnorr slots, BIP340 over SHA-256(signatureData)). The registration fee comes from the NIGHT UTXO's registration allowance.
- Transfer: all 500000000 raw NIGHT back to the funding wallet, block 130891, status SUCCESS, signed by the committee. DUST paid the fee.
- Earlier failures and fixes:
  - Run 1 failed with ledger custom error 196, `InvalidError::DustDoubleSpend`. The funding wallet's send spent DUST that a concurrent self-send from the same wallet (`b956020f…69c5`, block 130544) had already spent. The test now retries funding on a later `need-funds` event, at most 5 times and at least 180 s apart.
  - Run 2 failed in the SDK's own pre-submit check. `validateTransaction` checks against `LedgerState.blank`, which has no generation record for the NIGHT UTXO, so a registration always reads "0 available" of its fee allowance. The registration is now checked without balancing; signatures and limits are still checked, and the node checks balancing on submit.
- `submitTransaction` returns a 66-hex segment identifier. `mn.mjs` now asks the indexer for the 64-hex transaction hash, and the test records that hash with its explorer link.

## Live runs

Run one network with `TESTNET_E2E=1 cargo test --test testnet -- --ignored live_<network>` (`live_bitcoin_p2wpkh`, `live_bitcoin_p2tr`, `live_sepolia`, `live_cardano_preprod`, `live_solana_devnet`, `live_midnight_preview`). Each test appends one row below when the spend is confirmed.

| Network | Scheme | Path | Committee address | Funding tx | Spend tx | UTC |
|---|---|---|---|---|---|---|
| Midnight Preview | DUST registration of the committee NIGHT, BIP340 | split Schnorr slots, no envelope | `mn_addr_preview1ndxt4l8spegcxxthasnpxpns23kaxzh078qc2y6uhqxx5c022x0sf4ztm2` | [`c3ecfd19…53b4`](https://midnight-preview.subscan.io/tx/c3ecfd1967dffc5b3911b47414b4dcc7f0aaf5d36afb19f71b075f93903d53b4) | [`8ef47232392e08b60e16960eb189a4b14cd8c64fe4240d3111c17935ae5f97ea`](https://midnight-preview.subscan.io/tx/8ef47232392e08b60e16960eb189a4b14cd8c64fe4240d3111c17935ae5f97ea) | 2026-11-16 03:50 |
| Midnight Preview | unshielded NIGHT transfer, BIP340 over SHA-256(signatureData) | split Schnorr slots, no envelope | `mn_addr_preview1ndxt4l8spegcxxthasnpxpns23kaxzh078qc2y6uhqxx5c022x0sf4ztm2` | [`c3ecfd19…53b4`](https://midnight-preview.subscan.io/tx/c3ecfd1967dffc5b3911b47414b4dcc7f0aaf5d36afb19f71b075f93903d53b4) | [`33edbd9f9ad802c09c1341df9e55e4123fe1fae14ccd748846039fd2fc4a6352`](https://midnight-preview.subscan.io/tx/33edbd9f9ad802c09c1341df9e55e4123fe1fae14ccd748846039fd2fc4a6352) | 2026-11-16 03:50 |
| Bitcoin signet | P2WPKH ECDSA | split envelope | `tb1qk33u6alk0mykev0ugnnwz4nk80g2ldnj8fd9x5` | `e0c99c9a9b1f7e0ad0865fd6373be83e83ec2421c2791749fe4fb988dc690493` | [`79d574fe8b4623ceb9bca48e32e1df0d37dd9668441721c60e28b39f99c67b59`](https://mempool.space/signet/tx/79d574fe8b4623ceb9bca48e32e1df0d37dd9668441721c60e28b39f99c67b59) | 2026-11-16 06:09 |
| Bitcoin signet | P2TR BIP340 (BIP86 key path) | split envelope | `tb1p9vsp5mhlj6vna0wrevklj46qkjelqgnxl3z9v56vmk96s7s36fjsjqffs2` | `4640b44f4170e9b1c7b5c6c5e69e3afdcef6a3c2406d15800a12e4a85c243e70` | [`7d7eb102955836ddfb066fac2fb328cb054c6ea003b730da698cd1e9d1eacf21`](https://mempool.space/signet/tx/7d7eb102955836ddfb066fac2fb328cb054c6ea003b730da698cd1e9d1eacf21) | 2026-11-16 06:20 |
| Ethereum Sepolia | EIP-1559 ECDSA | split ECDSA slots, no envelope | `0xA0670b2176BF0e00e91e877D5a3452686f790319` | `0x8c65474c55bf05fe89d16dc305041dd91d1d6f1e2b897c26537ce0ef1856dc08` | [`0xae54d21ce2b91cae8e4170036f18e0f0999c6139f71829480720b808c3a534cb`](https://sepolia.etherscan.io/tx/0xae54d21ce2b91cae8e4170036f18e0f0999c6139f71829480720b808c3a534cb) | 2026-11-16 06:21 |
| Cardano preprod | Ed25519 enterprise address, Shelley-format tx | split envelope | `addr_test1vphq6jd50l73ra9720vgwc2mhwf46v56wpz9ym8ftenqjpqc3csca` | `d782b4849723aedaccb5c947471cd152dc9402793733f38ff5526efb3910bb3a` | [`3a2cdfc001eacc3dfb99fb6e1f8a741b8b4e4b4c51ad8e6ea14a4e699129007b`](https://preprod.cardanoscan.io/transaction/3a2cdfc001eacc3dfb99fb6e1f8a741b8b4e4b4c51ad8e6ea14a4e699129007b) | 2026-11-16 06:22 |
| Solana devnet | Ed25519 system transfer | split envelope | `CZssFP8WftbW4RcbB4vUnUyiRdoPAAgBX8YfE7595tRp` | `5QCG9KXGk1ebHDxYv48rof7qjjvJHM41nAwg6s7B5y8cpaayNkAD1z7TucChiPhSQeGSYnP2fKmEKk1uG6BeKj5H` | [`5RyGLuAZcoR62QoLaaSu8pSFNrERPhCStpGwWJ1cJWYh4TKk9boBMzn43dGAPAFbqLiehXdWmw1zXB24AgrFzePr`](https://explorer.solana.com/tx/5RyGLuAZcoR62QoLaaSu8pSFNrERPhCStpGwWJ1cJWYh4TKk9boBMzn43dGAPAFbqLiehXdWmw1zXB24AgrFzePr?cluster=devnet) | 2026-11-16 06:23 |
