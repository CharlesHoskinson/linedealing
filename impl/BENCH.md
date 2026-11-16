# Split-line prototype: benchmarks and sizes

These are the measurements behind DESIGN §11.1, §11.3 and §11.5.

## Conditions

- Code: commit ae1d20f (branch `split-proto`), crate `line-dealing`, `cargo bench --bench split` (criterion, 50 samples, 1 s warm-up, 5 s measurement per row).
- Machine: one Cortex-X925 core at 4.0 GHz (CPU 19, `taskset -c 19`), rustc 1.99.1, k256 0.13.4, curve25519-dalek 4.1.3. The run held the exclusive heavy slot, so no other heavy job ran.
- Committee: `n = 9`, `t = 7`, `q = 6` and `n = 17`, `t = 12`, `q = 12`.
- Request: BIP340 P2TR, `K = 8`, `L = 2`, `G_max = 2` (30 halves, 15 bodies, 4 slots), single-user unless a row names actors. The Ed25519 rows use `K = 1`, `L = 1`; the ECDSA rows use `K = 3`, `L = 2` over the ideal slot session.
- A second run of the same rows on commit 7953331 (before the slot-check change) gave medians up to 15% lower. Read each figure with that spread.

Reproduce from `impl/`: `cargo bench --offline --bench split`, then `python3 -I benches/criterion_table.py target/criterion`.

## Criterion medians

| Row | n = 9 median [95% CI] | n = 17 median [95% CI] |
|---|---:|---:|
| `actor_contribution_work` | 12.858 ms [12.816 ms, 12.943 ms] | 12.541 ms [12.337 ms, 12.744 ms] |
| `combine_bip340_actors0` | 486.7 µs [484.0 µs, 496.5 µs] | 494.6 µs [487.4 µs, 498.2 µs] |
| `combine_bip340_actors2` | 751.5 µs [746.9 µs, 762.1 µs] | 737.6 µs [718.8 µs, 744.8 µs] |
| `combine_ecdsa_actors0` | 709.7 µs [702.9 µs, 717.9 µs] | 994.1 µs [981.7 µs, 1.013 ms] |
| `combine_ecdsa_actors2` | 893.1 µs [879.4 µs, 898.0 µs] | 1.183 ms [1.168 ms, 1.211 ms] |
| `combine_ed25519_actors0` | 309.8 µs [307.7 µs, 313.9 µs] | 328.0 µs [324.4 µs, 330.7 µs] |
| `combine_ed25519_actors2` | 598.6 µs [591.3 µs, 605.3 µs] | 644.2 µs [629.6 µs, 652.0 µs] |
| `combine_failure_path` | 2.141 ms [2.125 ms, 2.170 ms] | 3.175 ms [3.121 ms, 3.260 ms] |
| `contrib_frame_open` | 1.045 ms [1.038 ms, 1.057 ms] | 1.221 ms [1.216 ms, 1.236 ms] |
| `contribution_seal` | 850.4 µs [846.3 µs, 856.4 µs] | 1.028 ms [1.006 ms, 1.045 ms] |
| `header_combine_open` | 270.8 µs [268.5 µs, 272.7 µs] | 450.7 µs [445.4 µs, 455.6 µs] |
| `header_partial` | 85.6 µs [85.0 µs, 86.4 µs] | 84.9 µs [83.6 µs, 85.6 µs] |
| `open_body_reconstruct_combine_bip340_actors0` | 1.056 ms [1.028 ms, 1.073 ms] | 1.181 ms [1.175 ms, 1.195 ms] |
| `open_body_reconstruct_combine_bip340_actors2` | 1.505 ms [1.497 ms, 1.524 ms] | 1.682 ms [1.665 ms, 1.698 ms] |
| `open_body_reconstruct_combine_ed25519_actors0` | 850.5 µs [844.0 µs, 858.7 µs] | 1.059 ms [1.008 ms, 1.130 ms] |
| `open_body_reconstruct_combine_ed25519_actors2` | 1.541 ms [1.531 ms, 1.553 ms] | 1.752 ms [1.741 ms, 1.767 ms] |
| `outer_share_check` | 329.1 µs [324.2 µs, 332.5 µs] | 319.1 µs [316.3 µs, 320.8 µs] |
| `own_signature_partials` | 237 ns [235 ns, 240 ns] | 233 ns [231 ns, 234 ns] |
| `pi_check` | 252.3 µs [250.5 µs, 257.4 µs] | 252.9 µs [247.7 µs, 255.6 µs] |
| `release_ticket_checks` | 101.6 µs [100.5 µs, 102.9 µs] | 99.8 µs [98.9 µs, 100.9 µs] |
| `slot_batch_verify` | 714.3 µs [703.6 µs, 721.5 µs] | 1.033 ms [1.020 ms, 1.038 ms] |
| `slot_deal_message` | 2.298 ms [2.216 ms, 2.416 ms] | 3.995 ms [3.865 ms, 4.185 ms] |
| `slot_fallback_verify` | 481.3 µs [474.4 µs, 487.1 µs] | 808.3 µs [801.5 µs, 819.0 µs] |
| `slot_lazy_eval` | 6.6 µs [6.5 µs, 6.6 µs] | 13.7 µs [13.6 µs, 13.9 µs] |
| `variant_key` | 342.4 µs [340.8 µs, 345.6 µs] | 516.8 µs [513.1 µs, 521.0 µs] |
| `vote_batch_verify_q_single_verify_strict` | 177.6 µs [176.3 µs, 178.5 µs] | 453.2 µs [448.0 µs, 462.9 µs] |
| `wallet_build_request` | 9.593 ms [9.558 ms, 9.681 ms] | 9.855 ms [9.749 ms, 10.007 ms] |

## Derived per-request figures (DESIGN §11.3)

| Figure | `n = 9` | `n = 17` | Rows |
|---|---|---|---|
| Header key | 0.356 ms | 0.536 ms | `header_partial` + `header_combine_open` |
| Request path, normal | 2.181 ms | 2.474 ms | `pi_check` + `outer_share_check` + header key + `release_ticket_checks` + `own_signature_partials` + `header_partial` (variant partial) + `open_body_reconstruct_combine_bip340/actors0` |
| Request path with one block's votes | 2.359 ms | 2.927 ms | the above + `vote_batch_verify_q_single_verify_strict` |
| Failure-path extra | 1.086 ms | 1.994 ms | `combine_failure_path` − `open_body_reconstruct_combine_bip340/actors0` |
| Slot replenishment, 4 slots | 6.232 ms | 14.483 ms | `(t/n)·slot_deal_message + (t − t/n)·slot_batch_verify` |
| Total | 8.41 to 8.59 ms | 16.96 to 17.41 ms | path + slots |
| Requests per second and core | 116 to 119 | 57 to 59 | 1000 / total |
| Combiner per request | 1.056 ms | 1.181 ms | `open_body_reconstruct_combine_bip340/actors0` |
| Combiner work per actor at release | 0.22 ms | 0.25 ms | (`.../actors2` − `.../actors0`) / 2 |

## Serialized sizes (`cargo run --release --bin split_sizes`)

All values are bytes from serialized prototype objects; frame capacity is 16,384 bytes.
Layout, header, bodies and capsules include AEAD tags. Layout is 64 bytes. Actor HPKE capsules are 385 bytes. Outer includes the public proof. Actor growth uses separately built one- and two-actor requests; first growth includes the shared contribution keys.

| n | Suite | Grid | Frame used | Outer + proof | Layout | Header | Bodies | Capsules | First other actor | Next other actor | CONTRIB frame used | Embedded actor |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 9 | BIP340 | K=8, L=2 | 11422 | 748 | 64 | 4700 | 1680 | 4134 | 1285 | 790 | 2818 | 1711 |
| 9 | ECDSA (embedded actors) | K=3, L=2 | 2887 | 748 | 64 | 446 | 336 | 1197 | 594 | 495 | 1462 | 355 |
| 9 | Ed25519 | K=1, L=1 | 1653 | 748 | 64 | 379 | 80 | 286 | 492 | 459 | 1204 | 97 |
| 17 | BIP340 | K=8, L=2 | 11843 | 1169 | 64 | 4700 | 1680 | 4134 | 1285 | 790 | 3239 | 1711 |
| 17 | ECDSA (embedded actors) | K=3, L=2 | 3308 | 1169 | 64 | 446 | 336 | 1197 | 594 | 495 | 1883 | 355 |
| 17 | Ed25519 | K=1, L=1 | 2074 | 1169 | 64 | 379 | 80 | 286 | 492 | 459 | 1625 | 97 |

Board slot posts include dealer context, ephemeral key and proof. Four slots are one batch per dealer; all t dealers are counted.

| n | t | One Schnorr slot | Four Schnorr slots |
|---:|---:|---:|---:|
| 9 | 7 | 8351 | 30317 |
| 17 | 12 | 24612 | 92580 |

## Signing sets per frame

The largest `|S|`, initiator included, whose actor capsules fit beside the request. `tests/split_envelope.rs`, test `reference_and_real_serialization_budgets_cover_every_grid_and_committee`, builds and serializes the request at this count and checks that one more actor overflows the frame.

| Grid | `n = 9` non-TEE / TEE | `n = 17` non-TEE / TEE |
|---|---|---|
| BIP340 `K = 8`, `L = 2` | 7 / 5 | 6 / 5 |
| BIP340 `K = 8`, `L = 1` | 10 / 9 | 10 / 8 |
| BIP340 `K = 5`, `L = 2` | 14 / 12 | 13 / 11 |
| ECDSA `K = 3`, `L = 2` | 26 / 24 | 25 / 23 |
| ECDSA `K = 1`, `L = 1` | 33 / 30 | 32 / 29 |
| BIP340 `K = 1`, `L = 1` | 32 / 29 | 31 / 29 |
