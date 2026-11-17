# Split-line prototype: benchmarks and sizes

These are the measurements behind DESIGN §11.1, §11.3 and §11.5.

## Conditions

- Code: commit 78df8aa, crate `line-dealing`, `cargo bench --bench split` (criterion, 50 samples, 1 s warm-up, 5 s measurement per row).
- Machine: one Cortex-X925 core (CPU 19, `taskset -c 19`) with the `performance` governor at a delivered clock of about 4.0 GHz, rustc 1.99.1, k256 0.13.4, curve25519-dalek 4.1.3. The run held the exclusive heavy slot, so no other heavy job ran.
- Time measure: every CPU row is thread CPU time (`CLOCK_THREAD_CPUTIME_ID`, `benches/support/cputime.rs`). The 95% interval of every row is within ±0.5% of its median.
- Committee: `n = 9`, `t = 7`, `q = 6` and `n = 17`, `t = 12`, `q = 12`.
- Request: BIP340 P2TR, `K = 8`, `L = 2`, `G_max = 2` (30 halves, 15 bodies, 4 slots), single-user unless a row names actors. The Ed25519 rows use `K = 1`, `L = 1`; the ECDSA rows use `K = 3`, `L = 2` over the ideal slot session.

[BENCHMARKS.md](BENCHMARKS.md) gives the same rows with `n = 5` and `n = 33`, the latency simulation and the seald Sessions tables. The raw outputs are in [bench-results/](bench-results/).

Reproduce from `impl/`: `SPLIT_BENCH_N=9 taskset -c 19 cargo bench --offline --bench split -- --noplot` (and `SPLIT_BENCH_N=17`), then `python3 -I benches/criterion_table.py target/criterion`.

## Criterion medians

| Row | n = 9 median [95% CI] | n = 17 median [95% CI] |
|---|---:|---:|
| `actor_contribution_work` | 10.857 ms [10.851 ms, 10.863 ms] | 10.828 ms [10.826 ms, 10.835 ms] |
| `combine_bip340_actors0` | 398.8 µs [398.6 µs, 399.0 µs] | 411.3 µs [411.0 µs, 411.4 µs] |
| `combine_bip340_actors2` | 628.7 µs [628.5 µs, 629.0 µs] | 640.4 µs [640.1 µs, 640.6 µs] |
| `combine_ecdsa_actors0` | 565.3 µs [565.0 µs, 565.6 µs] | 824.0 µs [823.7 µs, 824.3 µs] |
| `combine_ecdsa_actors2` | 715.1 µs [714.8 µs, 715.3 µs] | 974.0 µs [973.8 µs, 974.4 µs] |
| `combine_ed25519_actors0` | 266.7 µs [266.6 µs, 266.8 µs] | 286.4 µs [286.3 µs, 286.5 µs] |
| `combine_ed25519_actors2` | 507.4 µs [507.2 µs, 507.5 µs] | 529.6 µs [529.3 µs, 529.7 µs] |
| `combine_failure_path` | 1.861 ms [1.860 ms, 1.861 ms] | 2.696 ms [2.695 ms, 2.696 ms] |
| `contrib_frame_open` | 911.5 µs [911.0 µs, 911.8 µs] | 1.063 ms [1.063 ms, 1.064 ms] |
| `contribution_seal` | 771.7 µs [771.4 µs, 771.9 µs] | 773.9 µs [773.6 µs, 774.3 µs] |
| `header_combine_open` | 225.5 µs [225.4 µs, 225.5 µs] | 369.9 µs [369.6 µs, 370.0 µs] |
| `header_partial` | 72.3 µs [72.3 µs, 72.3 µs] | 72.1 µs [72.1 µs, 72.1 µs] |
| `open_body_reconstruct_combine_bip340_actors0` | 848.4 µs [848.0 µs, 848.6 µs] | 1.006 ms [1.005 ms, 1.006 ms] |
| `open_body_reconstruct_combine_bip340_actors2` | 1.285 ms [1.284 ms, 1.286 ms] | 1.441 ms [1.440 ms, 1.441 ms] |
| `open_body_reconstruct_combine_ed25519_actors0` | 733.2 µs [733.0 µs, 733.4 µs] | 894.0 µs [893.7 µs, 894.2 µs] |
| `open_body_reconstruct_combine_ed25519_actors2` | 1.287 ms [1.286 ms, 1.287 ms] | 1.447 ms [1.446 ms, 1.448 ms] |
| `outer_share_check` | 272.8 µs [272.7 µs, 272.9 µs] | 277.7 µs [277.7 µs, 277.9 µs] |
| `own_signature_partials` | 197 ns [197 ns, 197 ns] | 197 ns [197 ns, 197 ns] |
| `pi_check` | 210.7 µs [210.6 µs, 210.8 µs] | 212.8 µs [212.7 µs, 212.9 µs] |
| `release_ticket_checks` | 83.5 µs [83.5 µs, 83.6 µs] | 83.4 µs [83.3 µs, 83.4 µs] |
| `slot_batch_verify` | 647.4 µs [647.3 µs, 647.6 µs] | 840.5 µs [840.2 µs, 840.7 µs] |
| `slot_deal_message` | 1.967 ms [1.967 ms, 1.968 ms] | 3.437 ms [3.436 ms, 3.438 ms] |
| `slot_fallback_verify` | 437.9 µs [437.8 µs, 438.1 µs] | 640.7 µs [640.6 µs, 640.9 µs] |
| `slot_lazy_eval` | 6.1 µs [6.1 µs, 6.1 µs] | 10.4 µs [10.3 µs, 10.4 µs] |
| `variant_key` | 286.3 µs [286.1 µs, 286.4 µs] | 430.2 µs [430.0 µs, 430.4 µs] |
| `vote_batch_verify_q_single_verify_strict` | 161.7 µs [161.6 µs, 161.7 µs] | 323.8 µs [323.6 µs, 324.0 µs] |
| `wallet_build_request` | 7.813 ms [7.811 ms, 7.816 ms] | 8.217 ms [8.214 ms, 8.220 ms] |

## Derived per-request figures (DESIGN §11.3)

| Figure | `n = 9` | `n = 17` | Rows |
|---|---|---|---|
| Header key | 0.298 ms | 0.442 ms | `header_partial` + `header_combine_open` |
| Request path, normal | 1.786 ms | 2.094 ms | `pi_check` + `outer_share_check` + header key + `release_ticket_checks` + `own_signature_partials` + `header_partial` (variant partial) + `open_body_reconstruct_combine_bip340/actors0` |
| Request path with one block's votes | 1.947 ms | 2.418 ms | the above + `vote_batch_verify_q_single_verify_strict` |
| Failure-path extra | 1.012 ms | 1.690 ms | `combine_failure_path` − `open_body_reconstruct_combine_bip340/actors0` |
| Slot replenishment, 4 slots | 5.558 ms | 11.919 ms | `(t/n)·slot_deal_message + (t − t/n)·slot_batch_verify` |
| Total | 7.34 to 7.51 ms | 14.01 to 14.34 ms | path + slots |
| Requests per second and core | 133.2 to 136.2 | 69.8 to 71.4 | 1000 / total |
| Combiner per request | 0.848 ms | 1.006 ms | `open_body_reconstruct_combine_bip340/actors0` |
| Combiner work per actor at release | 0.22 ms | 0.22 ms | (`.../actors2` − `.../actors0`) / 2 |

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

The largest `|S|`, initiator included, whose actor capsules fit beside the request. `tests/split_envelope.rs`, test `reference_and_real_serialization_budgets_cover_every_grid_and_committee`, builds and serializes the request at this count and checks that one more actor overflows the frame. The capsules carry the measured host fields of the `split_sizes` fixture variants (P2TR for BIP340, P2WPKH for ECDSA), and the TEE counts include the TEE header fields (`24 + 33 + 32 + 32 + 32·K` bytes). `design/enhancement/vectors/sizes.py` gives the same counts.

| Grid | `n = 9` non-TEE / TEE | `n = 17` non-TEE / TEE |
|---|---|---|
| BIP340 `K = 8`, `L = 2` | 6 / 5 | 6 / 4 |
| BIP340 `K = 8`, `L = 1` | 11 / 10 | 11 / 9 |
| BIP340 `K = 5`, `L = 2` | 14 / 12 | 13 / 11 |
| ECDSA `K = 3`, `L = 2` | 26 / 24 | 25 / 23 |
| ECDSA `K = 1`, `L = 1` | 33 / 31 | 32 / 30 |
| BIP340 `K = 1`, `L = 1` | 32 / 30 | 31 / 29 |
