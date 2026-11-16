# Measurements

Measured on 2026-11-14 on an NVIDIA RTX Spark N1X laptop: aarch64, 20 cores (Cortex-X925 and Cortex-A725), rustc and Cargo 1.99.1, k256 0.13.4. Every timing run went through `heavy-slot --exclusive`, which reserves the host's CPU slots; a GPU transcription job that uses one CPU core ran at the same time.

## Commands and evidence

These commands ran from this directory:

```sh
export CARGO_TARGET_DIR=target
cargo fmt
cargo clippy --offline -j 4 --all-targets -- -D warnings > clippy-output.txt 2>&1
cargo test --offline -j 4 > test-output.txt 2>&1
LD_BENCH_N=9 cargo bench --offline -j 4 --bench protocol -- --noplot > criterion-n9.txt 2>&1
bash run-simulation-matrix.sh > simulation-results.txt 2>&1
cargo bench --offline -j 4 --bench protocol -- --test > criterion-smoke.txt 2>&1
```

The simulation script builds the release binary offline and runs all combinations of these settings:

| Parameter | Values |
|---|---|
| Committee | n=9, f=2, quorum q=6 |
| Threshold | 3, 7 |
| Suite | ECDSA, BIP340, Ed25519 |
| Mode | open, sealed with K=8 |
| Requests | 16 concurrent after preparation |
| One-way link delay | 0, 25, 50 ms |
| Maximum batch size | 1, 16 |
| Board service interval | 1 ms |
| Seed | 42 |

All 72 simulation runs completed all 16 requests: 1,152 reconstructed and verified signatures. Raw output is in [simulation-results.txt](simulation-results.txt). [simulation-results.csv](simulation-results.csv) contains all measurements.

The test suite passes 91 tests with zero failures (one timing test is ignored by the normal test command); clippy with `-D warnings` and `cargo fmt --check` are clean. All tables below were measured on the final wire format (196-byte authorship proof, `H_ct`, suite-3 subgroup checks) with quorum q = ⌈(n + f + 1)/2⌉, under `heavy-slot --exclusive`, on 2026-11-14.

## Nine-node microbenchmarks

Values are Criterion's reported central estimates in microseconds. Each case has ten samples, a 100 ms warmup, and a one-second measurement target. These operations run on one thread.

| Suite | Mode | n | t | Owner deal+encrypt | Step A | Decrypt | Partial | Verify partial | Combine |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ecdsa | open | 9 | 3 | 1,146.4 | 504.6 | 310.8 | 203.3 | 199.8 | 103.8 |
| ecdsa | sealed-k8 | 9 | 3 | 4,386.7 | 1,514.3 | 1,004.7 | 115.0 | 114.7 | 104.7 |
| bip340 | open | 9 | 3 | 1,440.7 | 571.3 | 429.6 | 286.5 | 284.1 | 98.4 |
| bip340 | sealed-k8 | 9 | 3 | 3,577.7 | 1,623.4 | 1,026.0 | 112.4 | 111.4 | 97.7 |
| ecdsa | open | 9 | 7 | 1,446.7 | 593.7 | 560.0 | 418.4 | 418.2 | 144.5 |
| ecdsa | sealed-k8 | 9 | 7 | 5,587.3 | 2,035.0 | 2,009.9 | 223.3 | 223.8 | 145.8 |
| bip340 | open | 9 | 7 | 1,914.5 | 715.4 | 811.2 | 614.4 | 613.5 | 141.2 |
| bip340 | sealed-k8 | 9 | 7 | 4,897.9 | 2,193.2 | 2,071.6 | 227.2 | 225.8 | 143.7 |
| ed25519 | open | 9 | 3 | 2,904.1 | 1,810.4 | 775.1 | 230.2 | 231.2 | 120.6 |
| ed25519 | sealed-k8 | 9 | 3 | 7,231.9 | 4,258.9 | 1,789.2 | 93.2 | 93.7 | 121.4 |
| ed25519 | open | 9 | 7 | 3,896.3 | 2,769.4 | 1,356.3 | 514.0 | 508.4 | 163.8 |
| ed25519 | sealed-k8 | 9 | 7 | 9,708.5 | 7,554.3 | 3,364.7 | 184.6 | 185.2 | 164.9 |

The owner measurement excludes preparation of transaction fixtures and sealed wallet signatures. Step A includes public validation. Bitcoin sealed validation reconstructs the variants and sighashes. Decryption includes share checks. Partial creation includes its local verification. Combination includes independent final signature verification.

[criterion-n9.txt](criterion-n9.txt) retains confidence intervals and sample diagnostics. Committee sizes 16, 64 and 256 are timed in the next section.

## Larger committees: n = 16, 64, 256

Criterion central estimates in microseconds, one thread, same settings as the nine-node table (ten samples, 100 ms warm-up, one-second target), with f = (n - 1)/3 and t = f + 1 or t = n - f. Run under `heavy-slot --exclusive`:

    for n in 16 64 256; do LD_BENCH_N=$n cargo bench --offline -j 4 --bench protocol -- --noplot > criterion-n$n.txt; done

Raw output with confidence intervals: [criterion-n16.txt](criterion-n16.txt), [criterion-n64.txt](criterion-n64.txt), [criterion-n256.txt](criterion-n256.txt).

| Suite | Mode | n | t | Owner deal+encrypt | Step A | Decrypt | Partial | Verify partial | Combine |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ecdsa | open | 16 | 6 | 1,821.1 | 620.4 | 517.9 | 379.8 | 376.7 | 138.4 |
| ecdsa | sealed-k8 | 16 | 6 | 6,420.9 | 2,006.2 | 1,812.7 | 203.7 | 203.4 | 137.9 |
| bip340 | open | 16 | 6 | 2,317.4 | 747.9 | 746.2 | 559.5 | 554.2 | 134.9 |
| bip340 | sealed-k8 | 16 | 6 | 5,749.8 | 2,209.0 | 1,872.8 | 203.1 | 202.8 | 136.0 |
| ecdsa | open | 16 | 11 | 2,242.9 | 761.1 | 869.0 | 678.2 | 668.2 | 198.5 |
| ecdsa | sealed-k8 | 16 | 11 | 8,200.9 | 2,783.6 | 3,245.4 | 353.3 | 348.1 | 198.3 |
| bip340 | open | 16 | 11 | 3,017.3 | 953.4 | 1,268.0 | 992.7 | 1,000.1 | 193.7 |
| bip340 | sealed-k8 | 16 | 11 | 7,448.7 | 2,896.0 | 3,234.1 | 357.6 | 348.6 | 195.7 |
| ed25519 | open | 16 | 6 | 4,974.7 | 2,843.5 | 1,287.3 | 453.6 | 455.4 | 152.6 |
| ed25519 | sealed-k8 | 16 | 6 | 12,420.0 | 7,292.7 | 3,121.4 | 167.2 | 167.2 | 151.6 |
| ed25519 | open | 16 | 11 | 6,186.6 | 4,034.5 | 2,048.2 | 818.1 | 809.6 | 212.9 |
| ed25519 | sealed-k8 | 16 | 11 | 15,642.0 | 11,455.0 | 5,219.2 | 291.9 | 283.6 | 216.7 |
| ecdsa | open | 64 | 22 | 5,958.4 | 1,307.3 | 1,596.4 | 1,298.8 | 1,294.8 | 340.6 |
| ecdsa | sealed-k8 | 64 | 22 | 18,796.0 | 4,721.2 | 6,103.6 | 674.7 | 667.3 | 336.4 |
| bip340 | open | 64 | 22 | 7,856.7 | 1,652.5 | 2,350.6 | 1,940.5 | 1,922.8 | 333.7 |
| bip340 | sealed-k8 | 64 | 22 | 17,954.0 | 4,956.6 | 6,168.8 | 669.6 | 665.9 | 335.8 |
| ecdsa | open | 64 | 43 | 7,871.7 | 1,908.3 | 3,030.0 | 2,549.6 | 2,531.5 | 643.4 |
| ecdsa | sealed-k8 | 64 | 43 | 26,725.0 | 8,033.6 | 11,819.0 | 1,274.6 | 1,279.1 | 646.7 |
| bip340 | open | 64 | 43 | 10,811.0 | 2,547.6 | 4,503.0 | 3,761.4 | 3,805.7 | 644.0 |
| bip340 | sealed-k8 | 64 | 43 | 25,676.0 | 8,527.9 | 13,085.0 | 1,717.2 | 1,666.7 | 783.4 |
| ed25519 | open | 64 | 22 | 18,722.0 | 8,396.6 | 4,603.8 | 2,094.2 | 2,088.2 | 450.4 |
| ed25519 | sealed-k8 | 64 | 22 | 54,446.0 | 28,679.0 | 13,098.0 | 720.8 | 725.1 | 501.0 |
| ed25519 | open | 64 | 43 | 31,719.0 | 17,732.0 | 9,107.5 | 4,067.9 | 3,296.6 | 838.0 |
| ed25519 | sealed-k8 | 64 | 43 | 61,030.0 | 40,639.0 | 18,169.0 | 1,074.9 | 1,068.3 | 849.8 |
| ecdsa | open | 256 | 86 | 24,274.0 | 4,082.8 | 5,956.9 | 5,151.6 | 5,125.2 | 1,475.9 |
| ecdsa | sealed-k8 | 256 | 86 | 74,085.0 | 15,570.0 | 23,481.0 | 2,544.8 | 2,565.6 | 1,504.0 |
| bip340 | open | 256 | 86 | 32,172.0 | 5,360.9 | 9,934.2 | 8,058.9 | 9,345.6 | 1,837.2 |
| bip340 | sealed-k8 | 256 | 86 | 90,930.0 | 19,373.0 | 29,262.0 | 2,628.5 | 2,628.1 | 1,490.4 |
| ecdsa | open | 256 | 171 | 33,098.0 | 6,569.8 | 11,737.0 | 9,964.0 | 10,143.0 | 3,801.7 |
| ecdsa | sealed-k8 | 256 | 171 | 111,690.0 | 28,643.0 | 46,466.0 | 5,032.1 | 5,044.8 | 3,803.5 |
| bip340 | open | 256 | 171 | 46,198.0 | 8,971.0 | 17,538.0 | 15,072.0 | 15,050.0 | 3,883.7 |
| bip340 | sealed-k8 | 256 | 171 | 113,030.0 | 29,066.0 | 47,257.0 | 5,024.6 | 5,163.6 | 3,843.1 |
| ed25519 | open | 256 | 86 | 74,365.0 | 28,631.0 | 13,517.0 | 6,216.4 | 6,228.3 | 2,333.7 |
| ed25519 | sealed-k8 | 256 | 86 | 185,120.0 | 82,183.0 | 35,230.0 | 2,057.6 | 2,091.8 | 2,339.2 |
| ed25519 | open | 256 | 171 | 98,991.0 | 48,992.0 | 26,162.0 | 12,280.0 | 12,520.0 | 7,315.9 |
| ed25519 | sealed-k8 | 256 | 171 | 257,930.0 | 154,980.0 | 69,676.0 | 4,130.4 | 4,179.3 | 7,361.3 |

Step A and decryption grow linearly in n and t, as SCHEME section 7 predicts. The owner's work at n = 256 is 23 to 32 ms for open ECDSA and up to 244 ms for sealed Ed25519 with eight variants. `partial` and `verify_partial` also grow linearly in t, although a partial needs only constant work once the Feldman evaluations are cached; this is the main optimization left in the prototype.

## ECDSA open simulation

Latency includes owner preparation, queueing, board exchanges, cryptographic work, and verified reconstruction. It excludes target-chain execution. Each row is one finite run, not a sustained capacity measurement.

| t | Link ms | Batch size | p50 ms | p99 ms | Requests/s |
|---:|---:|---:|---:|---:|---:|
| 3 | 0 | 1 | 676.5 | 851.8 | 18.8 |
| 3 | 0 | 16 | 104.8 | 115.7 | 132.6 |
| 3 | 25 | 1 | 810.7 | 979.7 | 16.3 |
| 3 | 25 | 16 | 327.1 | 335.6 | 46.4 |
| 3 | 50 | 1 | 875.0 | 1034.6 | 15.5 |
| 3 | 50 | 16 | 498.4 | 517.7 | 30.6 |
| 7 | 0 | 1 | 695.7 | 851.8 | 18.7 |
| 7 | 0 | 16 | 176.4 | 199.2 | 76.7 |
| 7 | 25 | 1 | 820.0 | 989.2 | 16.1 |
| 7 | 25 | 16 | 369.7 | 381.0 | 41.0 |
| 7 | 50 | 1 | 822.5 | 991.9 | 16.1 |
| 7 | 50 | 16 | 559.6 | 571.7 | 27.5 |

## All suites at zero injected latency

These runs use batch size 16 and the same one-millisecond board interval.

| Suite | Mode | t | p50 ms | p99 ms | Requests/s |
|---|---|---:|---:|---:|---:|
| ECDSA | open | 3 | 104.8 | 115.7 | 132.6 |
| ECDSA | open | 7 | 176.4 | 199.2 | 76.7 |
| ECDSA | sealed-k8 | 3 | 184.6 | 239.4 | 65.8 |
| ECDSA | sealed-k8 | 7 | 270.3 | 335.9 | 46.7 |
| BIP340 | open | 3 | 118.2 | 141.7 | 108.0 |
| BIP340 | open | 7 | 205.3 | 218.7 | 69.3 |
| BIP340 | sealed-k8 | 3 | 179.3 | 236.1 | 66.8 |
| BIP340 | sealed-k8 | 7 | 265.1 | 317.2 | 49.4 |
| Ed25519 | open | 3 | 211.7 | 239.0 | 65.4 |
| Ed25519 | open | 7 | 326.1 | 360.5 | 43.1 |
| Ed25519 | sealed-k8 | 3 | 317.5 | 389.2 | 40.7 |
| Ed25519 | sealed-k8 | 7 | 579.8 | 684.5 | 23.2 |

The simulator uses nine worker threads and standard channels. Every worker processes the owner message and decrypts its own shares. The sequencer verifies each signed post and each partial individually. Batching groups transport messages and board commits. It does not aggregate cryptographic verification.

Bitcoin fixtures use deterministic builder transactions and real sighashes. Ed25519 fixtures exercise the signature protocol without a Solana transaction adapter. The sequencer replaces BFT consensus. Chain finality, disk fsync costs, and physical share erasure are absent.

Per-request clocks start before serial owner preparation. Dispatch begins after every request is prepared. Thus earlier requests include more setup queueing. Throughput starts before all preparation and ends at the last verified signature. Late posts are drained afterward. Percentiles use nearest-rank samples.

## Throughput model

The honest workload emits 36 posts per open request and 27 per sealed request. All nine nodes post in every phase. Open mode has four board exchanges, and sealed mode has three.

For one-way delay L, network transit alone requires at least 8L in open mode or 6L in sealed mode. CPU time, batch formation, and queues add latency.

A service-only sustained-throughput estimate is:

```text
requests/s = mean_posts_per_batch / (board_interval_seconds * posts_per_request)
```

At a one-millisecond interval, single-post batches give 27.8 open or 37.0 sealed requests/s before cryptographic costs. Full batches of 16 give 444.4 or 592.6 respectively. These are derived service bounds, not measured throughput. They exclude post verification, owner work, link delay, and incomplete batches. Finite-run rates above include preparation but exclude the final drain of late posts.

The measured request rate corresponds to one reconstructed transaction signature per request. It is not chain TPS. No Bitcoin, Ethereum, or Solana node acceptance or execution measurement was run.

## Hand-timed per-request CPU cost (bench9) (open ECDSA, one slot)

**Committee.** n = 9, f = 2, with quorum q = ⌈(n + f + 1)/2⌉ = 6 for ACKs, height reports and PREVOTEs (any two quorums share at least f + 1 = 3 nodes). n = 7 and n = 10 (n = 3f + 1, q = 2f + 1) are shown for comparison. Final wire format: the 196-byte authorship proof (SCHEME C3), `H_ct`, and the Step A checks of SCHEME §3.4.

**Method.** `tests/bench9.rs`, release build, one thread, timed loop per step after one warm-up call, under `heavy-slot --exclusive`. A GPU transcription job (one CPU core) ran on the host at the same time. Raw output: [bench9-output.txt](bench9-output.txt). Per-node CPU per request = Step A + decrypt + lock digest + partial + one signature check per board post (3q quorum posts + t partials); the combiner's work is added once.

    CARGO_TARGET_DIR=target heavy-slot --exclusive --mem 8G --name mpc-bench9 -- \
      cargo test --offline --release --test bench9 -- --ignored --nocapture

| Committee | q | t | Owner message (bytes) | Post checks | Per-node CPU (µs) | Combiner (µs) | Requests/s per core |
|---|---:|---:|---:|---:|---:|---:|---:|
| n=7, f=2 | 5 | 3 | 1,333 | 18 | 2,173 | 105 | 439 |
| n=7, f=2 | 5 | 5 | 1,465 | 20 | 2,625 | 127 | 363 |
| **n=9, f=2** | **6** | **3** | **1,461** | **21** | **2,331** | **106** | **410** |
| **n=9, f=2** | **6** | **7** | **1,725** | **25** | **3,320** | **151** | **288** |
| n=10, f=3 | 7 | 4 | 1,591 | 25 | 2,734 | 117 | 351 |
| n=10, f=3 | 7 | 7 | 1,789 | 28 | 3,424 | 148 | 280 |

The message sizes equal the SCHEME §7 and `costs.py` figures for the same parameters.

### Throughput estimate for a 9-node committee

- **Per core:** 410 requests per second at t = 3, 288 at t = 7.
- **Per node:** requests are independent, so the work spreads across cores: about 5,200 requests per second at t = 3 and about 3,700 at t = 7 on a 16-core node at 80% use (arithmetic projection, not measured).
- **Board-post checks are about half of the per-node CPU** (21 × 54 µs of 2,331 µs at t = 3). A board that certifies posts in batches removes most of that cost.
- **The partial is slower than it needs to be.** `partial` and `verify_partial` recompute Feldman evaluations on every call; caching them after Step A should cut both to a few microseconds.

**The bound in practice is the board and the target chain, not the committee's CPU.** Each request needs three board commits after its trigger, so throughput follows the board's ordering rate and block size, and latency is about three commit times (1.5 s at an assumed 0.5 s per commit).
