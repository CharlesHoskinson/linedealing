Implemented builders, durable board state/replay/rotation, strict Ed25519 support, Criterion benches, `committee-sim`, and updated documentation.

Tests: **80 passed, 0 failed, 1 ignored**, preserving the original 26. Formatting and all-target Clippy passed.

All 288 benchmark smoke cases and 72 simulation runs completed. Exact commands and measurements are in [BENCHMARKS.md](/home/hoskinson/Projects/mpcexperiments-wt-rust/impl/BENCHMARKS.md).

No requested component remains unfinished. Timings cover n=9; larger sizes received smoke coverage. Live-chain acceptance was not tested. No commits made.