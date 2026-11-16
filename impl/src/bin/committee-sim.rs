use line_dealing::simulation::{run, Config};

fn main() {
    if let Err(error) = execute() {
        eprintln!("committee-sim: {error}");
        std::process::exit(2);
    }
}
fn execute() -> Result<(), String> {
    let mut config = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            println!("committee-sim [--requests N] [--suite ecdsa|bip340|ed25519] [--mode open|sealed] [--threshold 3|7] [--latency-ms 0|25|50] [--batch-size N] [--board-ms N] [--seed N]\n\nn=9, f=2, quorum=7. Sealed mode deals K=8 variants.\nLatency applies once per one-way channel delivery. Board service time applies per batch.\nTiming includes owner preparation, acceptance, anchoring, lock (open), and signature reconstruction.\nThe sequencer verifies signed posts. It does not simulate BFT consensus or chain finality.");
            return Ok(());
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--requests" => config.requests = value.parse().map_err(|_| "invalid request count")?,
            "--threshold" => config.threshold = value.parse().map_err(|_| "invalid threshold")?,
            "--latency-ms" => config.latency_ms = value.parse().map_err(|_| "invalid latency")?,
            "--batch-size" => {
                config.batch_size = value.parse().map_err(|_| "invalid batch size")?
            }
            "--board-ms" => config.board_ms = value.parse().map_err(|_| "invalid board time")?,
            "--seed" => config.seed = value.parse().map_err(|_| "invalid seed")?,
            "--suite" => {
                config.suite = match value.as_str() {
                    "ecdsa" => 1,
                    "bip340" => 2,
                    "ed25519" => 3,
                    _ => return Err("unknown suite".into()),
                }
            }
            "--mode" => {
                config.sealed = match value.as_str() {
                    "open" => false,
                    "sealed" => true,
                    _ => return Err("unknown mode".into()),
                }
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    let report = run(&config)?;
    println!(
        "suite={} mode={} n=9 f=2 t={} requests={} latency_ms={} batch_size={} board_ms={} seed={}",
        config.suite,
        if config.sealed { "sealed-k8" } else { "open" },
        config.threshold,
        config.requests,
        config.latency_ms,
        config.batch_size,
        config.board_ms,
        config.seed
    );
    println!("completed={} p50_ms={:.3} p99_ms={:.3} requests_per_second={:.3} elapsed_seconds={:.6} posts={} board_batches={} channel_batches={}", report.completed, report.p50_ms, report.p99_ms, report.requests_per_second, report.elapsed_seconds, report.posts, report.board_batches, report.channel_batches);
    Ok(())
}
