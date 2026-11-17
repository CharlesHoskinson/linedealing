//! Timing harness for a 9-node committee (open ECDSA, one slot), thread CPU time.
//! Run: cargo test --offline --release --test bench9 -- --ignored --nocapture
mod common;
use common::*;
use k256::ecdsa::{
    signature::hazmat::PrehashSigner, signature::hazmat::PrehashVerifier, Signature, SigningKey,
    VerifyingKey,
};
use line_dealing::message::*;
#[path = "../benches/support/cputime.rs"]
mod cputime;

fn keys_n(n: u16) -> Vec<k256::ProjectivePoint> {
    (1..=n).map(|i| G * node_secret(i)).collect()
}

struct BenchCtx {
    keys: Vec<k256::ProjectivePoint>,
    n: u16,
    f: u16,
}
impl AcceptanceContext for BenchCtx {
    fn committee(&self) -> CommitteeState {
        CommitteeState {
            chain_id: [1; 32],
            board_id: [2; 32],
            epoch: 7,
            keylist_hash: [4; 32],
            n: self.n,
            f: self.f,
            board_height: 20,
            grace_end: 200,
        }
    }
    fn check_header(&self, _: &line_dealing::wire::Header) -> line_dealing::Result<()> {
        Ok(())
    }
    fn is_bound_or_tombstoned(&self, _: &[u8; 32]) -> bool {
        false
    }
    fn sealed_sighashes(
        &self,
        _: &line_dealing::wire::Header,
    ) -> line_dealing::Result<Vec<[u8; 32]>> {
        Ok(vec![])
    }
    fn node_keys(&self) -> &[k256::ProjectivePoint] {
        &self.keys
    }
}

fn time<T>(label: &str, iters: u32, mut f: impl FnMut() -> T) -> f64 {
    let _ = f();
    let start = cputime::thread_ns();
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    let us = cputime::ms_since(start) * 1e3 / iters as f64;
    println!("{label:<44} {us:>10.1} us");
    us
}

#[allow(non_snake_case)]
fn run(n: u16, f: u16, threshold: u16) {
    let (N, F) = (n, f);
    println!("\n== n = {N}, f = {F}, t = {threshold}");
    let mut hdr = header(1, 2, 1);
    hdr.n = N;
    hdr.threshold = threshold;
    hdr.f = F;
    if threshold != F + 1 {
        hdr.on_rotation = 1; // reshare is legal only at t = f + 1 (SCHEME 5)
    }
    let keys = keys_n(N);
    let ctx = BenchCtx {
        keys: keys.clone(),
        n: N,
        f: F,
    };

    let owner = time("owner: deal + encrypt (one slot)", 200, || {
        let mut rng = TestRng::new();
        Owner::open_ecdsa(hdr.clone(), secret(), &[sc("nonce-1")], &mut rng)
            .unwrap()
            .encrypt(sc("eph"), &keys, &mut rng)
            .unwrap()
    });
    let mut rng = TestRng::new();
    let message = Owner::open_ecdsa(hdr.clone(), secret(), &[sc("nonce-1")], &mut rng)
        .unwrap()
        .encrypt(sc("eph"), &keys, &mut rng)
        .unwrap();
    let encoded = message.encode().unwrap();
    println!("{:<44} {:>10} bytes", "owner message size", encoded.len());

    let step_a = time("node: decode + Step A public checks", 500, || {
        OwnerMessage::decode(&encoded)
            .unwrap()
            .step_a(&ctx)
            .unwrap()
    });
    let accepted = message.step_a(&ctx).unwrap();
    let decrypt = time("node: decrypt + verify own shares", 2000, || {
        accepted.decrypt(1, node_secret(1)).unwrap()
    });
    let shares: Vec<_> = (1..=N)
        .map(|i| accepted.decrypt(i, node_secret(i)).unwrap())
        .collect();
    let m = msg("tx-A");
    let pkg_t = time("node: signing package (lock digest, R)", 2000, || {
        accepted.signing_package(1, 1, m, [9; 32]).unwrap()
    });
    let pkg = accepted.signing_package(1, 1, m, [9; 32]).unwrap();
    let partial = time("node: partial signature", 5000, || {
        pkg.partial(&shares[0]).unwrap()
    });
    let parts: Vec<_> = shares.iter().map(|s| pkg.partial(s).unwrap()).collect();
    let vpart = time("combiner: verify one partial", 2000, || {
        pkg.verify_partial(&parts[0])
    });
    let combine = time("combiner: combine t partials", 2000, || {
        pkg.combine(&parts[..threshold as usize]).unwrap()
    });

    // Board posts are signed; model each post check as one ECDSA verify.
    let sk = SigningKey::from_bytes(&sc("board").to_bytes()).unwrap();
    let vk = VerifyingKey::from(&sk);
    let sig: Signature = sk.sign_prehash(&[7u8; 32]).unwrap();
    let post = time("node: verify one signed board post", 5000, || {
        vk.verify_prehash(&[7u8; 32], &sig).is_ok()
    });

    // Per request, per node: Step A + decrypt + package + partial
    //   + verify signed posts: ACK, height-report and PREVOTE quorums (q each; q = ceil((n+f+1)/2)), t PARTIAL posts
    //   + combine (one node acts as combiner; optimistic path checks only the final signature).
    let posts = (3 * line_dealing::board::Committee { n: N, f: F }.quorum()
        + usize::from(threshold)) as f64;
    let node = step_a + decrypt + pkg_t + partial + posts * post;
    let combiner = combine;
    println!(
        "{:<44} {:>10.1} us  ({posts} post checks)",
        "=> per-node CPU per request", node
    );
    println!(
        "{:<44} {:>10.1} us",
        "=> combiner extra per request", combiner
    );
    let _ = (owner, vpart);
    println!(
        "{:<44} {:>10.0} req/s",
        "=> one core, CPU bound",
        1e6 / (node + combiner)
    );
}

#[test]
#[ignore]
#[allow(non_snake_case)]
fn bench_committee_of_9() {
    // n = 9 directly (q = 6 quorums), with n = 7 and n = 10 as brackets.
    for (n, f) in [(7u16, 2u16), (9, 2), (10, 3)] {
        run(n, f, f + 1); // profile T1, t = f + 1
        run(n, f, n - f); // profile T2, t = n - f
    }
}
