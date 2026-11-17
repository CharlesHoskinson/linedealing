//! Simulated post-to-broadcast latency of one split-line request (DESIGN §11.2).
//!
//! Model. Each run builds a real BIP340 P2TR request (K = 8, L = 2) and times,
//! on this thread, the real work of every node: the public proof check, its
//! outer share and header partial, the header opening, its release (ticket
//! checks, body partial, signature partials), the selected-body combination
//! and one board QC check (q Ed25519 strict verifications), in thread CPU time. A discrete-event
//! schedule then places that work on n parallel nodes:
//! - board: a post or vote reaches a block that commits C later. Model "fixed":
//!   the commit lands C after submission (the DESIGN §11.2 model). Model
//!   "blocks": blocks start every C at a uniform random phase, a submission
//!   waits for the next block start, then C.
//! - peer round: the messages of a round are delivered h after they are sent.
//!   The header-partial exchange, the release witness, the two slot-bind rounds
//!   and the release are one round each. Witness and bind carry no
//!   cryptographic work in the prototype, so they are pure delay.
//! - a node opens the header with its own partial and the first t - 1 others;
//!   the first node that has t release partials combines and broadcasts.
//! - authorization in force: Midnight-first at F_M = 10 s (reported as the
//!   remainder after F_M; F_M is later than every header opening); board-first
//!   at once.
//!   The board-first proof check is not in the prototype and is not counted.
//! - non-TEE mode: no witness and no bind rounds.
//!
//! Run: cargo test --offline --release --test split_latency -- --ignored --nocapture
use ed25519_dalek::{Signer, SigningKey};
use line_dealing::{
    experiment::SeededRng,
    split::{
        access::{Gate, LeafId},
        group::Secp,
        prf,
        request::SchnorrSetup,
    },
};
#[path = "../benches/support/cputime.rs"]
mod cputime;

struct Cpu {
    /// Per node, ms: pi check, outer share and header partial.
    order: Vec<f64>,
    /// Per node, ms: header combine and open.
    open: Vec<f64>,
    /// Per node, ms: ticket checks, body partial, signature partials.
    release: Vec<f64>,
    /// Per node, ms: body key, body and capsule, halves, combine and verify.
    combine: Vec<f64>,
    /// ms: q strict Ed25519 verifications of one board QC.
    qc: f64,
}

/// Thread CPU milliseconds since `start` (see benches/support/cputime.rs).
fn ms(start: u64) -> f64 {
    cputime::ms_since(start)
}

fn measure(n: u16, t: usize, q: usize, seed: u64) -> Cpu {
    let mut rng = SeededRng::new(seed);
    let id = LeafId::new(1, vec![], 1);
    let setup =
        SchnorrSetup::<Secp>::new(n, t, 8, 2, Gate::Leaf(id.clone()), vec![id], &mut rng).unwrap();
    let req = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
    let env = &req.envelope;
    let keys = setup.transport_keys.clone();
    let (mut order, mut shares, mut hdr) = (vec![], vec![], vec![]);
    for i in 1..=n {
        let start = cputime::thread_ns();
        env.verify_public(&keys, t, 1, 0).unwrap();
        let share = env
            .decrypt_share(i, setup.transport_secrets[usize::from(i - 1)], &keys)
            .unwrap();
        let partial = prf::partial(share, i, &env.dd(), prf::Label::Hdr).unwrap();
        order.push(ms(start));
        shares.push(share);
        hdr.push(partial);
    }
    let mut open = vec![];
    let mut opened = None;
    for _ in 1..=n {
        let start = cputime::thread_ns();
        let header = env.open_header(&hdr[..t]).unwrap();
        open.push(ms(start));
        opened = Some(header);
    }
    let opened = opened.unwrap();
    let (v, g) = (8u8, 1u8);
    let label = prf::Label::Body {
        variant: u16::from(v),
        generation: u16::from(g),
    };
    let (mut release, mut body) = (vec![], vec![]);
    let mut parts = vec![vec![]; usize::from(setup.l)];
    for i in 1..=n {
        let mut node = setup.node(i).unwrap();
        let start = cputime::thread_ns();
        let partial = prf::partial(shares[usize::from(i - 1)], i, &env.dd(), label).unwrap();
        let sig = req.signature_partials(&opened, v, g, &mut node).unwrap();
        release.push(ms(start));
        body.push(partial);
        for (j, p) in sig.into_iter().enumerate() {
            parts[j].push(p);
        }
    }
    let first: Vec<_> = parts.iter().map(|p| p[..t].to_vec()).collect();
    let mut combine = vec![];
    for _ in 1..=n {
        let mut slots = setup.slots.clone();
        let start = cputime::thread_ns();
        let out = req
            .combine(
                &opened,
                v,
                g,
                &body[..t],
                &first,
                &[],
                &setup.committee,
                &mut slots,
            )
            .unwrap();
        combine.push(ms(start));
        assert_eq!(out.len(), usize::from(setup.l));
    }
    let vote = b"split latency: one board block";
    let voters: Vec<_> = (1..=q)
        .map(|i| SigningKey::from_bytes(&[i as u8; 32]))
        .collect();
    let sigs: Vec<_> = voters.iter().map(|k| k.sign(vote)).collect();
    let start = cputime::thread_ns();
    for (k, s) in voters.iter().zip(&sigs) {
        k.verifying_key().verify_strict(vote, s).unwrap();
    }
    let qc = ms(start);
    Cpu {
        order,
        open,
        release,
        combine,
        qc,
    }
}

#[derive(Clone, Copy)]
struct Net {
    c: f64,
    h: f64,
    /// None: commit C after submission. Some(phase): blocks start at phase + kC.
    phase: Option<f64>,
    tee: bool,
    board_first: bool,
}

fn commit(net: Net, at: f64) -> f64 {
    match net.phase {
        None => at + net.c,
        Some(phase) => {
            let k = ((at - phase) / net.c).ceil();
            phase + k * net.c + net.c
        }
    }
}

/// k-th smallest (1-based).
fn kth(mut v: Vec<f64>, k: usize) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[k - 1]
}

/// Post-to-broadcast in ms. Midnight-first returns the remainder after F_M.
fn latency(cpu: &Cpu, n: usize, t: usize, q: usize, net: Net) -> f64 {
    let ordered = commit(net, 0.0) + cpu.qc;
    let sent: Vec<f64> = cpu.order.iter().map(|w| ordered + w).collect();
    let opened: Vec<f64> = (0..n)
        .map(|j| {
            let others: Vec<f64> = (0..n)
                .filter(|&i| i != j)
                .map(|i| sent[i] + net.h)
                .collect();
            let ready = if t > 1 {
                sent[j].max(kth(others, t - 1))
            } else {
                sent[j]
            };
            ready + cpu.open[j]
        })
        .collect();
    // F_M is a fixed 10 s, later than every header opening here, so the
    // remainder after it does not depend on its value and the block phase
    // relative to F_M is uniform; a board-first authorization is in force at once.
    let fm = if net.board_first {
        0.0
    } else {
        let latest = opened.iter().cloned().fold(0.0, f64::max);
        assert!(latest < 10_000.0);
        10_000.0
    };
    let votes: Vec<f64> = opened.iter().map(|o| o.max(fm)).collect();
    let admitted = commit(net, kth(votes, q)) + cpu.qc;
    let rounds = if net.tee { 3.0 } else { 0.0 };
    let rel: Vec<f64> = (0..n)
        .map(|j| admitted + rounds * net.h + cpu.release[j])
        .collect();
    let broadcast = (0..n)
        .map(|k| {
            let arrivals: Vec<f64> = (0..n)
                .map(|i| if i == k { rel[i] } else { rel[i] + net.h })
                .collect();
            rel[k].max(kth(arrivals, t)) + cpu.combine[k]
        })
        .fold(f64::INFINITY, f64::min);
    broadcast - fm
}

fn pct(mut v: Vec<f64>, p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((p * v.len() as f64).ceil() as usize).clamp(1, v.len());
    v[i - 1]
}

#[test]
#[ignore]
fn split_latency_table() {
    let runs: u64 = std::env::var("SPLIT_LATENCY_RUNS")
        .ok()
        .map_or(30, |v| v.parse().unwrap());
    println!("| n | t | q | Mode | Authorization | C ms | h ms | Board model | runs | p50 ms | p99 ms | max ms | Formula ms |");
    println!("|---:|---:|---:|---|---|---:|---:|---|---:|---:|---:|---:|---:|");
    for n in [9u16, 17] {
        let f = (n - 1) / 3;
        let t = usize::from(n - f);
        let q = usize::from((n + f + 1).div_ceil(2));
        // One warm-up request per committee size is measured and discarded.
        measure(n, t, q, 8999);
        let cpus: Vec<Cpu> = (0..runs).map(|r| measure(n, t, q, 9000 + r)).collect();
        let mut work = [0.0f64; 5];
        for cpu in &cpus {
            work[0] += cpu.order.iter().sum::<f64>() / f64::from(n);
            work[1] += cpu.open.iter().sum::<f64>() / f64::from(n);
            work[2] += cpu.release.iter().sum::<f64>() / f64::from(n);
            work[3] += cpu.combine.iter().sum::<f64>() / f64::from(n);
            work[4] += cpu.qc;
        }
        println!(
            "\nn={n} mean per-node work ms over {runs} runs: order {:.3}, open {:.3}, release {:.3}, combine {:.3}, qc {:.3}\n",
            work[0] / runs as f64,
            work[1] / runs as f64,
            work[2] / runs as f64,
            work[3] / runs as f64,
            work[4] / runs as f64
        );
        for tee in [true, false] {
            for board_first in [false, true] {
                for (c, h) in [(1000.0, 50.0), (500.0, 50.0), (1000.0, 25.0), (500.0, 0.0)] {
                    for blocks in [false, true] {
                        let mut out = vec![];
                        for (r, cpu) in cpus.iter().enumerate() {
                            // 32 block phases per measured run.
                            let phases: Vec<Option<f64>> = if blocks {
                                (0..32)
                                    .map(|p| Some(c * ((r * 32 + p) as f64 * 0.618_034).fract()))
                                    .collect()
                            } else {
                                vec![None]
                            };
                            for phase in phases {
                                let net = Net {
                                    c,
                                    h,
                                    phase,
                                    tee,
                                    board_first,
                                };
                                out.push(latency(cpu, usize::from(n), t, q, net));
                            }
                        }
                        let rounds = if tee { 4.0 } else { 1.0 };
                        let formula = if board_first {
                            2.0 * c + (rounds + 1.0) * h
                        } else {
                            c + rounds * h
                        };
                        let max = out.iter().cloned().fold(0.0, f64::max);
                        println!(
                            "| {n} | {t} | {q} | {} | {} | {c:.0} | {h:.0} | {} | {} | {:.1} | {:.1} | {max:.1} | {formula:.0} |",
                            if tee { "TEE" } else { "non-TEE" },
                            if board_first { "board-first" } else { "Midnight-first, after F_M" },
                            if blocks { "blocks, random phase" } else { "fixed C" },
                            out.len(),
                            pct(out.clone(), 0.5),
                            pct(out.clone(), 0.99),
                        );
                    }
                }
            }
        }
    }
}
