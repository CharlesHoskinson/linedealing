//! Threaded n=9 benchmark. The sequencer authenticates and orders posts.
//! Target-chain finality, durable fsync costs, and BFT consensus are not simulated.
use crate::{
    board::*,
    experiment::{EdSetup, SecpSetup, SeededRng},
    hash::h,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

type SimResult<T> = Result<T, String>;
#[derive(Clone, Debug)]
pub struct Config {
    pub requests: usize,
    pub suite: u8,
    pub sealed: bool,
    pub threshold: u16,
    pub latency_ms: u64,
    pub batch_size: usize,
    pub board_ms: u64,
    pub seed: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            requests: 16,
            suite: 1,
            sealed: false,
            threshold: 3,
            latency_ms: 0,
            batch_size: 1,
            board_ms: 1,
            seed: 42,
        }
    }
}
#[derive(Debug)]
pub struct Report {
    pub completed: usize,
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub requests_per_second: f64,
    pub elapsed_seconds: f64,
    pub posts: usize,
    pub board_batches: usize,
    pub channel_batches: usize,
}

fn error(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
#[derive(Clone)]
enum CryptoRequest {
    Secp(Box<(SecpSetup, crate::message::OwnerMessage)>),
    Ed(Box<(EdSetup, crate::ed25519::OwnerMessage)>),
}
enum CryptoNode {
    Secp(crate::signing::SigningPackage, crate::message::NodeShares),
    Ed(crate::ed25519::SigningPackage, crate::ed25519::NodeShares),
}
enum CryptoVerifier {
    Secp(crate::signing::SigningPackage),
    Ed(crate::ed25519::SigningPackage),
}
#[derive(Clone)]
enum CryptoPartial {
    Secp(crate::signing::Partial),
    Ed(crate::ed25519::Partial),
}
impl CryptoRequest {
    fn verifier(&self) -> SimResult<CryptoVerifier> {
        match self {
            Self::Secp(pair) => {
                let (setup, message) = &**pair;
                let accepted = message.step_a(setup).map_err(error)?;
                setup
                    .package(&accepted)
                    .map(CryptoVerifier::Secp)
                    .map_err(error)
            }
            Self::Ed(pair) => {
                let (setup, message) = &**pair;
                let accepted = message.step_a(setup).map_err(error)?;
                setup
                    .package(&accepted)
                    .map(CryptoVerifier::Ed)
                    .map_err(error)
            }
        }
    }
    fn prepare(&self, node: u16) -> SimResult<CryptoNode> {
        match self {
            Self::Secp(pair) => {
                let (setup, msg) = &**pair;
                let accepted = msg.step_a(setup).map_err(error)?;
                Ok(CryptoNode::Secp(
                    setup.package(&accepted).map_err(error)?,
                    accepted
                        .decrypt(node, setup.secrets[node as usize - 1])
                        .map_err(error)?,
                ))
            }
            Self::Ed(pair) => {
                let (setup, msg) = &**pair;
                let accepted = msg.step_a(setup).map_err(error)?;
                Ok(CryptoNode::Ed(
                    setup.package(&accepted).map_err(error)?,
                    accepted
                        .decrypt(node, setup.secrets[node as usize - 1])
                        .map_err(error)?,
                ))
            }
        }
    }
}
impl CryptoNode {
    fn partial(&self) -> SimResult<CryptoPartial> {
        match self {
            Self::Secp(p, s) => p.partial(s).map(CryptoPartial::Secp).map_err(error),
            Self::Ed(p, s) => p.partial(s).map(CryptoPartial::Ed).map_err(error),
        }
    }
}
impl CryptoVerifier {
    fn verify(&self, partial: &CryptoPartial) -> bool {
        match (self, partial) {
            (Self::Secp(p), CryptoPartial::Secp(s)) => p.verify_partial(s),
            (Self::Ed(p), CryptoPartial::Ed(s)) => p.verify_partial(s),
            _ => false,
        }
    }
    fn combine(&self, partials: &[CryptoPartial]) -> SimResult<()> {
        match self {
            Self::Secp(p) => {
                let values: Vec<_> = partials
                    .iter()
                    .filter_map(|s| {
                        if let CryptoPartial::Secp(s) = s {
                            Some(*s)
                        } else {
                            None
                        }
                    })
                    .collect();
                p.combine(&values).map_err(error)?;
            }
            Self::Ed(p) => {
                let values: Vec<_> = partials
                    .iter()
                    .filter_map(|s| {
                        if let CryptoPartial::Ed(s) = s {
                            Some(*s)
                        } else {
                            None
                        }
                    })
                    .collect();
                p.combine(&values).map_err(error)?;
            }
        }
        Ok(())
    }
}
struct Request {
    crypto: CryptoRequest,
    build: LocalBuild,
    mid: Digest,
    started: Instant,
}
#[derive(Clone, Copy)]
enum Phase {
    Accept,
    Observe,
    Vote,
    Share,
}
#[derive(Clone, Copy)]
struct Command {
    id: usize,
    phase: Phase,
}
struct Post {
    id: usize,
    node: u16,
    event: Event,
    partial: Option<CryptoPartial>,
    signature: ed25519_dalek::Signature,
}
fn post_bytes(event: &Event) -> Vec<u8> {
    // Injective Debug serialization for this closed experimental enum; not a wire protocol.
    let mut bytes = b"LD1/post/simulator/board-2/epoch-1/".to_vec();
    bytes.extend(format!("{event:?}").as_bytes());
    bytes
}
fn worker(
    node: u16,
    requests: Arc<Vec<Request>>,
    board: Arc<Mutex<Board>>,
    rx: mpsc::Receiver<Vec<Command>>,
    tx: mpsc::Sender<(Instant, SimResult<Vec<Post>>)>,
) {
    let mut local = NodeState::new(node, 1);
    let key = SigningKey::from_bytes(&h("simulation/post-key", &node.to_be_bytes()));
    let mut crypto: BTreeMap<usize, CryptoNode> = BTreeMap::new();
    for commands in rx {
        let result = (|| {
            let mut posts = Vec::with_capacity(commands.len());
            for command in commands {
                let request = &requests[command.id];
                let build = &request.build;
                {
                    let view = board.lock().map_err(error)?;
                    local
                        .replay(&view, |rid, generation| {
                            // The simulator holds one generation per request.
                            if generation.is_none_or(|g| g == 1) {
                                crypto.retain(|id, _| requests[*id].build.rid != rid);
                            }
                            Ok(())
                        })
                        .map_err(error)?;
                    local.ensure_can_post(&view).map_err(error)?;
                }
                let (event, partial) = match command.phase {
                    Phase::Accept => {
                        crypto.insert(command.id, request.crypto.prepare(node)?);
                        (
                            Event::Ack {
                                rid: build.rid,
                                epoch: 1,
                                node,
                                mid: request.mid,
                            },
                            None,
                        )
                    }
                    Phase::Observe => (
                        Event::Obs {
                            rid: build.rid,
                            epoch: 1,
                            node,
                            generation: 1,
                            attempt: 1,
                            target_height: 100,
                        },
                        None,
                    ),
                    Phase::Vote => (
                        local
                            .prevote(&*board.lock().map_err(error)?, build)
                            .map_err(error)?,
                        None,
                    ),
                    Phase::Share => {
                        let event = local
                            .partial(&*board.lock().map_err(error)?, build)
                            .map_err(error)?;
                        // Consumption precedes even the calculation of the secret partial.
                        let partial = crypto
                            .get(&command.id)
                            .ok_or("missing decrypted shares")?
                            .partial()?;
                        (event, Some(partial))
                    }
                };
                let signature = key.sign(&post_bytes(&event));
                posts.push(Post {
                    id: command.id,
                    node,
                    event,
                    partial,
                    signature,
                });
            }
            Ok(posts)
        })();
        if tx.send((Instant::now(), result)).is_err() {
            return;
        }
    }
}

pub fn run(config: &Config) -> SimResult<Report> {
    if config.requests == 0
        || config.requests > 100_000
        || !(1..=3).contains(&config.suite)
        || ![3, 7].contains(&config.threshold)
        || config.batch_size == 0
        || config.latency_ms > 60_000
        || config.board_ms > 60_000
    {
        return Err("invalid configuration".into());
    }
    let start = Instant::now();
    let mut board = Board::new(Committee { n: 9, f: 2 }, 1).map_err(error)?;
    let mut requests = Vec::new();
    for id in 0..config.requests {
        let started = Instant::now();
        let seed = config.seed.wrapping_add(id as u64);
        let mut rng = SeededRng::new(seed);
        let (crypto, rid, mid, digest, pin, txid) = if config.suite == 3 {
            let setup = EdSetup::new(9, config.threshold, config.sealed, seed).map_err(error)?;
            let message = setup.owner_message(&mut rng).map_err(error)?;
            let (rid, mid, digest) = (
                message.rid().map_err(error)?,
                message.mid().map_err(error)?,
                setup.digest,
            );
            let pin = h("LD1/pin", &setup.header.intent.pin);
            let txid = h("simulation/ed-message", &setup.messages[0]);
            (
                CryptoRequest::Ed(Box::new((setup, message))),
                rid,
                mid,
                digest,
                pin,
                txid,
            )
        } else {
            let setup = SecpSetup::new(9, config.threshold, config.suite, config.sealed, seed)
                .map_err(error)?;
            let message = setup.owner_message(&mut rng).map_err(error)?;
            let (rid, mid, digest) = (
                message.rid().map_err(error)?,
                message.mid().map_err(error)?,
                setup
                    .lock_digest(message.rid().map_err(error)?)
                    .map_err(error)?,
            );
            let pin = h("LD1/pin", &setup.header.intent.pin);
            use sha2::Digest as _;
            let txid =
                sha2::Sha256::digest(sha2::Sha256::digest(setup.transaction().map_err(error)?))
                    .into();
            (
                CryptoRequest::Secp(Box::new((setup, message))),
                rid,
                mid,
                digest,
                pin,
                txid,
            )
        };
        board
            .apply(
                1,
                Event::Bind {
                    spec: RequestSpec {
                        rid,
                        mid,
                        pin,
                        epoch: 1,
                        mode: if config.sealed {
                            Mode::Sealed
                        } else {
                            Mode::Open
                        },
                        threshold: config.threshold,
                        not_before: 0,
                        expires: 1_000_000,
                        generations: 1,
                        variants: if config.sealed { 8 } else { 0 },
                        rotation: Rotation::Finish,
                    },
                    valid: true,
                },
            )
            .map_err(error)?;
        requests.push(Request {
            crypto,
            build: LocalBuild {
                rid,
                epoch: 1,
                generation: 1,
                candidate: Candidate {
                    attempt: 1,
                    block_hash: h("simulation/block", &100u64.to_be_bytes()),
                    digest,
                },
                pin,
                txid,
                variant: config.sealed.then_some(1),
            },
            mid,
            started,
        });
    }
    let requests = Arc::new(requests);
    let board = Arc::new(Mutex::new(board));
    let (posts_tx, posts_rx) = mpsc::channel();
    let mut senders = Vec::new();
    let mut handles = Vec::new();
    for node in 1..=9 {
        let (tx, rx) = mpsc::channel();
        senders.push(tx);
        let (requests, board, posts_tx) =
            (Arc::clone(&requests), Arc::clone(&board), posts_tx.clone());
        handles.push(thread::spawn(move || {
            worker(node, requests, board, rx, posts_tx)
        }));
    }
    drop(posts_tx);
    let keys: Vec<VerifyingKey> = (1u16..=9)
        .map(|node| {
            SigningKey::from_bytes(&h("simulation/post-key", &node.to_be_bytes())).verifying_key()
        })
        .collect();
    let link = Duration::from_millis(config.latency_ms);
    let commit = Duration::from_millis(config.board_ms);
    let mut scheduled: Vec<(Instant, usize, Vec<Command>)> = Vec::new();
    let mut outgoing = vec![Vec::new(); 9];
    for queue in &mut outgoing {
        queue.extend((0..config.requests).map(|id| Command {
            id,
            phase: Phase::Accept,
        }));
    }
    let mut network: Vec<(Instant, Vec<Post>)> = Vec::new();
    let mut pending = VecDeque::new();
    let mut stages = vec![0; config.requests];
    let mut partials = vec![Vec::new(); config.requests];
    let mut completed = vec![false; config.requests];
    let mut latencies = Vec::new();
    let mut packages: BTreeMap<usize, CryptoVerifier> = BTreeMap::new();
    let (mut posts, mut batches, mut channel_batches) = (0, 0, 0);
    let expected_posts = config.requests * 9 * if config.sealed { 3 } else { 4 };
    let mut next_commit = Instant::now();
    let mut last_completion = start;
    let deadline = Instant::now() + Duration::from_secs(300);
    while posts < expected_posts || latencies.len() < config.requests {
        if Instant::now() > deadline {
            return Err(format!(
                "simulation timed out after {posts}/{expected_posts} posts"
            ));
        }
        let now = Instant::now();
        for (node, queue) in outgoing.iter_mut().enumerate() {
            for chunk in queue.chunks(config.batch_size) {
                scheduled.push((now + link, node, chunk.to_vec()));
            }
            queue.clear();
        }
        let mut i = 0;
        while i < scheduled.len() {
            if scheduled[i].0 <= now {
                let (_, node, commands) = scheduled.swap_remove(i);
                senders[node].send(commands).map_err(error)?;
                channel_batches += 1;
            } else {
                i += 1
            }
        }
        for (sent, result) in posts_rx.try_iter() {
            network.push((sent + link, result?));
        }
        let mut i = 0;
        while i < network.len() {
            if network[i].0 <= now {
                let (_, batch) = network.swap_remove(i);
                pending.extend(batch);
                channel_batches += 1;
            } else {
                i += 1
            }
        }
        if !pending.is_empty() && now >= next_commit {
            let count = config.batch_size.min(pending.len());
            batches += 1;
            for _ in 0..count {
                let post = pending.pop_front().unwrap();
                keys[post.node as usize - 1]
                    .verify_strict(&post_bytes(&post.event), &post.signature)
                    .map_err(error)?;
                if let Some(partial) = &post.partial {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        packages.entry(post.id)
                    {
                        entry.insert(requests[post.id].crypto.verifier()?);
                    }
                    if !packages[&post.id].verify(partial) {
                        return Err("invalid cryptographic partial".into());
                    }
                }
                let mut board = board.lock().map_err(error)?;
                // Reports that arrive after their quorum remain valid ordered posts.
                let late = matches!(post.event, Event::Obs { .. } | Event::Prevote { .. });
                match board.apply(1, post.event) {
                    Ok(()) => {}
                    Err(BoardError::Attempt) if late => {}
                    Err(e) => return Err(error(e)),
                }
                posts += 1;
                if let Some(partial) = post.partial {
                    partials[post.id].push(partial);
                    if !completed[post.id] && partials[post.id].len() >= config.threshold as usize {
                        packages[&post.id]
                            .combine(&partials[post.id][..config.threshold as usize])?;
                        completed[post.id] = true;
                        last_completion = Instant::now();
                        latencies.push(
                            last_completion
                                .duration_since(requests[post.id].started)
                                .as_secs_f64()
                                * 1000.0,
                        );
                    }
                }
                let request = board.request(&requests[post.id].build.rid).map_err(error)?;
                let phase = match stages[post.id] {
                    0 if request.armed => {
                        stages[post.id] = 1;
                        Some(Phase::Observe)
                    }
                    1 if request
                        .generations
                        .get(&1)
                        .and_then(|g| g.attempts.get(&1))
                        .and_then(|a| a.anchor.as_ref())
                        .is_some() =>
                    {
                        stages[post.id] = if config.sealed { 3 } else { 2 };
                        Some(if config.sealed {
                            Phase::Share
                        } else {
                            Phase::Vote
                        })
                    }
                    2 if request
                        .generations
                        .get(&1)
                        .is_some_and(|g| g.lock.is_some()) =>
                    {
                        stages[post.id] = 3;
                        Some(Phase::Share)
                    }
                    _ => None,
                };
                if let Some(phase) = phase {
                    for queue in &mut outgoing {
                        queue.push(Command { id: post.id, phase });
                    }
                }
            }
            next_commit = Instant::now() + commit;
        }
        if outgoing.iter().any(|q| !q.is_empty()) {
            continue;
        }
        let wake = scheduled
            .iter()
            .map(|e| e.0)
            .chain(network.iter().map(|e| e.0))
            .chain((!pending.is_empty()).then_some(next_commit))
            .min()
            .unwrap_or(deadline)
            .min(deadline);
        let wait = wake.saturating_duration_since(Instant::now());
        if posts < expected_posts {
            match posts_rx.recv_timeout(wait) {
                Ok((sent, batch)) => network.push((sent + link, batch?)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("workers disconnected".into())
                }
            }
        }
    }
    drop(senders);
    for handle in handles {
        handle.join().map_err(|_| "worker panic".to_string())?;
    }
    latencies.sort_by(f64::total_cmp);
    let percentile = |p: usize| latencies[(latencies.len() * p).div_ceil(100).saturating_sub(1)];
    let elapsed = last_completion.duration_since(start).as_secs_f64();
    Ok(Report {
        completed: latencies.len(),
        p50_ms: percentile(50),
        p99_ms: percentile(99),
        requests_per_second: config.requests as f64 / elapsed,
        elapsed_seconds: elapsed,
        posts,
        board_batches: batches,
        channel_batches,
    })
}
