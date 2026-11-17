//! Measure the encoded prototype objects. Fixture keys and RNG seeds are public.
#[path = "../../benches/support/mod.rs"]
mod support;

use k256::{ProjectivePoint, Scalar};
use line_dealing::{
    experiment::SeededRng,
    split::{
        envelope::{
            self, ContributionPayload, Envelope, Header, OpenedHeader, PreparedEnvelope, Public,
            WireSizes,
        },
        group::{Edwards, Secp, Suite},
        schnorr::SchnorrSuite,
        slots,
    },
};
use std::collections::BTreeMap;

fn contribution_sizes(
    header: &Header,
    payload: ContributionPayload,
    keys: &[ProjectivePoint],
    t: u16,
) -> (usize, usize) {
    let mut embedded = payload.token.to_vec();
    for sealed in &payload.sealed {
        embedded.extend(sealed.encode());
    }
    let header = Header::contribution(header, payload).unwrap();
    let mut rng = SeededRng::new(165);
    let prepared = PreparedEnvelope::new(
        Public::new(1, envelope::keylist_hash(keys).unwrap(), 100),
        keys,
        t,
        &mut rng,
    )
    .unwrap();
    let pending = prepared
        .build(header, vec![], vec![], vec![], &mut rng)
        .unwrap();
    let used = pending.used_bytes();
    let frame = pending.authorize(None, &mut rng).unwrap();
    assert_eq!(frame.as_bytes().len(), envelope::FRAME_SIZE);
    (used, embedded.len())
}

fn sizes(frame: &Envelope, header: &OpenedHeader, expected_used: usize) -> WireSizes {
    let result = frame.wire_sizes(header).unwrap();
    assert_eq!(result.used(), expected_used);
    assert_eq!(frame.as_bytes().len(), envelope::FRAME_SIZE);
    result
}

fn row(
    n: u16,
    suite: &str,
    grid: &str,
    sizes: WireSizes,
    growth: [usize; 2],
    contribution: (usize, usize),
) {
    println!(
        "| {n} | {suite} | {grid} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
        sizes.used(),
        sizes.outer + sizes.proof,
        sizes.layout,
        sizes.header,
        sizes.bodies,
        sizes.capsules,
        growth[0],
        growth[1],
        contribution.0,
        contribution.1
    );
}

fn schnorr<S: SchnorrSuite>(n: u16, k: u8, l: u8, name: &str) {
    let mut rng = SeededRng::new(153);
    let mut used = vec![];
    let mut base = None;
    let mut contribution = None;
    for count in 0..=2 {
        let mut setup = support::schnorr::<S>(n, k, l, count);
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let partials: Vec<_> = (1..=support::threshold(n))
            .map(|i| {
                request
                    .header_partial(
                        i,
                        setup.transport_secrets[usize::from(i - 1)],
                        &setup.transport_keys,
                    )
                    .unwrap()
            })
            .collect();
        let opened = request.envelope.open_header(&partials).unwrap();
        let actual = sizes(&request.envelope, &opened, request.used_bytes);
        used.push(actual.used());
        if count == 0 {
            base = Some(actual);
        }
        if count == 1 {
            let payload = request
                .actor_contribute(
                    1,
                    &setup.actor_secrets[&1],
                    setup.pools.get_mut(&setup.set[1]).unwrap(),
                    0,
                    20,
                    &mut rng,
                )
                .unwrap();
            contribution = Some(contribution_sizes(
                opened.header(),
                payload,
                &setup.transport_keys,
                support::threshold(n),
            ));
        }
    }
    row(
        n,
        name,
        &format!("K={k}, L={l}"),
        base.unwrap(),
        [used[1] - used[0], used[2] - used[1]],
        contribution.unwrap(),
    );
}

fn ecdsa(n: u16) {
    let mut used = vec![];
    let mut base = None;
    let mut contribution = None;
    for count in 0..=2 {
        let (request, secrets) = support::ecdsa(n, count);
        let partials: Vec<_> = (1..=support::threshold(n))
            .map(|i| {
                request
                    .header_partial(i, secrets[usize::from(i - 1)])
                    .unwrap()
            })
            .collect();
        let opened = request.open_header(&partials).unwrap();
        let actual = sizes(&request.envelope, &opened, request.sizes.used);
        used.push(actual.used());
        if count == 0 {
            base = Some(actual);
        }
        if count == 1 {
            let actor = &opened.header().actors[0];
            let embedded = actor.embedded.as_ref().unwrap();
            let payload = ContributionPayload {
                target_hd: request.envelope.hd(),
                position: actor.position,
                token: embedded.token,
                sealed: embedded.sealed.clone(),
            };
            let keys: Vec<_> = secrets.iter().map(|s| Secp::generator_mul(*s)).collect();
            contribution = Some(contribution_sizes(
                opened.header(),
                payload,
                &keys,
                support::threshold(n),
            ));
        }
    }
    row(
        n,
        "ECDSA (embedded actors)",
        "K=3, L=2",
        base.unwrap(),
        [used[1] - used[0], used[2] - used[1]],
        contribution.unwrap(),
    );
}

fn slot_bytes(n: u16, count: u64) -> usize {
    let mut rng = SeededRng::new(149);
    let recipients: BTreeMap<_, _> = (1..=n)
        .map(|i| (i, Secp::generator_mul(Scalar::from(u64::from(i) + 100))))
        .collect();
    let ids: Vec<_> = (1..=count).collect();
    (1..=support::threshold(n))
        .map(|dealer| {
            slots::create_dealer_message::<Secp>(
                dealer,
                1,
                support::threshold(n),
                &ids,
                &recipients,
                &mut rng,
            )
            .unwrap()
            .encode()
            .unwrap()
            .len()
        })
        .sum()
}

/// Encoded points of one actor pool of 64 pairs (D, E). The POOL record
/// framing (pool id, pool key, signature) has no encoder in the prototype (O23).
fn pool_points() -> usize {
    use line_dealing::split::{access::LeafId, schnorr::ActorPool};
    let mut rng = SeededRng::new(171);
    let pool = ActorPool::<Secp>::new(
        LeafId::new(1, vec![], 1),
        [1; 32],
        Secp::random(&mut rng),
        Secp::random(&mut rng),
        64,
        &mut rng,
    )
    .unwrap();
    (0..64)
        .map(|i| {
            let c = pool.commitment(i).unwrap();
            Secp::encode_point(c.d).unwrap().len() + Secp::encode_point(c.e).unwrap().len()
        })
        .sum()
}

fn main() {
    println!(
        "All values are bytes from serialized prototype objects; frame capacity is 16,384 bytes."
    );
    println!("Layout, header, bodies and capsules include AEAD tags. Layout is 64 bytes. Actor HPKE capsules are 385 bytes. Outer includes the public proof. Actor growth uses separately built one- and two-actor requests; first growth includes the shared contribution keys.");
    println!();
    println!("| n | Suite | Grid | Frame used | Outer + proof | Layout | Header | Bodies | Capsules | First other actor | Next other actor | CONTRIB frame used | Embedded actor |\n|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for n in [5, 9, 17, 33] {
        schnorr::<Secp>(n, 8, 2, "BIP340");
        ecdsa(n);
        schnorr::<Edwards>(n, 1, 1, "Ed25519");
    }
    println!("\nBoard slot posts include dealer context, ephemeral key and proof. Four slots are one batch per dealer; all t dealers are counted.");
    println!("\n| n | t | One Schnorr slot | Four Schnorr slots |\n|---:|---:|---:|---:|");
    for n in [5, 9, 17, 33] {
        println!(
            "| {n} | {} | {} | {} |",
            support::threshold(n),
            slot_bytes(n, 1),
            slot_bytes(n, 4)
        );
    }
    println!(
        "\nActor pool pair points, N_pool = 64 pairs (D, E), secp256k1 encoder: {} bytes",
        pool_points()
    );
}
