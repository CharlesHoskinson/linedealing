mod common;
use common::TestRng;
use line_dealing::split::{
    access::{Gate, LeafId},
    group::{Edwards, Secp},
    request::SchnorrSetup,
};

fn checkpoint(board: &mut line_dealing::split::request::board::BoardAdapter) {
    use line_dealing::split::state::{Event, PoolCheckpoint, PoolId, Suite};
    use std::collections::BTreeMap;
    board
        .apply(
            0,
            Event::Checkpoint {
                pools: [Suite::Bip340, Suite::Ed25519]
                    .into_iter()
                    .map(|suite| {
                        (
                            PoolId { suite, epoch: 1 },
                            PoolCheckpoint {
                                h: 0,
                                pending_min: 1,
                                pending_root: [0; 32],
                                pending_count: 0,
                                pending: BTreeMap::new(),
                                pending_verified: true,
                            },
                        )
                    })
                    .collect(),
            },
        )
        .unwrap();
}

fn single() -> (Gate, Vec<LeafId>) {
    let id = LeafId::new(1, vec![], 1);
    (Gate::Leaf(id.clone()), vec![id])
}
#[test]
fn birth_to_serialized_schnorr_request() {
    let mut rng = TestRng::new();
    let (gate, set) = single();
    let setup = SchnorrSetup::<Secp>::new(9, 7, 8, 2, gate, set, &mut rng).unwrap();
    let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
    assert_eq!(request.envelope.as_bytes().len(), 16384);
    assert!(request.used_bytes < 16384);
}

mod board_scenarios {
    use super::{single, TestRng};
    use line_dealing::{
        board::Committee,
        split::{
            access::{Gate, LeafId},
            envelope::OpenedHeader,
            group::Secp,
            prf::Label,
            request::{
                board::{
                    AuthorizationEvidence, BoardAdapter, BoardError, HeaderPolicy, ReleaseEvidence,
                },
                check_release_tickets, decode_ticket, SchnorrRequest, SchnorrSetup,
            },
            state::{Observation, Settlement, SlotState, SplitError, State, VoidReason},
        },
    };

    fn adapter(setup: &SchnorrSetup<Secp>) -> BoardAdapter {
        let mut board = BoardAdapter::new(
            Committee { n: 9, f: 2 },
            1,
            20,
            256,
            false,
            false,
            setup.transport_keys.clone(),
        )
        .unwrap();
        super::checkpoint(&mut board);
        board
    }

    fn open(
        board: &mut BoardAdapter,
        setup: &SchnorrSetup<Secp>,
        request: &SchnorrRequest<Secp>,
        policy_id: u8,
    ) -> OpenedHeader {
        let keys: Vec<_> = setup
            .transport_secrets
            .iter()
            .take(7)
            .enumerate()
            .map(|(i, key)| (i as u16 + 1, *key))
            .collect();
        board.post(1, &request.envelope).unwrap();
        board.order(1, request.envelope.eid(), true).unwrap();
        let opened = board
            .open_header(
                1,
                &request.envelope,
                &keys,
                HeaderPolicy::simulator_owner(
                    [policy_id; 32],
                    [policy_id + 20; 32],
                    [policy_id + 40; 32],
                ),
            )
            .unwrap();
        board
            .authorize(
                1,
                request.envelope.eid(),
                AuthorizationEvidence {
                    statement_verified: true,
                    inclusion_verified: true,
                    midnight_height: 1,
                },
            )
            .unwrap();
        board.board().check_invariants().unwrap();
        opened
    }

    fn admit(board: &mut BoardAdapter, request: &SchnorrRequest<Secp>) {
        for node in 1..=6 {
            board
                .admit(
                    2,
                    request.envelope.eid(),
                    node,
                    Observation {
                        host_height: 10,
                        midnight_height: 1,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            board
                .board()
                .request(&request.envelope.eid())
                .unwrap()
                .state,
            State::Anchored(1)
        );
    }

    #[test]
    fn copied_slots_cannot_displace_the_first_opened_envelope() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let setup = SchnorrSetup::<Secp>::new(9, 7, 1, 1, gate, set, &mut rng).unwrap();
        let first = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let copied = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        assert_ne!(first.envelope.dd(), copied.envelope.dd());
        let mut board = adapter(&setup);
        open(&mut board, &setup, &first, 1);
        open(&mut board, &setup, &copied, 2);
        let first_id = first.envelope.eid();
        let copied_id = copied.envelope.eid();
        let slots = board
            .board()
            .request(&first_id)
            .unwrap()
            .header
            .as_ref()
            .unwrap()
            .slots
            .clone();
        assert_eq!(
            slots,
            board
                .board()
                .request(&copied_id)
                .unwrap()
                .header
                .as_ref()
                .unwrap()
                .slots
        );
        assert_eq!(
            board.admit(
                2,
                copied_id,
                1,
                Observation {
                    host_height: 10,
                    midnight_height: 1
                }
            ),
            Err(BoardError::Reducer(SplitError::SlotTaken))
        );
        for node in 1..=3 {
            board
                .void_vote(2, copied_id, node, VoidReason::SlotTaken)
                .unwrap();
        }
        assert_eq!(
            board.board().request(&copied_id).unwrap().state,
            State::Void(VoidReason::SlotTaken)
        );
        for slot in &slots {
            assert_eq!(board.board().slot(slot), SlotState::Named(first_id));
        }
        admit(&mut board, &first);
        board.board().check_invariants().unwrap();
        board.board().check_release_invariants().unwrap();
    }

    #[test]
    fn silent_actor_stalls_and_settles_without_release() {
        let mut rng = TestRng::new();
        let leaves = vec![LeafId::new(1, vec![], 1), LeafId::new(2, vec![], 1)];
        let gate = Gate::And(leaves.iter().cloned().map(Gate::Leaf).collect());
        let setup = SchnorrSetup::<Secp>::new(9, 7, 1, 1, gate, leaves, &mut rng).unwrap();
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let eid = request.envelope.eid();
        let mut board = adapter(&setup);
        open(&mut board, &setup, &request, 1);
        for node in 1..=6 {
            board.vote_opened(2, eid, node).unwrap();
        }
        assert_eq!(
            board.board().request(&eid).unwrap().state,
            State::Collecting
        );
        assert_eq!(
            board.admit(
                2,
                eid,
                1,
                Observation {
                    host_height: 10,
                    midnight_height: 1
                }
            ),
            Err(BoardError::Reducer(SplitError::Collection))
        );
        board.stall(21, eid).unwrap();
        assert!(board.board().request(&eid).unwrap().stalled);
        for node in 1..=3 {
            board.void_vote(21, eid, node, VoidReason::Stalled).unwrap();
        }
        let settled = board.board().request(&eid).unwrap();
        assert_eq!(settled.state, State::Void(VoidReason::Stalled));
        assert_eq!(settled.settlement, Some(Settlement::UnspentFreshNullifier));
        assert!(settled.releases.is_empty());
        for slot in &settled.header.as_ref().unwrap().slots {
            assert_eq!(board.board().slot(slot), SlotState::Burned);
        }
        board.board().check_invariants().unwrap();
        board.board().check_release_invariants().unwrap();
    }

    #[test]
    fn real_release_then_expiry_keeps_the_record_pin() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let setup = SchnorrSetup::<Secp>::new(9, 7, 1, 1, gate, set, &mut rng).unwrap();
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let eid = request.envelope.eid();
        let mut board = adapter(&setup);
        let opened = open(&mut board, &setup, &request, 1);
        admit(&mut board, &request);
        let tickets = opened
            .header()
            .tickets
            .iter()
            .map(|wire| decode_ticket::<Secp>(wire))
            .collect::<line_dealing::Result<Vec<_>>>()
            .unwrap();
        let mut partials = Vec::new();
        for node in 1..=7 {
            board
                .release(
                    3,
                    eid,
                    node,
                    1,
                    1,
                    ReleaseEvidence {
                        selection_verified: true,
                        midnight_height: 1,
                        not_revoked_verified: true,
                    },
                    || check_release_tickets::<Secp>(1, &tickets, &request.context.slots),
                )
                .unwrap();
            partials.push(
                request
                    .partial(
                        node,
                        setup.transport_secrets[node as usize - 1],
                        &setup.transport_keys,
                        Label::Body {
                            variant: 1,
                            generation: 1,
                        },
                    )
                    .unwrap(),
            );
        }
        request
            .envelope
            .open_selected(&opened, 1, 1, &partials)
            .unwrap();
        assert_eq!(
            board.board().request(&eid).unwrap().state,
            State::Released {
                generation: 1,
                variant: 1
            }
        );
        board.expire(100, eid).unwrap();
        let settled = board.board().request(&eid).unwrap();
        assert_eq!(settled.state, State::Expired);
        assert_eq!(
            settled.settlement,
            Some(Settlement::Released { pin: [41; 32] })
        );
        assert_eq!(board.board().erasures().len(), 1);
        board.board().check_invariants().unwrap();
        board.board().check_release_invariants().unwrap();
    }
}

mod integration {
    use super::*;
    use k256::{ProjectivePoint, Scalar};
    use line_dealing::{
        algebra,
        hash::h,
        message::AuthProof,
        split::{
            envelope::{ContributionPayload, Envelope, OpenedHeader},
            prf,
            request::{self, board::*, CombineError, SchnorrRequest},
            schnorr::{self, Node, SchnorrSuite},
            state::{Observation, Settlement, State, VoidReason},
        },
    };

    fn open<S: SchnorrSuite>(
        setup: &SchnorrSetup<S>,
        req: &SchnorrRequest<S>,
    ) -> (BoardAdapter, OpenedHeader) {
        let n = setup.committee.n;
        let f = n - setup.committee.threshold as u16;
        let mut board = BoardAdapter::new(
            line_dealing::board::Committee { n, f },
            1,
            20,
            256,
            false,
            false,
            setup.transport_keys.clone(),
        )
        .unwrap();
        super::checkpoint(&mut board);
        board.post(1, &req.envelope).unwrap();
        board.order(2, req.envelope.eid(), true).unwrap();
        let keys = setup
            .transport_secrets
            .iter()
            .enumerate()
            .map(|(i, s)| (i as u16 + 1, *s))
            .collect::<Vec<_>>();
        let opened = board
            .open_header(
                3,
                &req.envelope,
                &keys,
                HeaderPolicy::simulator_owner([1; 32], [2; 32], [3; 32]),
            )
            .unwrap();
        let q = (n + f + 1).div_ceil(2);
        board
            .authorize(
                3,
                req.envelope.eid(),
                AuthorizationEvidence {
                    statement_verified: true,
                    inclusion_verified: true,
                    midnight_height: 10,
                },
            )
            .unwrap();
        if opened.header().actors.iter().any(|a| a.embedded.is_none()) {
            for node in 1..=q {
                board.vote_opened(3, req.envelope.eid(), node).unwrap();
            }
        }
        (board, opened)
    }
    fn admit(board: &mut BoardAdapter, eid: [u8; 32], n: u16, t: usize) {
        let q = (n + (n - t as u16) + 1).div_ceil(2);
        for node in 1..=q {
            board
                .admit(
                    4,
                    eid,
                    node,
                    Observation {
                        host_height: 100,
                        midnight_height: 10,
                    },
                )
                .unwrap();
        }
        let state = board.board().request(&eid).unwrap();
        assert!(state.admitted);
        assert_eq!(state.state, State::Anchored(1));
    }
    #[allow(clippy::too_many_arguments)]
    fn released<S: SchnorrSuite>(
        setup: &mut SchnorrSetup<S>,
        req: &SchnorrRequest<S>,
        opened: &OpenedHeader,
        board: &mut BoardAdapter,
        nodes: &mut [Node<S>],
        v: u8,
        g: u8,
        payloads: &[ContributionPayload],
    ) -> Vec<schnorr::Combined> {
        let label = prf::Label::Body {
            variant: v as u16,
            generation: g as u16,
        };
        let mut body = Vec::new();
        let mut parts = vec![vec![]; setup.l as usize];
        let tickets = opened
            .header()
            .labels()
            .iter()
            .position(|p| *p == (v, g))
            .unwrap()
            * setup.l as usize;
        let tickets = opened.header().tickets[tickets..tickets + setup.l as usize]
            .iter()
            .map(|b| request::decode_ticket::<S>(b).unwrap())
            .collect::<Vec<_>>();
        for node in nodes {
            board
                .release(
                    5 + g as u64,
                    req.envelope.eid(),
                    node.id,
                    g as u16,
                    v as u16,
                    ReleaseEvidence {
                        selection_verified: true,
                        midnight_height: 11,
                        not_revoked_verified: true,
                    },
                    || request::check_release_tickets::<S>(1, &tickets, &setup.context.slots),
                )
                .unwrap();
            body.push(
                req.partial(
                    node.id,
                    setup.transport_secrets[node.id as usize - 1],
                    &setup.transport_keys,
                    label,
                )
                .unwrap(),
            );
            for (j, p) in req
                .signature_partials(opened, v, g, node)
                .unwrap()
                .into_iter()
                .enumerate()
            {
                parts[j].push(p);
            }
        }
        assert_eq!(
            board.board().request(&req.envelope.eid()).unwrap().state,
            State::Released {
                generation: g as u16,
                variant: v as u16
            }
        );
        for (other_v, other_g) in opened.header().labels() {
            let result = req.envelope.open_selected(opened, other_v, other_g, &body);
            assert_eq!(result.is_ok(), (other_v, other_g) == (v, g));
        }
        assert_eq!(
            board.accepted_contributions(req.envelope.eid()).unwrap(),
            payloads
        );
        let combined = req
            .combine_admitted(
                board,
                opened,
                v,
                g,
                &body,
                &parts,
                &setup.committee,
                &mut setup.slots,
            )
            .unwrap();
        let selected = req.envelope.open_selected(opened, v, g, &body).unwrap();
        let messages = request::SpendVariant {
            transaction: selected.capsule.transaction.clone(),
            prevouts: selected.capsule.prevouts.clone(),
            destination: selected.capsule.destination.clone(),
        }
        .messages(S::SUITE_ID, setup.l)
        .unwrap();
        for (signature, message) in combined.iter().zip(messages) {
            S::verify(setup.key.output().unwrap(), &message, &signature.signature).unwrap();
        }
        board.board().check_invariants().unwrap();
        board.board().check_release_invariants().unwrap();
        combined
    }
    fn finish<S: SchnorrSuite>(
        setup: &SchnorrSetup<S>,
        req: &SchnorrRequest<S>,
        board: &mut BoardAdapter,
    ) {
        let hdr = (1..=setup.committee.threshold as u16)
            .map(|i| {
                req.header_partial(
                    i,
                    setup.transport_secrets[i as usize - 1],
                    &setup.transport_keys,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let z = prf::combine(&hdr, setup.committee.threshold).unwrap();
        let cipher = prf::final_key(z)
            .unwrap()
            .encrypt(&[77; 32], &req.envelope.eid())
            .unwrap();
        let digest = h("SL1/final-ciphertext", &cipher);
        let n = setup.committee.n;
        let f = n - setup.committee.threshold as u16;
        for node in 1..=(n + f + 1).div_ceil(2) {
            board
                .final_vote(9, req.envelope.eid(), node, digest)
                .unwrap();
        }
        assert_eq!(
            board.board().request(&req.envelope.eid()).unwrap().state,
            State::Final(digest)
        );
        assert_eq!(
            board
                .board()
                .request(&req.envelope.eid())
                .unwrap()
                .settlement,
            Some(Settlement::Successor(digest))
        );
    }
    #[test]
    fn bip340_two_generations_both_committees() {
        for (n, t) in [(9, 7), (17, 12)] {
            let mut rng = TestRng::new();
            let (gate, set) = single();
            let mut setup = SchnorrSetup::<Secp>::new(n, t, 8, 2, gate, set, &mut rng).unwrap();
            let req = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
            let (mut board, opened) = open(&setup, &req);
            admit(&mut board, req.envelope.eid(), n, t);
            let mut nodes = (1..=n).map(|i| setup.node(i).unwrap()).collect::<Vec<_>>();
            let first = released(&mut setup, &req, &opened, &mut board, &mut nodes, 1, 1, &[]);
            for node in 1..=(n + (n - t as u16) + 1).div_ceil(2) {
                board
                    .anchor(
                        7,
                        req.envelope.eid(),
                        2,
                        node,
                        Observation {
                            host_height: 110,
                            midnight_height: 11,
                        },
                        true,
                    )
                    .unwrap();
            }
            let second = released(&mut setup, &req, &opened, &mut board, &mut nodes, 8, 2, &[]);
            assert_ne!(first[0].signature, second[0].signature);
            finish(&setup, &req, &mut board);
        }
    }
    #[test]
    fn ed25519_single_user() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let mut setup = SchnorrSetup::<Edwards>::new(9, 7, 1, 1, gate, set, &mut rng).unwrap();
        let req = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let (mut board, opened) = open(&setup, &req);
        admit(&mut board, req.envelope.eid(), 9, 7);
        let mut nodes = (1..=9).map(|i| setup.node(i).unwrap()).collect::<Vec<_>>();
        released(&mut setup, &req, &opened, &mut board, &mut nodes, 1, 1, &[]);
        finish(&setup, &req, &mut board);
    }
    fn multi(gate: Gate, set: Vec<LeafId>, embed: bool) {
        let mut rng = TestRng::new();
        let mut setup = SchnorrSetup::<Secp>::new(9, 7, 8, 2, gate, set, &mut rng).unwrap();
        let mut draft = setup.build(&mut rng).unwrap();
        let last = setup.set.len() - 1;
        if embed {
            draft
                .embed(
                    last as u8,
                    setup.pools.get_mut(&setup.set[last]).unwrap(),
                    &mut rng,
                )
                .unwrap();
        }
        let req = draft.finish(&mut rng).unwrap();
        let (mut board, opened) = open(&setup, &req);
        assert_eq!(
            board.board().request(&req.envelope.eid()).unwrap().state,
            State::Collecting
        );
        let mut payloads = Vec::new();
        for position in 1..=last as u8 {
            if embed && position == last as u8 {
                continue;
            }
            let payload = req
                .actor_contribute(
                    position,
                    &setup.actor_secrets[&position],
                    setup.pools.get_mut(&setup.set[position as usize]).unwrap(),
                    3,
                    22,
                    &mut rng,
                )
                .unwrap();
            let (frame, _) = request::contribution_frame(
                opened.header(),
                payload.clone(),
                &setup.transport_keys,
                7,
                1,
                100,
                &mut rng,
            )
            .unwrap();
            let keys = setup
                .transport_secrets
                .iter()
                .enumerate()
                .map(|(i, s)| (i as u16 + 1, *s))
                .collect::<Vec<_>>();
            board
                .open_contribution(3, &frame, &keys, &req.envelope, &opened, true)
                .unwrap();
            payloads.push(payload);
        }
        admit(&mut board, req.envelope.eid(), 9, 7);
        let mut nodes = (1..=9).map(|i| setup.node(i).unwrap()).collect::<Vec<_>>();
        released(
            &mut setup, &req, &opened, &mut board, &mut nodes, 2, 1, &payloads,
        );
        finish(&setup, &req, &mut board);
        for pool in setup.pools.values() {
            assert_eq!(pool.unused(), 0);
        }
    }
    #[test]
    fn two_actor_and_with_contrib_frame() {
        let ids = (1..=2)
            .map(|i| LeafId::new(i, vec![], 1))
            .collect::<Vec<_>>();
        multi(
            Gate::And(ids.iter().cloned().map(Gate::Leaf).collect()),
            ids,
            false,
        );
    }
    #[test]
    fn embedded_and_framed_and_and_two_of_three() {
        let ids = (1..=3)
            .map(|i| LeafId::new(i, vec![], 1))
            .collect::<Vec<_>>();
        multi(
            Gate::And(ids.iter().cloned().map(Gate::Leaf).collect()),
            ids,
            true,
        );
        let init = LeafId::new(1, vec![], 1);
        let group = (1..=3)
            .map(|i| LeafId::new(2, vec![], i))
            .collect::<Vec<_>>();
        for subset in [[0, 1], [0, 2], [1, 2]] {
            multi(
                Gate::And(vec![
                    Gate::Leaf(init.clone()),
                    Gate::Threshold {
                        k: 2,
                        children: group.iter().cloned().map(Gate::Leaf).collect(),
                    },
                ]),
                vec![
                    init.clone(),
                    group[subset[0]].clone(),
                    group[subset[1]].clone(),
                ],
                true,
            );
        }
    }
    #[test]
    fn bitcoin_capsule_roundtrip_preserves_txid_order_and_sighash() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let setup = SchnorrSetup::<Secp>::new(9, 7, 1, 2, gate, set, &mut rng).unwrap();
        let host = &setup.variants[0];
        let mut tx = request::decode_bitcoin(&host.transaction, &host.prevouts, 2).unwrap();
        tx.inputs[0].outpoint.txid = std::array::from_fn(|i| i as u8);
        let encoded = request::SpendVariant::bitcoin(&tx).unwrap();
        let decoded = request::decode_bitcoin(&encoded.transaction, &encoded.prevouts, 2).unwrap();
        assert_eq!(decoded.inputs, tx.inputs);
        assert_eq!(decoded.sighashes().unwrap(), tx.sighashes().unwrap());
    }
    fn release_fault_case(
        setup: &SchnorrSetup<Secp>,
        req: &SchnorrRequest<Secp>,
        opened: &OpenedHeader,
        board: &mut BoardAdapter,
    ) {
        let tickets = opened.header().tickets[..setup.l as usize]
            .iter()
            .map(|b| request::decode_ticket::<Secp>(b).unwrap())
            .collect::<Vec<_>>();
        for node in 1..=9 {
            board
                .release(
                    6,
                    req.envelope.eid(),
                    node,
                    1,
                    1,
                    ReleaseEvidence {
                        selection_verified: true,
                        midnight_height: 11,
                        not_revoked_verified: true,
                    },
                    || request::check_release_tickets::<Secp>(1, &tickets, &setup.context.slots),
                )
                .unwrap();
        }
    }
    fn void_initiator(board: &mut BoardAdapter, eid: [u8; 32]) {
        board
            .attributed_failure(
                8,
                AttributedFailure {
                    eid,
                    party: ResponsibleParty::Initiator,
                    reason: VoidReason::FailedContribution,
                },
                true,
            )
            .unwrap();
        assert_eq!(board.failures()[0].party, ResponsibleParty::Initiator);
        assert_eq!(
            board.board().request(&eid).unwrap().state,
            State::Void(VoidReason::FailedContribution)
        );
        assert_eq!(
            board.board().request(&eid).unwrap().settlement,
            Some(Settlement::Released { pin: [3; 32] })
        );
    }
    #[test]
    fn bad_initiator_scalar_names_initiator_and_voids() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let mut setup = SchnorrSetup::<Secp>::new(9, 7, 1, 1, gate, set, &mut rng).unwrap();
        let mut draft = setup.build(&mut rng).unwrap();
        draft.bodies[0][0] += Scalar::ONE;
        let req = draft.finish(&mut rng).unwrap();
        let (mut board, opened) = open(&setup, &req);
        admit(&mut board, req.envelope.eid(), 9, 7);
        release_fault_case(&setup, &req, &opened, &mut board);
        let body = (1..=9)
            .map(|i| {
                req.partial(
                    i,
                    setup.transport_secrets[i as usize - 1],
                    &setup.transport_keys,
                    prf::Label::Body {
                        variant: 1,
                        generation: 1,
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let parts = (1..=9)
            .map(|i| {
                req.signature_partials(&opened, 1, 1, &mut setup.node(i).unwrap())
                    .unwrap()
                    .remove(0)
            })
            .collect::<Vec<_>>();
        assert!(
            matches!(req.combine(&opened,1,1,&body,&[parts],&[],&setup.committee,&mut setup.slots),Err(CombineError::Initiator(id)) if id==setup.set[0])
        );
        void_initiator(&mut board, req.envelope.eid());
    }
    #[test]
    fn bad_signature_partial_is_dropped_and_retried() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let mut setup = SchnorrSetup::<Secp>::new(9, 7, 1, 1, gate, set, &mut rng).unwrap();
        let req = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let (board, opened) = open(&setup, &req);
        let body = (1..=9)
            .map(|i| {
                req.partial(
                    i,
                    setup.transport_secrets[i as usize - 1],
                    &setup.transport_keys,
                    prf::Label::Body {
                        variant: 1,
                        generation: 1,
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut parts = (1..=9)
            .map(|i| {
                req.signature_partials(&opened, 1, 1, &mut setup.node(i).unwrap())
                    .unwrap()
                    .remove(0)
            })
            .collect::<Vec<_>>();
        parts[0].value += Scalar::ONE;
        assert!(matches!(
            req.combine_admitted(
                &board,
                &opened,
                1,
                1,
                &body,
                std::slice::from_ref(&parts),
                &setup.committee,
                &mut setup.slots
            ),
            Err(CombineError::Invalid(line_dealing::Error::Context))
        ));
        let result = req
            .combine(
                &opened,
                1,
                1,
                &body,
                &[parts],
                &[],
                &setup.committee,
                &mut setup.slots,
            )
            .unwrap();
        assert_eq!(result[0].rejected_partials, vec![1]);
        assert!(setup.slots.slots[&1].cached_nodes() > 0);
    }
    #[test]
    fn wrong_contribution_key_requires_proofs_then_names_initiator_and_voids() {
        let mut rng = TestRng::new();
        let ids = (1..=2)
            .map(|i| LeafId::new(i, vec![], 1))
            .collect::<Vec<_>>();
        let mut setup = SchnorrSetup::<Secp>::new(
            9,
            7,
            1,
            1,
            Gate::And(ids.iter().cloned().map(Gate::Leaf).collect()),
            ids,
            &mut rng,
        )
        .unwrap();
        // Independent deterministic wallet stream reveals only this malicious
        // test dealer's two secrets, allowing an authentically proved bad header.
        let mut wallet_rng = TestRng::new();
        let mut probe_rng = TestRng::new();
        let master = algebra::random_nonzero(&mut probe_rng);
        let ephemeral = algebra::random_nonzero(&mut probe_rng);
        let mut draft = setup.build(&mut wallet_rng).unwrap();
        draft
            .embed(
                1,
                setup.pools.get_mut(&setup.set[1]).unwrap(),
                &mut wallet_rng,
            )
            .unwrap();
        let mut req = draft.finish(&mut wallet_rng).unwrap();
        let hdr = (1..=7)
            .map(|i| {
                req.header_partial(
                    i,
                    setup.transport_secrets[i as usize - 1],
                    &setup.transport_keys,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let opened = req.envelope.open_header(&hdr).unwrap();
        let mut header = opened.header().clone();
        header.contribution_keys[0] += ProjectivePoint::GENERATOR;
        let z = prf::evaluate(master, &req.envelope.dd(), prf::Label::Hdr).unwrap();
        let ciphertext = prf::header_key(z)
            .unwrap()
            .encrypt(&header.encode().unwrap(), &req.envelope.dd())
            .unwrap();
        let proof_start = 96 + 7 * 33 + 9 * 32 + 33 + line_dealing::split::envelope::LAYOUT_SIZE;
        let header_start = proof_start + 196;
        let mut wire = req.envelope.as_bytes().to_vec();
        wire[header_start..header_start + ciphertext.len()].copy_from_slice(&ciphertext);
        let mut masked = wire.clone();
        masked[46..78].fill(0);
        masked.drain(proof_start..proof_start + 196);
        let hd = h("SL1/hd", &masked);
        let eid = h(
            "SL1/eid",
            &[hd.as_slice(), &req.envelope.public().auth_ref].concat(),
        );
        let proof = AuthProof::create(
            &eid,
            &wire[96 + 7 * 33..96 + 7 * 33 + 9 * 32],
            ephemeral,
            master,
            ProjectivePoint::GENERATOR,
            None,
            &mut rng,
        )
        .unwrap();
        wire[proof_start..proof_start + 196].copy_from_slice(&proof.encode().unwrap());
        req.envelope = Envelope::decode(&wire, 9, 7).unwrap();
        req.envelope
            .verify_public(&setup.transport_keys, 7, 1, 0)
            .unwrap();
        let (mut board, opened) = open(&setup, &req);
        admit(&mut board, req.envelope.eid(), 9, 7);
        release_fault_case(&setup, &req, &opened, &mut board);
        let label = prf::Label::Body {
            variant: 1,
            generation: 1,
        };
        let parts = (1..=9)
            .map(|i| {
                req.partial(
                    i,
                    setup.transport_secrets[i as usize - 1],
                    &setup.transport_keys,
                    label,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            req.open_selected_with_proofs(&opened, 1, 1, &parts, |_| None),
            Err(CombineError::Invalid(line_dealing::Error::Threshold))
        ));
        let error = req.open_selected_with_proofs(&opened, 1, 1, &parts, |p| {
            Some(
                prf::prove(
                    req.envelope
                        .decrypt_share(
                            p.index,
                            setup.transport_secrets[p.index as usize - 1],
                            &setup.transport_keys,
                        )
                        .unwrap(),
                    p.index,
                    &req.envelope.dd(),
                    label,
                    &mut rng,
                )
                .unwrap(),
            )
        });
        assert!(matches!(error,Err(CombineError::Initiator(id)) if id==setup.set[0]));
        void_initiator(&mut board, req.envelope.eid());
    }
}

mod review_regressions {
    use super::{single, TestRng};
    use line_dealing::{
        split::{
            access::{Gate, LeafId},
            envelope::OpenedHeader,
            group::{Edwards, Secp},
            request::{check_release_tickets, decode_ticket, SchnorrRequest, SchnorrSetup},
        },
        Error,
    };

    fn open(setup: &SchnorrSetup<Secp>, request: &SchnorrRequest<Secp>) -> OpenedHeader {
        let partials = (1..=3)
            .map(|node| {
                request
                    .header_partial(
                        node,
                        setup.transport_secrets[node as usize - 1],
                        &setup.transport_keys,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        request.envelope.open_header(&partials).unwrap()
    }

    #[test]
    fn malformed_public_header_and_capsule_return_errors() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let setup = SchnorrSetup::<Secp>::new(4, 3, 1, 1, gate, set, &mut rng).unwrap();
        let draft = setup.build(&mut rng).unwrap();
        let mut header = draft.header.clone();
        header.tickets.clear();
        assert!(draft
            .context
            .reconstruct(&header, &draft.capsules, 1)
            .is_err());
        header = draft.header.clone();
        header.slots.clear();
        assert!(draft
            .context
            .reconstruct(&header, &draft.capsules, 1)
            .is_err());
        let mut capsules = draft.capsules.clone();
        capsules[0].initiator = 9;
        assert!(draft
            .context
            .reconstruct(&draft.header, &capsules, 1)
            .is_err());
    }

    #[test]
    fn wrong_actor_pool_is_rejected_before_consumption() {
        let mut rng = TestRng::new();
        let leaves = (1..=3)
            .map(|id| LeafId::new(id, vec![], 1))
            .collect::<Vec<_>>();
        let gate = Gate::And(leaves.iter().cloned().map(Gate::Leaf).collect());
        let mut setup =
            SchnorrSetup::<Secp>::new(4, 3, 2, 1, gate, leaves.clone(), &mut rng).unwrap();
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let wrong_pool = setup.pools.get_mut(&leaves[2]).unwrap();
        let unused = wrong_pool.unused();
        assert!(request
            .actor_contribute(1, &setup.actor_secrets[&1], wrong_pool, 1, 20, &mut rng)
            .is_err());
        assert_eq!(wrong_pool.unused(), unused);
        let mut draft = setup.build(&mut rng).unwrap();
        let wrong_pool = setup.pools.get_mut(&leaves[1]).unwrap();
        let unused = wrong_pool.unused();
        assert!(draft.embed(2, wrong_pool, &mut rng).is_err());
        assert_eq!(wrong_pool.unused(), unused);
        // The first capsule matches position 2. A different variant does not.
        draft.capsules[1].actors.swap(0, 1);
        let expected_pool = setup.pools.get_mut(&leaves[2]).unwrap();
        let unused = expected_pool.unused();
        assert!(draft.embed(2, expected_pool, &mut rng).is_err());
        assert_eq!(expected_pool.unused(), unused);
    }

    #[test]
    fn foreign_opened_header_does_not_consume_signature_slots() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let setup = SchnorrSetup::<Secp>::new(4, 3, 1, 1, gate, set, &mut rng).unwrap();
        let first = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let other = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let first_header = open(&setup, &first);
        let other_header = open(&setup, &other);
        let mut node = setup.node(1).unwrap();
        assert!(first
            .signature_partials(&other_header, 1, 1, &mut node)
            .is_err());
        assert!(first
            .signature_partials(&first_header, 1, 1, &mut node)
            .is_ok());
    }

    #[test]
    fn wrong_node_epoch_and_suite_do_not_consume_signature_slots() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let setup = SchnorrSetup::<Secp>::new(4, 3, 1, 1, gate, set, &mut rng).unwrap();
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let opened = open(&setup, &request);
        let mut node = setup.node(1).unwrap();
        node.epoch = 2;
        assert!(request
            .signature_partials(&opened, 1, 1, &mut node)
            .is_err());
        node.epoch = 1;
        let (gate, set) = single();
        let ed_setup = SchnorrSetup::<Edwards>::new(4, 3, 1, 1, gate, set, &mut rng).unwrap();
        let ed_request = ed_setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let partials = (1..=3)
            .map(|id| {
                ed_request
                    .header_partial(
                        id,
                        ed_setup.transport_secrets[id as usize - 1],
                        &ed_setup.transport_keys,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let ed_opened = ed_request.envelope.open_header(&partials).unwrap();
        let mistyped = SchnorrRequest::<Secp> {
            envelope: ed_request.envelope,
            used_bytes: ed_request.used_bytes,
            context: request.context.clone(),
        };
        assert!(mistyped
            .signature_partials(&ed_opened, 1, 1, &mut node)
            .is_err());
        assert!(request.signature_partials(&opened, 1, 1, &mut node).is_ok());
    }

    #[test]
    fn release_ticket_batch_rejects_empty_zero_and_duplicate_slots() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let setup = SchnorrSetup::<Secp>::new(4, 3, 1, 1, gate, set, &mut rng).unwrap();
        let draft = setup.build(&mut rng).unwrap();
        let ticket = decode_ticket::<Secp>(&draft.header.tickets[0]).unwrap();
        assert_eq!(
            check_release_tickets::<Secp>(1, &[], &setup.context.slots),
            Err(Error::Nonce)
        );
        assert_eq!(
            check_release_tickets::<Secp>(
                1,
                &[ticket.clone(), ticket.clone()],
                &setup.context.slots
            ),
            Err(Error::Nonce)
        );
        let mut zero = ticket;
        zero.slot = 0;
        assert_eq!(
            check_release_tickets::<Secp>(1, &[zero], &setup.context.slots),
            Err(Error::Nonce)
        );
    }
}

mod actor_policy_regression {
    use super::TestRng;
    use line_dealing::{
        split::{
            access::{Gate, LeafId},
            group::Secp,
            request::SchnorrSetup,
        },
        Error,
    };

    #[test]
    fn rejecting_actor_policy_preserves_every_nonce() {
        let mut rng = TestRng::new();
        let leaves = (1..=2)
            .map(|id| LeafId::new(id, vec![], 1))
            .collect::<Vec<_>>();
        let gate = Gate::And(leaves.iter().cloned().map(Gate::Leaf).collect());
        let mut setup =
            SchnorrSetup::<Secp>::new(4, 3, 2, 1, gate, leaves.clone(), &mut rng).unwrap();
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let pool = setup.pools.get_mut(&leaves[1]).unwrap();
        let unused = pool.unused();
        let result = request.actor_contribute_with_policy(
            1,
            &setup.actor_secrets[&1],
            pool,
            1,
            20,
            &mut rng,
            |capsules| {
                assert_eq!(capsules.len(), 2);
                assert!(capsules
                    .iter()
                    .all(|capsule| !capsule.transaction.is_empty()));
                Err(Error::Context)
            },
        );
        assert!(matches!(result, Err(Error::Context)));
        assert_eq!(pool.unused(), unused);
        request
            .actor_contribute_with_policy(
                1,
                &setup.actor_secrets[&1],
                pool,
                1,
                20,
                &mut rng,
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(pool.unused(), 0);
    }
}

mod ecdsa_integration {
    use k256::ProjectivePoint;
    use line_dealing::{
        hash::h,
        split::{
            prf,
            request::{
                board::{
                    AuthorizationEvidence, BoardAdapter, BoardError, HeaderPolicy, ReleaseEvidence,
                },
                SpendVariant,
            },
            state::{Observation, Settlement, State},
        },
        Error,
    };

    #[allow(dead_code)]
    mod support {
        include!("../benches/support/mod.rs");
    }

    #[test]
    fn p2wpkh_k3_l2_reaches_final_with_selected_signatures() {
        let (mut request, secrets) = support::ecdsa(9, 0);
        let keys = secrets
            .iter()
            .map(|secret| ProjectivePoint::GENERATOR * secret)
            .collect::<Vec<_>>();
        let node_keys = secrets
            .iter()
            .take(7)
            .enumerate()
            .map(|(i, secret)| (i as u16 + 1, *secret))
            .collect::<Vec<_>>();
        let eid = request.envelope.eid();
        let mut board = BoardAdapter::new(
            line_dealing::board::Committee { n: 9, f: 2 },
            1,
            20,
            256,
            false,
            false,
            keys,
        )
        .unwrap();
        board.post(1, &request.envelope).unwrap();
        board.order(2, eid, true).unwrap();

        // ECDSA source-root membership is a mandatory caller-supplied check.
        // The simulator's source is exactly the six installed slot records.
        let mut policy = HeaderPolicy::simulator_owner([71; 32], [72; 32], [73; 32]);
        assert!(matches!(
            board.open_header(3, &request.envelope, &node_keys, policy.clone()),
            Err(BoardError::TicketMembership)
        ));
        let installed = (1..=3)
            .flat_map(|variant| (0..2).map(move |input| (variant, input)))
            .map(|(variant, input)| request.slot_record(variant, input).unwrap().slot)
            .collect::<Vec<_>>();
        policy.ticket_membership = (1..=3)
            .flat_map(|variant| (0..2).map(move |input| (variant, input)))
            .map(|(variant, input)| {
                installed.contains(&request.ticket(variant, input).unwrap().slot)
            })
            .collect();
        assert_eq!(policy.ticket_membership, vec![true; 6]);
        let opened = board
            .open_header(3, &request.envelope, &node_keys, policy)
            .unwrap();
        assert_eq!(opened.header().tickets.len(), 6);
        assert!(opened
            .header()
            .tickets
            .iter()
            .all(|ticket| ticket.len() == 36));
        let translated = board
            .board()
            .request(&eid)
            .unwrap()
            .header
            .as_ref()
            .unwrap();
        assert!(translated
            .tickets
            .iter()
            .all(|ticket| ticket.in_source_root));
        assert_eq!(board.board().request(&eid).unwrap().state, State::Opened);
        board
            .authorize(
                3,
                eid,
                AuthorizationEvidence {
                    statement_verified: true,
                    inclusion_verified: true,
                    midnight_height: 10,
                },
            )
            .unwrap();
        for node in 1..=6 {
            board
                .admit(
                    4,
                    eid,
                    node,
                    Observation {
                        host_height: 100,
                        midnight_height: 10,
                    },
                )
                .unwrap();
        }
        assert!(board.board().request(&eid).unwrap().admitted);
        assert_eq!(
            board.board().request(&eid).unwrap().state,
            State::Anchored(1)
        );

        let variant = 2;
        let mut body_partials = Vec::new();
        let mut signing_partials = vec![Vec::new(), Vec::new()];
        for (node, secret) in &node_keys {
            // Board generation 1 selects ECDSA envelope generation 0.
            board
                .release(
                    5,
                    eid,
                    *node,
                    1,
                    variant,
                    ReleaseEvidence {
                        selection_verified: true,
                        midnight_height: 11,
                        not_revoked_verified: true,
                    },
                    || {
                        for input in 0..2 {
                            let ticket = request.ticket(variant as u8, input)?;
                            let wire = &opened.header().tickets[(variant as usize - 1) * 2 + input];
                            if wire[..4] != (ticket.slot as u32).to_be_bytes()
                                || wire[4..] != ticket.hash
                                || request.slot_record(variant as u8, input)?.slot != ticket.slot
                            {
                                return Err(Error::Context);
                            }
                        }
                        Ok(())
                    },
                )
                .unwrap();
            body_partials.push(request.body_partial(*node, *secret, variant as u8).unwrap());
            for (input, partial) in request
                .signature_partials(variant as u8, *node)
                .unwrap()
                .into_iter()
                .enumerate()
            {
                signing_partials[input].push(partial);
            }
        }
        assert_eq!(
            board.board().request(&eid).unwrap().state,
            State::Released {
                generation: 1,
                variant
            }
        );
        for (other_variant, generation) in opened.header().labels() {
            assert_eq!(
                request
                    .envelope
                    .open_selected(&opened, other_variant, generation, &body_partials)
                    .is_ok(),
                other_variant == variant as u8
            );
        }
        let signatures = request
            .combine(&opened, variant as u8, &body_partials, &signing_partials)
            .unwrap();
        let body = request
            .envelope
            .open_selected(&opened, variant as u8, 0, &body_partials)
            .unwrap();
        let messages = SpendVariant {
            transaction: body.capsule.transaction.clone(),
            prevouts: body.capsule.prevouts.clone(),
            destination: body.capsule.destination.clone(),
        }
        .messages(1, 2)
        .unwrap();
        assert_eq!(signatures.len(), 2);
        for (signature, message) in signatures.iter().zip(messages) {
            signature
                .verify(request.public_key, &message.try_into().unwrap())
                .unwrap();
        }

        let header_partials = node_keys
            .iter()
            .map(|(node, secret)| request.header_partial(*node, *secret).unwrap())
            .collect::<Vec<_>>();
        let successor_key = prf::final_key(prf::combine(&header_partials, 7).unwrap()).unwrap();
        let successor = successor_key.encrypt(&[74; 32], &eid).unwrap();
        let digest = h("SL1/final-ciphertext", &successor);
        for node in 1..=6 {
            board.final_vote(6, eid, node, digest).unwrap();
        }
        let final_request = board.board().request(&eid).unwrap();
        assert_eq!(final_request.state, State::Final(digest));
        assert_eq!(
            final_request.settlement,
            Some(Settlement::Successor(digest))
        );
        board.board().check_invariants().unwrap();
        board.board().check_release_invariants().unwrap();
    }
}

mod release_preflight_regression {
    use super::{single, TestRng};
    use line_dealing::split::{
        group::Secp,
        request::{decode_ticket, SchnorrSetup},
    };

    #[test]
    fn missing_second_slot_does_not_consume_first_slot() {
        let mut rng = TestRng::new();
        let (gate, set) = single();
        let setup = SchnorrSetup::<Secp>::new(4, 3, 1, 2, gate, set, &mut rng).unwrap();
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let partials = (1..=3)
            .map(|id| {
                request
                    .header_partial(
                        id,
                        setup.transport_secrets[id as usize - 1],
                        &setup.transport_keys,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let opened = request.envelope.open_header(&partials).unwrap();
        let first = decode_ticket::<Secp>(&opened.header().tickets[0]).unwrap();
        let second = decode_ticket::<Secp>(&opened.header().tickets[1]).unwrap();
        let mut node = setup.node(1).unwrap();
        node.burn(second.slot);
        assert!(request
            .signature_partials(&opened, 1, 1, &mut node)
            .is_err());
        assert!(node.release(&first).is_ok());
        assert!(node.release(&first).is_err());
    }
}

mod accepted_frame_regression {
    use super::TestRng;
    use line_dealing::{
        board::Committee,
        split::{
            access::{Gate, LeafId},
            group::Secp,
            request::{
                board::{AuthorizationEvidence, BoardAdapter, HeaderPolicy},
                contribution_frame, SchnorrSetup,
            },
            state::Event,
        },
    };

    #[test]
    fn accepted_payload_tracks_first_frame_and_verified_complaints() {
        let mut rng = TestRng::new();
        let leaves = (1..=2)
            .map(|id| LeafId::new(id, vec![], 1))
            .collect::<Vec<_>>();
        let gate = Gate::And(leaves.iter().cloned().map(Gate::Leaf).collect());
        let mut setup =
            SchnorrSetup::<Secp>::new(4, 3, 2, 1, gate, leaves.clone(), &mut rng).unwrap();
        let request = setup.build(&mut rng).unwrap().finish(&mut rng).unwrap();
        let eid = request.envelope.eid();
        let mut board = BoardAdapter::new(
            Committee { n: 4, f: 1 },
            1,
            20,
            256,
            false,
            false,
            setup.transport_keys.clone(),
        )
        .unwrap();
        super::checkpoint(&mut board);
        let keys = setup
            .transport_secrets
            .iter()
            .enumerate()
            .map(|(i, secret)| (i as u16 + 1, *secret))
            .collect::<Vec<_>>();
        board.post(1, &request.envelope).unwrap();
        board.order(2, eid, true).unwrap();
        let opened = board
            .open_header(
                3,
                &request.envelope,
                &keys,
                HeaderPolicy::simulator_owner([1; 32], [2; 32], [3; 32]),
            )
            .unwrap();
        board
            .authorize(
                3,
                eid,
                AuthorizationEvidence {
                    statement_verified: true,
                    inclusion_verified: true,
                    midnight_height: 1,
                },
            )
            .unwrap();
        for node in 1..=3 {
            board.vote_opened(3, eid, node).unwrap();
        }
        let first_payload = request
            .actor_contribute(
                1,
                &setup.actor_secrets[&1],
                setup.pools.get_mut(&leaves[1]).unwrap(),
                3,
                22,
                &mut rng,
            )
            .unwrap();
        let (first_frame, _) = contribution_frame(
            opened.header(),
            first_payload.clone(),
            &setup.transport_keys,
            3,
            1,
            100,
            &mut rng,
        )
        .unwrap();
        board
            .open_contribution(3, &first_frame, &keys, &request.envelope, &opened, true)
            .unwrap();
        let mut later_payload = first_payload.clone();
        later_payload.sealed.reverse();
        assert_ne!(later_payload, first_payload);
        let (later_frame, _) = contribution_frame(
            opened.header(),
            later_payload.clone(),
            &setup.transport_keys,
            3,
            1,
            100,
            &mut rng,
        )
        .unwrap();
        board
            .open_contribution(3, &later_frame, &keys, &request.envelope, &opened, true)
            .unwrap();
        assert_eq!(
            board.board().request(&eid).unwrap().contributions.get(&1),
            Some(&first_frame.eid())
        );
        assert_eq!(
            board.accepted_contributions(eid).unwrap(),
            vec![first_payload]
        );
        board
            .apply(
                3,
                Event::ContributionComplaint {
                    frame: first_frame.eid(),
                    verified: true,
                },
            )
            .unwrap();
        assert_eq!(
            board.board().request(&eid).unwrap().contributions.get(&1),
            Some(&later_frame.eid())
        );
        assert_eq!(
            board.accepted_contributions(eid).unwrap(),
            vec![later_payload]
        );
        board
            .apply(
                3,
                Event::ContributionComplaint {
                    frame: later_frame.eid(),
                    verified: true,
                },
            )
            .unwrap();
        assert!(board.accepted_contributions(eid).unwrap().is_empty());
        board.board().check_invariants().unwrap();
    }
}

#[test]
fn intent_commitment_binds_the_grid_and_uses_a_fresh_opening() {
    use line_dealing::split::request::intent_commitment;
    let mut rng = TestRng::new();
    let (gate, set) = single();
    let setup = SchnorrSetup::<Secp>::new(9, 7, 1, 1, gate, set, &mut rng).unwrap();
    let first = setup.build(&mut rng).unwrap();
    let second = setup.build(&mut rng).unwrap();
    assert_ne!(first.header.ic, second.header.ic);
    assert_eq!(
        first.header.ic,
        intent_commitment(&setup.variants, &first.intent_opening).unwrap()
    );
    let mut changed = setup.variants.clone();
    changed[0].transaction[0] ^= 1;
    assert_ne!(
        first.header.ic,
        intent_commitment(&changed, &first.intent_opening).unwrap()
    );
}
