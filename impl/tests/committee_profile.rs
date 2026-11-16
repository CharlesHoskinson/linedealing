mod common;

#[test]
fn quorum_is_the_smallest_honest_intersection_quorum() {
    use line_dealing::board::Committee;
    assert_eq!(Committee { n: 9, f: 2 }.quorum(), 6);
    for f in 0..20 {
        for n in 3 * f + 1..3 * f + 8 {
            let q = Committee { n, f }.quorum();
            assert!(2 * q > usize::from(n + f));
            assert!(2 * (q - 1) <= usize::from(n + f));
            assert!(q <= usize::from(n - f));
        }
    }
}

#[test]
fn revised_owner_proof_adds_66_bytes() {
    use line_dealing::experiment::{SecpSetup, SeededRng};
    for (t, old_size) in [(3, 1395), (7, 1659)] {
        let setup = SecpSetup::new(9, t, 1, false, 99).unwrap();
        let message = setup.owner_message(&mut SeededRng::new(99)).unwrap();
        assert_eq!(message.encode().unwrap().len(), old_size + 66);
    }
}

#[test]
fn nine_node_profile_preserves_threshold_choices() {
    let mut header = common::header(1, 2, 1);
    header.n = 9;
    header.f = 2;
    header.threshold = 3;
    assert!(header.validate().is_ok());
    header.on_rotation = 1;
    header.threshold = 7;
    assert!(header.validate().is_ok());
    header.n = 6;
    assert!(header.validate().is_err());
}

#[test]
fn nine_node_t1_profile_can_transfer_its_shares() {
    use line_dealing::{
        experiment::{SecpSetup, SeededRng},
        hash::ReshareDomain,
        reshare::{NewCommittee, Subdealing},
    };
    let setup = SecpSetup::new(9, 3, 1, false, 99).unwrap();
    let mut rng = SeededRng::new(99);
    let message = setup.owner_message(&mut rng).unwrap();
    let accepted = message.step_a(&setup).unwrap();
    let shares = accepted.decrypt(1, setup.secrets[0]).unwrap();
    let label = message.deal.labels(&message.header).unwrap()[0];
    let transfer = Subdealing::create(
        ReshareDomain {
            rid: message.rid().unwrap(),
            old_epoch: 1,
            new_epoch: 2,
            dealer: 1,
        },
        label,
        &accepted.polynomials()[0],
        shares.values()[0],
        NewCommittee {
            keys: setup.keys.clone(),
            f: 2,
            threshold: 3,
        },
        common::sc("transfer-eph"),
        &mut rng,
    );
    assert!(transfer.is_ok());
    assert!(setup
        .package(&accepted)
        .unwrap()
        .with_resharing(9, 3, accepted.polynomials())
        .is_ok());
}
