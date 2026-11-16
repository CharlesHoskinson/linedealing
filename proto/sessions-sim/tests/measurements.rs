use sessions_sim::{measurements::*, *};
#[test]
fn encoding_sizes_and_fragmentation_ss088() {
    let free = pool_measurement(10_000, PoolState::Free, 8);
    let bound = pool_measurement(10_000, PoolState::Bound, 8);
    assert_eq!(free.record, 750_127);
    assert_eq!(free.accounted_body + 92, bound.record);
    assert_eq!(bound.body, 1_070_035);
    assert_eq!(bound.record, 1_070_127);
    assert_eq!(free.accounted_body, bound.accounted_body);
    assert!(bound.record > 1_048_576 && bound.accounted_body < 2_097_152);
    assert_eq!(pool_measurement(10_000, PoolState::Burned, 8).record, 143);
    assert!(pool_measurement(10_000, PoolState::Alternating, 8).record > 143);
}
#[test]
fn restart_windows_and_different_boot_checkpoint_union_ss068() {
    for b in [1, 2, 4, 8, 16, 32, 64, 128, 256] {
        let r = restart_measurement(b);
        assert_eq!(r.sequential, b + 1);
        assert_eq!(r.account, 16);
        assert_eq!(r.voided, 1);
        assert_eq!(r.union, 2 * b + 1);
        for rate in [1, 4, 16] {
            let refusals = window_refusals(b, rate);
            assert_eq!(
                refusals,
                if b >= rate {
                    0.0
                } else {
                    1000.0 * (rate - b) as f64 / rate as f64
                }
            );
        }
    }
}
#[test]
fn fresh_share_index_reuse_is_distinct_from_nonce_reuse() {
    let mut s = Sim::new(Params::new(4, 1), 5);
    let p = Purpose::Ecdsa;
    let snap = s.snapshot();
    s.slot_put(0, p, 1, vec![7; 64]).unwrap();
    s.post_checkpoint().unwrap();
    s.slot_bind(0, p, 1, hash(b"d1")).unwrap();
    assert!(s.release(0, p, 1, hash(b"d1")));
    s.inject(Fault::CoordinatedRollback(snap));
    s.recover_all();
    s.post_checkpoint().unwrap(); // SS-124: allow a new account slot after recovery.
                                  // SS-048: a fresh dealt share still violates index uniqueness, but does not
                                  // demonstrate reuse of the first nonce share (Q-11).
    s.slot_put(0, p, 1, vec![8; 64]).unwrap();
    s.post_checkpoint().unwrap();
    s.slot_bind(0, p, 1, hash(b"d2")).unwrap();
    assert!(s.release(0, p, 1, hash(b"d2")));
    assert_eq!(s.oracle.releases[&(0, p, 1)].len(), 2);
    assert!(s.oracle.share_releases.values().all(|ds| ds.len() == 1));
    assert_eq!(s.oracle.first_shares[&(0, p, 1)], vec![7; 64]);
    let shares: Vec<_> = s
        .trace
        .iter()
        .filter_map(|e| match e {
            sessions_sim::oracle::Event::Release { share, .. } => Some(share.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(shares, vec![vec![7; 64], vec![8; 64]]);
}

#[test]
fn canonical_body_fields_tags_and_runs_ss134_ss135() {
    let mut body = Body {
        restart_mark: 9,
        ..Body::default()
    };
    body.entries.insert("z".into(), vec![3]);
    body.entries.insert("a".into(), vec![1, 2]);
    body.slots.insert(5, Slot::Free(vec![4, 5]));
    body.put_tags.insert(5, [6; 16]);
    body.slots.insert(8, Slot::Bound(vec![7], [8; 32]));
    body.put_tags.insert(8, [9; 16]);
    for i in [1, 2, 4] {
        body.slots.insert(i, Slot::Burned);
    }
    // SS-134: independently build the bytes, including variable share lengths.
    let mut expected = vec![];
    expected.extend(5u16.to_be_bytes());
    expected.extend(b"ecdsa");
    expected.extend(9u64.to_be_bytes());
    expected.extend(2u32.to_be_bytes());
    expected.extend(1u16.to_be_bytes());
    expected.extend(b"a");
    expected.extend(2u32.to_be_bytes());
    expected.extend([1, 2]);
    expected.extend(1u16.to_be_bytes());
    expected.extend(b"z");
    expected.extend(1u32.to_be_bytes());
    expected.push(3);
    expected.extend(2u32.to_be_bytes());
    expected.extend(5u64.to_be_bytes());
    expected.push(1);
    expected.extend(2u16.to_be_bytes());
    expected.extend([4, 5]);
    expected.extend([6; 16]);
    expected.extend(8u64.to_be_bytes());
    expected.push(2);
    expected.extend(1u16.to_be_bytes());
    expected.push(7);
    expected.extend([9; 16]);
    expected.extend([8; 32]);
    expected.extend(2u32.to_be_bytes());
    for (first, last) in [(1u64, 2u64), (4, 4)] {
        expected.extend(first.to_be_bytes());
        expected.extend(last.to_be_bytes());
    }
    assert_eq!(encode_body(&body, Purpose::Ecdsa, false), expected);
    assert_eq!(body.bytes(Purpose::Ecdsa), expected);
    assert_eq!(
        encode_body(&body, Purpose::Ecdsa, true).len(),
        expected.len() + 32
    );
    let mut changed = body.clone();
    changed.put_tags.insert(5, [10; 16]);
    assert_ne!(body.digest(Purpose::Ecdsa), changed.digest(Purpose::Ecdsa));
}
