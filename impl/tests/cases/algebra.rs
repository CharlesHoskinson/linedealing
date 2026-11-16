use k256::{ProjectivePoint, Scalar};
use line_dealing::algebra::*;
use line_dealing::hash::*;
use sha2::{Digest, Sha256, Sha512};

#[test]
fn feldman_arbitrary_base_and_threshold() {
    let base = ProjectivePoint::GENERATOR * Scalar::from(19u64);
    let p = Polynomial::from_coefficients(vec![
        Scalar::from(42u64),
        Scalar::from(7u64),
        Scalar::from(13u64),
    ])
    .unwrap();
    let c = p.commit(base).unwrap();
    let shares: Vec<_> = [2, 5, 9]
        .into_iter()
        .map(|i| (i, p.evaluate(i).unwrap()))
        .collect();
    for (i, s) in &shares {
        assert!(c.verify(*i, *s));
    }
    assert_eq!(interpolate(&shares, 3).unwrap(), Scalar::from(42u64));
    assert!(interpolate(&shares[..2], 3).is_err());
    assert!(interpolate(&[(2, shares[0].1), (2, shares[0].1), shares[2]], 3).is_err());
    assert!(!c.verify(0, Scalar::from(42u64)));
    assert!(!c.verify(2, shares[0].1 + Scalar::ONE));
}

#[test]
fn spec_hash_is_sha512_outer_and_labels_are_injective() {
    let tag = Sha256::digest(b"LD1/enc");
    let mut outer = Sha512::new();
    outer.update(tag);
    outer.update(tag);
    outer.update(b"payload");
    assert_eq!(hq("LD1/enc", b"payload"), reduce(&outer.finalize()));
    assert_eq!(
        SlotLabel::new(2, 2, 1, 3).unwrap().bytes(),
        [2, 2, 0, 1, 0, 3, 0, 0]
    );
    assert_ne!(
        SlotLabel::new(2, 2, 1, 3).unwrap(),
        SlotLabel::new(2, 3, 1, 3).unwrap()
    );
    assert!(SlotLabel::new(2, 4, 1, 0).is_err());
    assert_ne!(
        dealing_digest(b"a", b"bc").unwrap(),
        dealing_digest(b"ab", b"c").unwrap()
    );
}

#[test]
fn strict_points_and_scalars() {
    let g = ProjectivePoint::GENERATOR;
    assert_eq!(decode_point(&encode_point(g).unwrap()).unwrap(), g);
    assert!(decode_point(&[0; 33]).is_err());
    assert!(decode_point(&[4; 33]).is_err());
    assert!(decode_scalar(&[255; 32]).is_err());
    assert!(encode_point(ProjectivePoint::IDENTITY).is_err());
}

#[test]
fn wide_hash_reduction_matches_k256_independently() {
    use k256::elliptic_curve::{bigint::U512, ops::Reduce};
    for tag_name in [
        "LD1/enc",
        "LD1/auth",
        "LD1/bind",
        "LD1/rs-enc",
        "LD1/rs-auth",
    ] {
        let tag = Sha256::digest(tag_name.as_bytes());
        let mut outer = Sha512::new();
        outer.update(tag);
        outer.update(tag);
        outer.update(b"test-vector");
        let bytes = outer.finalize();
        let expected = <Scalar as Reduce<U512>>::reduce(U512::from_be_slice(&bytes));
        assert_eq!(hq(tag_name, b"test-vector"), expected);
    }
}
