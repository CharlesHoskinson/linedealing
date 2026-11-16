//! Suite arithmetic for split-line dealing. Scalar wire encodings are big endian.
use crate::{Error, Result};
use core::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};
use k256::elliptic_curve::{
    bigint::U512,
    ops::{MulByGenerator, Reduce},
    rand_core::CryptoRngCore,
    sec1::ToEncodedPoint,
    BatchNormalize,
};
use sha2::{Digest, Sha256, Sha512};

pub trait Suite: Copy + Clone + Debug + Eq {
    type Scalar: Copy
        + Debug
        + Eq
        + k256::elliptic_curve::zeroize::Zeroize
        + Add<Output = Self::Scalar>
        + Sub<Output = Self::Scalar>
        + Mul<Output = Self::Scalar>
        + Neg<Output = Self::Scalar>;
    type Point: Copy
        + Debug
        + Eq
        + Add<Output = Self::Point>
        + Sub<Output = Self::Point>
        + Neg<Output = Self::Point>;
    const NAME: &'static str;
    const SUITE_ID: u8;
    fn scalar_zero() -> Self::Scalar;
    fn scalar_one() -> Self::Scalar;
    fn scalar_from_u64(value: u64) -> Self::Scalar;
    fn random(rng: &mut impl CryptoRngCore) -> Self::Scalar;
    fn invert(value: Self::Scalar) -> Result<Self::Scalar>;
    fn generator_mul(value: Self::Scalar) -> Self::Point;
    fn mul(point: Self::Point, scalar: Self::Scalar) -> Self::Point;
    fn identity() -> Self::Point;
    /// Trusted arithmetic points: encoding rejects identity; decoding checks subgroup.
    fn encode_point(point: Self::Point) -> Result<Vec<u8>>;
    fn decode_point(bytes: &[u8]) -> Result<Self::Point>;
    /// Validate an untrusted typed point once at a public API boundary.
    fn validate_point(point: Self::Point) -> Result<()> {
        if Self::decode_point(&Self::encode_point(point)?)? != point {
            return Err(Error::Point);
        }
        Ok(())
    }
    fn encode_points(points: &[Self::Point]) -> Result<Vec<Vec<u8>>> {
        points.iter().map(|p| Self::encode_point(*p)).collect()
    }
    fn encode_scalar(value: Self::Scalar) -> [u8; 32];
    fn decode_scalar(bytes: &[u8; 32]) -> Result<Self::Scalar>;
    /// Interpret a 512-bit integer in big-endian order, reducing once.
    fn scalar_from_wide(bytes: &[u8; 64]) -> Self::Scalar;
    fn hash_to_scalar(tag: &str, data: &[u8]) -> Self::Scalar {
        let t = Sha256::digest(tag.as_bytes());
        let mut h = Sha512::new();
        h.update(t);
        h.update(t);
        h.update(data);
        Self::scalar_from_wide(&h.finalize().into())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Secp;
impl Suite for Secp {
    type Scalar = k256::Scalar;
    type Point = k256::ProjectivePoint;
    const NAME: &'static str = "secp256k1";
    const SUITE_ID: u8 = 2;
    fn scalar_zero() -> Self::Scalar {
        k256::Scalar::ZERO
    }
    fn scalar_one() -> Self::Scalar {
        k256::Scalar::ONE
    }
    fn scalar_from_u64(value: u64) -> Self::Scalar {
        value.into()
    }
    fn random(rng: &mut impl CryptoRngCore) -> Self::Scalar {
        crate::algebra::random_nonzero(rng)
    }
    fn invert(value: Self::Scalar) -> Result<Self::Scalar> {
        crate::algebra::inverse(value)
    }
    fn generator_mul(value: Self::Scalar) -> Self::Point {
        k256::ProjectivePoint::mul_by_generator(&value)
    }
    fn mul(point: Self::Point, scalar: Self::Scalar) -> Self::Point {
        point * scalar
    }
    fn identity() -> Self::Point {
        k256::ProjectivePoint::IDENTITY
    }
    fn encode_point(point: Self::Point) -> Result<Vec<u8>> {
        Ok(crate::algebra::encode_point(point)?.to_vec())
    }
    fn decode_point(bytes: &[u8]) -> Result<Self::Point> {
        crate::algebra::decode_point(bytes)
    }
    fn validate_point(point: Self::Point) -> Result<()> {
        use k256::elliptic_curve::Group;
        // A typed k256 point is already on the prime-order curve.
        if bool::from(point.is_identity()) {
            return Err(Error::Point);
        }
        Ok(())
    }
    fn encode_points(points: &[Self::Point]) -> Result<Vec<Vec<u8>>> {
        if points.is_empty() {
            return Ok(Vec::new());
        }
        if points.iter().any(|p| *p == Self::identity()) {
            return Err(Error::Point);
        }
        let affine =
            <k256::ProjectivePoint as BatchNormalize<[k256::ProjectivePoint]>>::batch_normalize(
                points,
            );
        Ok(affine
            .iter()
            .map(|p| p.to_encoded_point(true).as_bytes().to_vec())
            .collect())
    }
    fn encode_scalar(value: Self::Scalar) -> [u8; 32] {
        value.to_bytes().into()
    }
    fn decode_scalar(bytes: &[u8; 32]) -> Result<Self::Scalar> {
        crate::algebra::decode_scalar(bytes)
    }
    fn scalar_from_wide(bytes: &[u8; 64]) -> Self::Scalar {
        <k256::Scalar as Reduce<U512>>::reduce_bytes(&(*bytes).into())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Edwards;
impl Suite for Edwards {
    type Scalar = curve25519_dalek::scalar::Scalar;
    type Point = curve25519_dalek::edwards::EdwardsPoint;
    const NAME: &'static str = "edwards25519";
    const SUITE_ID: u8 = 3;
    fn scalar_zero() -> Self::Scalar {
        Self::Scalar::ZERO
    }
    fn scalar_one() -> Self::Scalar {
        Self::Scalar::ONE
    }
    fn scalar_from_u64(value: u64) -> Self::Scalar {
        value.into()
    }
    fn random(rng: &mut impl CryptoRngCore) -> Self::Scalar {
        crate::ed25519::random_nonzero(rng)
    }
    fn invert(value: Self::Scalar) -> Result<Self::Scalar> {
        if value == Self::scalar_zero() {
            Err(Error::Scalar)
        } else {
            Ok(value.invert())
        }
    }
    fn generator_mul(value: Self::Scalar) -> Self::Point {
        curve25519_dalek::edwards::EdwardsPoint::mul_base(&value)
    }
    fn mul(point: Self::Point, scalar: Self::Scalar) -> Self::Point {
        point * scalar
    }
    fn identity() -> Self::Point {
        use curve25519_dalek::traits::Identity;
        Self::Point::identity()
    }
    fn encode_point(point: Self::Point) -> Result<Vec<u8>> {
        if point == Self::identity() {
            return Err(Error::Point);
        }
        let mut bytes = vec![0];
        bytes.extend_from_slice(point.compress().as_bytes());
        Ok(bytes)
    }
    fn decode_point(bytes: &[u8]) -> Result<Self::Point> {
        crate::ed25519::decode_point(bytes)
    }
    fn validate_point(point: Self::Point) -> Result<()> {
        use curve25519_dalek::traits::IsIdentity;
        // Typed points can contain torsion, but need no wire round trip.
        if point.is_identity() || !point.is_torsion_free() {
            return Err(Error::Point);
        }
        Ok(())
    }
    fn encode_scalar(value: Self::Scalar) -> [u8; 32] {
        crate::ed25519::encode_scalar(value)
    }
    fn decode_scalar(bytes: &[u8; 32]) -> Result<Self::Scalar> {
        crate::ed25519::decode_scalar(bytes)
    }
    fn scalar_from_wide(bytes: &[u8; 64]) -> Self::Scalar {
        let mut little = *bytes;
        little.reverse();
        Self::Scalar::from_bytes_mod_order_wide(&little)
    }
}

pub fn lagrange<S: Suite>(indices: &[u16]) -> Result<Vec<S::Scalar>> {
    if indices.is_empty()
        || indices.contains(&0)
        || indices
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != indices.len()
    {
        return Err(Error::Threshold);
    }
    let mut fractions: Vec<_> = indices
        .iter()
        .map(|i| {
            let mut numerator = S::scalar_one();
            let mut denominator = S::scalar_one();
            for j in indices {
                if i != j {
                    let x = S::scalar_from_u64(*j as u64);
                    numerator = numerator * (-x);
                    denominator = denominator * (S::scalar_from_u64(*i as u64) - x);
                }
            }
            (numerator, denominator)
        })
        .collect();
    // All denominators are nonzero because the public indices are distinct.
    // Montgomery's batch inversion uses one inversion for the entire subset.
    let mut product = S::scalar_one();
    let mut prefixes = Vec::with_capacity(fractions.len());
    for (_, denominator) in &fractions {
        prefixes.push(product);
        product = product * *denominator;
    }
    let mut inverse = S::invert(product)?;
    for ((numerator, denominator), prefix) in fractions.iter_mut().zip(prefixes).rev() {
        *numerator = *numerator * inverse * prefix;
        inverse = inverse * *denominator;
    }
    Ok(fractions.into_iter().map(|(value, _)| value).collect())
}

pub fn evaluate_scalar<S: Suite>(coefficients: &[S::Scalar], index: u16) -> Result<S::Scalar> {
    if coefficients.is_empty() || index == 0 {
        return Err(Error::Parameters);
    }
    let x = S::scalar_from_u64(index as u64);
    Ok(coefficients
        .iter()
        .rev()
        .fold(S::scalar_zero(), |v, c| v * x + *c))
}

/// Variable time only in the public node index; never a full-width scalar multiply.
pub fn mul_small<S: Suite>(mut point: S::Point, mut index: u16) -> S::Point {
    let mut result = S::identity();
    while index != 0 {
        if index & 1 == 1 {
            result = result + point;
        }
        point = point + point;
        index >>= 1;
    }
    result
}
pub fn evaluate_commitments<S: Suite>(coefficients: &[S::Point], index: u16) -> Result<S::Point> {
    if coefficients.is_empty() || index == 0 {
        return Err(Error::Parameters);
    }
    Ok(coefficients
        .iter()
        .rev()
        .fold(S::identity(), |v, c| mul_small::<S>(v, index) + *c))
}
pub fn random_polynomial<S: Suite>(
    constant: S::Scalar,
    threshold: usize,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<S::Scalar>> {
    if threshold == 0 || threshold > u16::MAX as usize {
        return Err(Error::Threshold);
    }
    let mut coefficients = vec![constant];
    coefficients.extend((1..threshold).map(|_| S::random(rng)));
    Ok(coefficients)
}
pub fn commitments<S: Suite>(coefficients: &[S::Scalar]) -> Vec<S::Point> {
    coefficients.iter().map(|c| S::generator_mul(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arithmetic<S: Suite>() {
        let c: Vec<_> = [17, 23, 41].map(S::scalar_from_u64).to_vec();
        let points = commitments::<S>(&c);
        for i in [1, 2, 9, 17, 65535] {
            assert_eq!(
                evaluate_commitments::<S>(&points, i).unwrap(),
                S::generator_mul(evaluate_scalar::<S>(&c, i).unwrap())
            );
        }
        let ids = [2, 4, 8];
        let weights = lagrange::<S>(&ids).unwrap();
        let recovered = ids
            .iter()
            .zip(weights)
            .fold(S::scalar_zero(), |acc, (i, w)| {
                acc + w * evaluate_scalar::<S>(&c, *i).unwrap()
            });
        assert_eq!(recovered, c[0]);
        assert!(lagrange::<S>(&[1, 1]).is_err());
        assert!(lagrange::<S>(&[0]).is_err());
        assert!(lagrange::<S>(&[]).is_err());
        for (point, encoded) in points.iter().zip(S::encode_points(&points).unwrap()) {
            assert_eq!(S::decode_point(&encoded).unwrap(), *point);
        }
        assert!(S::encode_point(S::identity()).is_err());
        assert!(S::decode_scalar(&[255; 32]).is_err());
        assert!(S::invert(S::scalar_zero()).is_err());
    }
    #[test]
    fn suite_arithmetic() {
        arithmetic::<Secp>();
        arithmetic::<Edwards>();
    }
    #[test]
    fn wide_reduction_matches_reference() {
        let wide = [0xa5; 64];
        assert_eq!(Secp::scalar_from_wide(&wide), crate::algebra::reduce(&wide));
        assert_eq!(
            Secp::hash_to_scalar("SL1/test", b"wide"),
            crate::hash::hq("SL1/test", b"wide")
        );
        assert_eq!(
            Edwards::hash_to_scalar("SL1/test", b"wide"),
            crate::ed25519::hq("SL1/test", b"wide")
        );
    }
    #[test]
    fn reject_edwards_torsion() {
        let mut wire = vec![0];
        wire.extend_from_slice(
            curve25519_dalek::constants::EIGHT_TORSION[1]
                .compress()
                .as_bytes(),
        );
        assert!(Edwards::decode_point(&wire).is_err());
    }
    #[test]
    fn empty_batch_encoding_is_empty() {
        assert!(Secp::encode_points(&[]).unwrap().is_empty());
        assert!(Edwards::encode_points(&[]).unwrap().is_empty());
    }
    #[test]
    fn typed_point_validation_preserves_subgroup_checks() {
        assert!(Secp::validate_point(Secp::identity()).is_err());
        assert!(Edwards::validate_point(Edwards::identity()).is_err());
        let ed_base = Edwards::generator_mul(Edwards::scalar_one());
        for torsion in curve25519_dalek::constants::EIGHT_TORSION.iter().skip(1) {
            assert!(Edwards::validate_point(*torsion).is_err());
            assert!(Edwards::validate_point(ed_base + torsion).is_err());
        }
        for value in [1, 2, 17, 255, u64::MAX] {
            assert!(
                Secp::validate_point(Secp::generator_mul(Secp::scalar_from_u64(value))).is_ok()
            );
            assert!(
                Edwards::validate_point(Edwards::generator_mul(Edwards::scalar_from_u64(value)))
                    .is_ok()
            );
        }
    }
    #[test]
    fn interpolation_recovers_every_polynomial_coefficient_basis() {
        fn check<S: Suite>() {
            for ids in [vec![65535], vec![17, 3, 65535, 1], (1..=12).rev().collect()] {
                let weights = lagrange::<S>(&ids).unwrap();
                for degree in 0..ids.len() {
                    let recovered =
                        ids.iter()
                            .zip(&weights)
                            .fold(S::scalar_zero(), |sum, (i, w)| {
                                let x = S::scalar_from_u64(u64::from(*i));
                                let power = (0..degree).fold(S::scalar_one(), |p, _| p * x);
                                sum + power * *w
                            });
                    assert_eq!(
                        recovered,
                        if degree == 0 {
                            S::scalar_one()
                        } else {
                            S::scalar_zero()
                        }
                    );
                }
            }
        }
        check::<Secp>();
        check::<Edwards>();
    }
}
