use crate::{Error, Result};
use k256::elliptic_curve::{
    bigint::U512,
    group::Group,
    ops::{MulByGenerator, Reduce},
    point::BatchNormalize,
    rand_core::CryptoRngCore,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    Field, PrimeField,
};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

pub fn reduce(bytes: &[u8]) -> Scalar {
    // The input is a big-endian integer, including for non-digest lengths.
    // A digest of at most 512 bits needs exactly one wide reduction.
    let first = if bytes.len() <= 64 {
        bytes.len()
    } else {
        (bytes.len() - 1) % 32 + 1
    };
    let mut wide = [0; 64];
    wide[64 - first..].copy_from_slice(&bytes[..first]);
    let mut scalar = <Scalar as Reduce<U512>>::reduce_bytes(&wide.into());
    // Each remaining full limb extends the reduced prefix by 256 bits.
    for limb in bytes[first..].as_chunks::<32>().0 {
        wide[..32].copy_from_slice(&scalar.to_bytes());
        wide[32..].copy_from_slice(limb);
        scalar = <Scalar as Reduce<U512>>::reduce_bytes(&wide.into());
    }
    scalar
}

pub(crate) fn mul_generator(scalar: Scalar) -> ProjectivePoint {
    ProjectivePoint::mul_by_generator(&scalar)
}

pub(crate) fn mul_base(base: ProjectivePoint, scalar: Scalar) -> ProjectivePoint {
    // The base is public; both scalar multiplication paths are constant time.
    if base == ProjectivePoint::GENERATOR {
        mul_generator(scalar)
    } else {
        base * scalar
    }
}

pub fn decode_scalar(bytes: &[u8; 32]) -> Result<Scalar> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).ok_or(Error::Scalar)
}

pub fn encode_point(point: ProjectivePoint) -> Result<[u8; 33]> {
    if bool::from(point.is_identity()) {
        return Err(Error::Point);
    }
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| Error::Point)
}

/// Normalize a wire point sequence with one field inversion.
pub(crate) fn encode_points(points: &[ProjectivePoint]) -> Result<Vec<[u8; 33]>> {
    // k256's slice batch inversion returns None for an empty batch.
    if points.is_empty() {
        return Ok(Vec::new());
    }
    // Identity has no wire encoding. Reject it before batch inversion, including
    // noncanonical internal zero representations returned by multiplication.
    if points.iter().any(|point| bool::from(point.is_identity())) {
        return Err(Error::Point);
    }
    <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize(points)
        .iter()
        .map(|point| {
            point
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .map_err(|_| Error::Point)
        })
        .collect()
}

pub fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    if bytes.len() != 33 || !matches!(bytes[0], 2 | 3) {
        return Err(Error::Point);
    }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| Error::Point)?;
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(Error::Point)?;
    let point = ProjectivePoint::from(point);
    if encode_point(point)?.as_slice() != bytes {
        return Err(Error::Point);
    }
    Ok(point)
}

pub fn x_bytes(point: ProjectivePoint) -> Result<[u8; 32]> {
    Ok(encode_point(point)?[1..]
        .try_into()
        .expect("fixed point width"))
}

pub fn lift_x(x: &[u8; 32]) -> Result<ProjectivePoint> {
    let mut bytes = [2; 33];
    bytes[1..].copy_from_slice(x);
    decode_point(&bytes)
}

pub fn is_odd(point: ProjectivePoint) -> Result<bool> {
    Ok(encode_point(point)?[0] == 3)
}

pub fn inverse(s: Scalar) -> Result<Scalar> {
    Option::<Scalar>::from(s.invert()).ok_or(Error::Scalar)
}

pub fn random_nonzero(rng: &mut impl CryptoRngCore) -> Scalar {
    loop {
        let s = Scalar::random(&mut *rng);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

#[derive(Clone)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    pub fn from_coefficients(coefficients: Vec<Scalar>) -> Result<Self> {
        if coefficients.is_empty() || coefficients.len() > u16::MAX as usize {
            return Err(Error::Parameters);
        }
        Ok(Self { coefficients })
    }

    pub fn random(constant: Scalar, threshold: u16, rng: &mut impl CryptoRngCore) -> Result<Self> {
        if threshold == 0 {
            return Err(Error::Threshold);
        }
        let mut coefficients = vec![constant];
        // Step A forbids identity coefficient commitments, so resample zeros.
        coefficients.extend((1..threshold).map(|_| random_nonzero(rng)));
        Self::from_coefficients(coefficients)
    }

    pub fn constant(&self) -> Scalar {
        self.coefficients[0]
    }
    pub fn threshold(&self) -> usize {
        self.coefficients.len()
    }

    pub fn evaluate(&self, node: u16) -> Result<Scalar> {
        if node == 0 {
            return Err(Error::Parameters);
        }
        let x = Scalar::from(node as u64);
        Ok(self
            .coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |v, a| v * x + a))
    }

    pub fn commit(&self, base: ProjectivePoint) -> Result<Commitment> {
        encode_point(base)?;
        let coefficients: Vec<_> = self.coefficients[1..]
            .iter()
            .map(|a| mul_base(base, *a))
            .collect();
        encode_points(&coefficients)?;
        Ok(Commitment {
            base,
            constant: mul_base(base, self.constant()),
            coefficients,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub base: ProjectivePoint,
    pub constant: ProjectivePoint,
    /// Only the nonconstant coefficients are sent on the wire.
    pub coefficients: Vec<ProjectivePoint>,
}

impl Commitment {
    pub fn evaluate(&self, node: u16) -> Result<ProjectivePoint> {
        if node == 0 {
            return Err(Error::Parameters);
        }
        let mut acc = ProjectivePoint::IDENTITY;
        for c in self.coefficients.iter().rev() {
            let point = acc + c;
            acc = ProjectivePoint::IDENTITY;
            // Only the public, at most 16-bit node index controls this loop.
            for bit in (0..u16::BITS - node.leading_zeros()).rev() {
                acc = acc.double();
                if node & (1 << bit) != 0 {
                    acc += point;
                }
            }
        }
        Ok(acc + self.constant)
    }
    pub fn verify(&self, node: u16, share: Scalar) -> bool {
        self.evaluate(node)
            .is_ok_and(|p| mul_base(self.base, share) == p)
    }
}

pub fn lagrange(nodes: &[u16]) -> Result<Vec<Scalar>> {
    if nodes.is_empty() || nodes.contains(&0) {
        return Err(Error::Threshold);
    }
    let mut result = Vec::with_capacity(nodes.len());
    for (pos, i) in nodes.iter().enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (other, j) in nodes.iter().enumerate() {
            if pos == other {
                continue;
            }
            if i == j {
                return Err(Error::Threshold);
            }
            num *= -Scalar::from(*j as u64);
            den *= Scalar::from(*i as u64) - Scalar::from(*j as u64);
        }
        result.push(num * inverse(den)?);
    }
    Ok(result)
}

pub fn interpolate(shares: &[(u16, Scalar)], threshold: usize) -> Result<Scalar> {
    if threshold == 0 || shares.len() < threshold {
        return Err(Error::Threshold);
    }
    let nodes: Vec<_> = shares.iter().map(|(i, _)| *i).collect();
    Ok(lagrange(&nodes)?
        .iter()
        .zip(shares)
        .map(|(l, (_, v))| *l * v)
        .sum())
}
