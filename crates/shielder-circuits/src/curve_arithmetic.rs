use alloc::vec::Vec;
use core::ops::{Add, Mul, Sub};

use halo2_frontend::plonk::Expression;
use halo2_proofs::{
    arithmetic::{CurveExt, Field},
    halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
};
use rand::RngCore;

use crate::{AssignedCell, Value};

#[derive(Copy, Clone, Debug, PartialEq, Default)]
pub struct GrumpkinPoint<T> {
    pub x: T,
    pub y: T,
    pub z: T,
}

impl<T> GrumpkinPoint<T> {
    pub fn new(x: T, y: T, z: T) -> Self {
        Self { x, y, z }
    }
}

impl From<G1> for GrumpkinPoint<Fr> {
    fn from(p: G1) -> Self {
        GrumpkinPoint {
            x: p.x,
            y: p.y,
            z: p.z,
        }
    }
}

impl From<GrumpkinPoint<Fr>> for G1 {
    fn from(p: GrumpkinPoint<Fr>) -> Self {
        G1 {
            x: p.x,
            y: p.y,
            z: p.z,
        }
    }
}

impl From<GrumpkinPoint<AssignedCell>> for GrumpkinPoint<Value> {
    fn from(p: GrumpkinPoint<AssignedCell>) -> Self {
        GrumpkinPoint {
            x: p.x.value().copied(),
            y: p.y.value().copied(),
            z: p.z.value().copied(),
        }
    }
}

impl From<GrumpkinPoint<Fr>> for GrumpkinPoint<Value> {
    fn from(p: GrumpkinPoint<Fr>) -> Self {
        GrumpkinPoint {
            x: Value::known(p.x),
            y: Value::known(p.y),
            z: Value::known(p.z),
        }
    }
}

impl GrumpkinPoint<Fr> {
    pub fn zero() -> Self {
        Self::new(Fr::ZERO, Fr::ONE, Fr::ZERO)
    }

    pub fn random(rng: &mut impl RngCore) -> Self {
        G1::random(rng).into()
    }

    pub fn generator() -> Self {
        G1::generator().into()
    }
}

impl Sub for GrumpkinPoint<Fr> {
    type Output = GrumpkinPoint<Fr>;
    fn sub(self, other: Self) -> Self {
        let p: G1 = self.into();
        let q: G1 = other.into();
        (p - q).into()
    }
}

/// An abstraction over the scalar field of the curve.
pub trait CurveScalar:
    Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> + Clone
{
    /// Returns the parameter `b` from the curve equation added to itself 3 times.
    fn b3() -> Self;
}

impl CurveScalar for Fr {
    fn b3() -> Self {
        G1::b() + G1::b() + G1::b()
    }
}

impl CurveScalar for Value {
    fn b3() -> Self {
        Value::known(Fr::b3())
    }
}

impl CurveScalar for Expression<Fr> {
    fn b3() -> Self {
        Expression::Constant(Fr::b3())
    }
}

/// Algorithm 7 https://eprint.iacr.org/2015/1060.pdf
pub fn points_add<S: CurveScalar>(p: GrumpkinPoint<S>, q: GrumpkinPoint<S>) -> GrumpkinPoint<S> {
    let GrumpkinPoint {
        x: x1,
        y: y1,
        z: z1,
    } = p;

    let GrumpkinPoint {
        x: x2,
        y: y2,
        z: z2,
    } = q;

    let t0 = x1.clone() * x2.clone();
    let t1 = y1.clone() * y2.clone();
    let t2 = z1.clone() * z2.clone();
    let t3 = x1.clone() + y1.clone();
    let t4 = x2.clone() + y2.clone();
    let t3 = t3 * t4;
    let t4 = t0.clone() + t1.clone();
    let t3 = t3 - t4;
    let t4 = y1 + z1.clone();
    let x3 = y2 + z2.clone();
    let t4 = t4 * x3;
    let x3 = t1.clone() + t2.clone();
    let t4 = t4 - x3;
    let x3 = x1 + z1;
    let y3 = x2 + z2;
    let x3 = x3 * y3;
    let y3 = t0.clone() + t2.clone();
    let y3 = x3 - y3;
    let x3 = t0.clone() + t0.clone();
    let t0 = x3 + t0;
    let t2 = t2 * S::b3();
    let z3 = t1.clone() + t2.clone();
    let t1 = t1 - t2;
    let y3 = y3 * S::b3();
    let x3 = t4.clone() * y3.clone();
    let t2 = t3.clone() * t1.clone();
    let x3 = t2 - x3;
    let y3 = y3 * t0.clone();
    let t1 = t1 * z3.clone();
    let y3 = t1 + y3;
    let t0 = t0 * t3;
    let z3 = z3 * t4;
    let z3 = z3 + t0;

    GrumpkinPoint::new(x3, y3, z3)
}

/// Algorithm 9, https://eprint.iacr.org/2015/1060.pdf
pub fn point_double<S: CurveScalar>(p: GrumpkinPoint<S>) -> GrumpkinPoint<S> {
    let GrumpkinPoint { x, y, z } = p;

    let t0 = y.clone() * y.clone();
    let z3 = t0.clone() + t0.clone();
    let z3 = z3.clone() + z3;
    let z3 = z3.clone() + z3;
    let t1 = y.clone() * z.clone();
    let t2 = z.clone() * z;
    let t2 = t2 * S::b3();
    let x3 = t2.clone() * z3.clone();
    let y3 = t0.clone() + t2.clone();
    let z3 = t1 * z3;
    let t1 = t2.clone() + t2.clone();
    let t2 = t1 + t2;
    let t0 = t0 - t2;
    let y3 = t0.clone() * y3;
    let y3 = x3 + y3;
    let t1 = x * y;
    let x3 = t0 * t1;
    let x3 = x3.clone() + x3;

    GrumpkinPoint::new(x3, y3, z3)
}

pub fn normalize_point<T: Field>(p: GrumpkinPoint<T>) -> GrumpkinPoint<T> {
    let GrumpkinPoint { x, y, z } = p;
    let z_inv = z.invert().unwrap();
    GrumpkinPoint::new(x * z_inv, y * z_inv, T::ONE)
}

pub fn scalar_multiply<S: CurveScalar + PartialEq>(
    input: GrumpkinPoint<S>,
    scalar_bits: [S; 254],
    zero: S,
    one: S,
) -> GrumpkinPoint<S> {
    let mut result = GrumpkinPoint {
        x: zero.clone(),
        y: one.clone(),
        z: zero,
    };

    let mut doubled = input.clone();

    for bit in scalar_bits {
        if bit == one {
            result = points_add(result, doubled.clone());
        }
        doubled = point_double(doubled);
    }
    result
}

/// Converts given field element to the individual LE bit representation
///
/// panics if value is not 254 bits
pub fn field_element_to_le_bits(value: Fr) -> [Fr; 254] {
    let bits_vec = to_bits_le(value.to_repr().as_ref())
        .to_vec()
        .iter()
        .take(Fr::NUM_BITS as usize)
        .map(|&x| Fr::from(u64::from(x)))
        .collect::<Vec<Fr>>();
    bits_vec.try_into().expect("value is not 254 bits long")
}

fn to_bits_le(num: &[u8]) -> Vec<bool> {
    let len = num.len() * 8;
    let mut bits = Vec::new();
    for i in 0..len {
        let bit = num[i / 8] & (1 << (i % 8)) != 0;
        bits.push(bit);
    }
    bits
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        arithmetic::Field,
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
    };

    use super::field_element_to_le_bits;
    use crate::{
        curve_arithmetic::{
            normalize_point, point_double, points_add, scalar_multiply, GrumpkinPoint,
        },
        rng,
    };

    #[test]
    fn scalar_multiply_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let n = Fr::from_u128(3);
        let bits = field_element_to_le_bits(n);

        let expected: GrumpkinPoint<Fr> = (p + p + p).into();
        let expected: GrumpkinPoint<Fr> = normalize_point(expected);

        let result = scalar_multiply(p.into(), bits, Fr::ZERO, Fr::ONE);
        let result = normalize_point(result);

        assert_eq!(expected, result);
    }

    #[test]
    fn adding_random_points() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let expected: GrumpkinPoint<Fr> = (p + q).into();

        assert_eq!(expected, points_add(p.into(), q.into()));
    }

    #[test]
    fn doubling_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let expected: GrumpkinPoint<Fr> = (p + p).into();

        assert_eq!(expected, point_double(p.into()));
    }
}
