use core::ops::Sub;

use halo2_proofs::halo2curves::{group::Group, grumpkin::G1};
use rand_core::RngCore;

use crate::{curve_arithmetic::curve_scalar::CurveScalar, AssignedCell, Fr, Value};

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

impl<S: CurveScalar> GrumpkinPoint<S> {
    pub fn zero() -> Self {
        Self::new(S::zero(), S::one(), S::zero())
    }
}

impl GrumpkinPoint<Fr> {
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
