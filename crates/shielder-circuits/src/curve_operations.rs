use core::ops::{Add, Mul, Sub};

use halo2_proofs::{circuit::Value, halo2curves::{bn256::Fr, grumpkin::G1}};

use crate::AssignedCell;

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

impl From<GrumpkinPoint<AssignedCell>> for GrumpkinPoint<Value<Fr>> {
    fn from(p: GrumpkinPoint<AssignedCell>) -> Self {
        GrumpkinPoint {
            x: p.x.value().copied(),
            y: p.y.value().copied(),
            z: p.z.value().copied(),
        }
    }
}

/// Algorithm 7 https://eprint.iacr.org/2015/1060.pdf
pub fn points_add<T>(p: GrumpkinPoint<T>, q: GrumpkinPoint<T>, b3: T) -> GrumpkinPoint<T>
where
    T: Add<Output = T> + Sub<Output = T> + Mul<Output = T> + Clone,
{
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
    let t2 = t2 * b3.clone();
    let z3 = t1.clone() + t2.clone();
    let t1 = t1 - t2;
    let y3 = y3 * b3;
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
pub fn point_double<T>(p: GrumpkinPoint<T>, b3: T) -> GrumpkinPoint<T>
where
    T: Add<Output = T> + Sub<Output = T> + Mul<Output = T> + Clone,
{
    let GrumpkinPoint { x, y, z } = p;

    let t0 = y.clone() * y.clone();
    let z3 = t0.clone() + t0.clone();
    let z3 = z3.clone() + z3;
    let z3 = z3.clone() + z3;
    let t1 = y.clone() * z.clone();
    let t2 = z.clone() * z;
    let t2 = t2 * b3;
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

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        arithmetic::CurveExt,
        halo2curves::{bn256::Fr, group::Group, grumpkin::G1},
    };

    use crate::{
        curve_operations::{point_double, points_add, GrumpkinPoint},
        rng,
    };

    #[test]
    fn adding_random_points() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let expected: GrumpkinPoint<Fr> = (p + q).into();

        let b3 = G1::b() + G1::b() + G1::b();
        assert_eq!(expected, points_add(p.into(), q.into(), b3));
    }

    #[test]
    fn doubling_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let expected: GrumpkinPoint<Fr> = (p + p).into();

        let b3 = G1::b() + G1::b() + G1::b();
        assert_eq!(expected, point_double(p.into(), b3));
    }
}
