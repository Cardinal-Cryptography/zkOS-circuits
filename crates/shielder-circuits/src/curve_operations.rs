use core::ops::{Add, Mul, Sub};

/// Algorithm 7 https://eprint.iacr.org/2015/1060.pdf
pub fn points_add<T>(p: [T; 3], q: [T; 3], b3: T) -> [T; 3]
where
    T: Add<Output = T> + Sub<Output = T> + Mul<Output = T> + Clone,
{
    let [x1, y1, z1] = p;
    let [x2, y2, z2] = q;

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

    [x3, y3, z3]
}

/// Algorithm 9, https://eprint.iacr.org/2015/1060.pdf
pub fn point_double<T>(p: [T; 3], b3: T) -> [T; 3]
where
    T: Add<Output = T> + Sub<Output = T> + Mul<Output = T> + Clone,
{
    let [x, y, z] = p;

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

    [x3, y3, z3]
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        arithmetic::CurveExt,
        halo2curves::{group::Group, grumpkin::G1},
    };

    use crate::{
        curve_operations::{point_double, points_add},
        rng,
    };

    #[test]
    fn adding_random_points() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let expected = p + q;

        let b3 = G1::b() + G1::b() + G1::b();
        assert_eq!(
            [expected.x, expected.y, expected.z],
            points_add([p.x, p.y, p.z], [q.x, q.y, q.z], b3)
        );
    }

    #[test]
    fn doubling_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let expected = p + p;

        let b3 = G1::b() + G1::b() + G1::b();
        assert_eq!(
            [expected.x, expected.y, expected.z],
            point_double([p.x, p.y, p.z], b3)
        );
    }
}
