use halo2_proofs::{
    arithmetic::{CurveExt, Field},
    halo2curves::{bn256::Fr, grumpkin::G1},
};

use crate::FieldExt;

// TODO : type-enforce curve (Grumpkin::G1)
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PointAffine {
    pub x: Fr,
    pub y: Fr,
}

impl PointAffine {
    pub fn new(x: Fr, y: Fr) -> Self {
        PointAffine { x, y }
    }

    pub fn to_projective(&self) -> PointProjective {
        PointProjective::new(self.x, self.y, Fr::ONE)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PointProjective {
    pub x: Fr,
    pub y: Fr,
    pub z: Fr,
}

impl PointProjective {
    pub fn new(x: Fr, y: Fr, z: Fr) -> Self {
        PointProjective { x, y, z }
    }

    pub fn to_affine(&self) -> PointAffine {
        let z_inverse = self
            .z
            .invert()
            .expect("no multiplicative inverse to the element");

        PointAffine::new(self.x.mul(&z_inverse), self.y.mul(&z_inverse))
    }
}

impl From<G1> for PointProjective {
    fn from(g1: G1) -> Self {
        PointProjective::new(g1.x, g1.y, g1.z)
    }
}

pub trait GroupOperations {
    const POINT_AT_INFINITY: Self;

    fn add(&self, q: PointProjective) -> PointProjective;

    fn is_on_curve(&self) -> bool;
}

impl GroupOperations for PointProjective {
    const POINT_AT_INFINITY: Self = PointProjective {
        x: Fr::zero(),
        y: Fr::one(),
        z: Fr::zero(),
    };

    ///
    ///
    /// Inefficient implementation
    fn is_on_curve(&self) -> bool {
        todo!()
    }

    /// Adds another point on the curve
    ///
    /// Algorithm 7 https://eprint.iacr.org/2015/1060.pdf
    fn add(&self, q: PointProjective) -> PointProjective {
        let b3 = G1::b() + G1::b() + G1::b();

        let PointProjective {
            x: x1,
            y: y1,
            z: z1,
            ..
        } = *self;

        let PointProjective {
            x: x2,
            y: y2,
            z: z2,
            ..
        } = q;

        let t0 = x1 * x2;
        let t1 = y1 * y2;
        let t2 = z1 * z2;
        let t3 = x1 + y1;
        let t4 = x2 + y2;
        let t3 = t3 * t4;
        let t4 = t0 + t1;
        let t3 = t3 - t4;
        let t4 = y1 + z1;
        let x3 = y2 + z2;
        let t4 = t4 * x3;
        let x3 = t1 + t2;
        let t4 = t4 - x3;
        let x3 = x1 + z1;
        let y3 = x2 + z2;
        let x3 = x3 * y3;
        let y3 = t0 + t2;
        let y3 = x3 - y3;
        let x3 = t0 + t0;
        let t0 = x3 + t0;
        let t2 = b3 * t2;
        let z3 = t1 + t2;
        let t1 = t1 - t2;
        let y3 = b3 * y3;
        let x3 = t4 * y3;
        let t2 = t3 * t1;
        let x3 = t2 - x3;
        let y3 = y3 * t0;
        let t1 = t1 * z3;
        let y3 = t1 + y3;
        let t0 = t0 * t3;
        let z3 = z3 * t4;
        let z3 = z3 + t0;

        PointProjective::new(x3, y3, z3)
    }
}

#[cfg(test)]
mod test {
    use halo2_proofs::{
        arithmetic::{CurveExt, Field},
        halo2curves::{
            bn256::{Fq, Fr, G1Affine},
            ff::PrimeField,
            group::{Curve, Group},
            grumpkin::G1,
        },
    };
    use once_cell::sync::Lazy;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;

    use crate::grumpkin::{native::PointProjective, GroupOperations};

    static RNG: Lazy<StdRng> =
        Lazy::new(|| StdRng::from_seed(*b"00000000000000000000100001011001"));

    #[test]
    fn coordinate_conversion() {
        let rng = RNG.clone();
        let p: PointProjective = G1::random(rng).into();

        let p_affine = p.to_affine();
        let p_projective = p_affine.to_projective();

        assert_eq!(p, p_projective);
    }

    #[test]
    fn adding_point_at_infinity() {
        let rng = RNG.clone();
        let p1: PointProjective = G1::random(rng).into();
        let p2 = p1.add(PointProjective::POINT_AT_INFINITY);
        assert_eq!(p1.to_affine(), p2.to_affine());
    }

    #[test]
    fn test_case() {
        let rng = RNG.clone();

        let zero = G1 {
            x: Fr::ZERO,
            y: Fr::ONE,
            z: Fr::ZERO,
        };

        let result = zero + zero;

        assert_eq!(result, zero);
    }

    #[test]
    fn el_gamal() {
        let rng = RNG.clone();

        // let generator = G1::generator();
        let generator = G1 {
            x: Fr::ONE,
            y: Fr::from_u128(2),
            z: Fr::ONE,
        };

        let private_key = Fq::random(rng.clone());

        let public_key = generator * private_key;

        let message = G1::random(rng.clone());

        let trapdoor = Fq::random(rng.clone());

        let shared_secret = public_key * trapdoor;

        let c1 = generator * trapdoor;
        let c2 = message + shared_secret;

        let recovered_shared_secret = c1 * private_key;

        assert_eq!(shared_secret, recovered_shared_secret);

        let recovered_message = c2 - recovered_shared_secret;

        assert_eq!(message, recovered_message);
    }
}
