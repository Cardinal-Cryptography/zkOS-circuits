use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

use halo2_proofs::{
    arithmetic::{CurveExt, Field},
    halo2curves::{bn256::Fr, grumpkin::G1},
};

use crate::FieldExt;

// #[derive(Clone, Copy, Debug)]
// pub struct PointAffine<F: Field, C: CurveExt> {
//     pub x: F,
//     pub y: F,
//     _c: PhantomData<C>,
// }

// impl<F: Field, C: CurveExt> PointAffine<F, C> {
//     pub fn new(x: F, y: F) -> Self {
//         PointAffine {
//             x,
//             y,
//             _c: PhantomData,
//         }
//     }

//     pub fn to_projective(&self) -> PointProjective<F, C> {
//         PointProjective::new(self.x, self.y, F::ONE)
//     }
// }

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PointProjective {
    pub x: Fr,
    pub y: Fr,
    pub z: Fr,
    // _c: PhantomData<G1>,
}

impl PointProjective {
    pub fn new(x: Fr, y: Fr, z: Fr) -> Self {
        PointProjective {
            x,
            y,
            z,
            // _c: PhantomData,
        }
    }

    // pub fn to_affine(&self) -> PointAffine<F, C> {
    //     let z_inverse = self
    //         .z
    //         .invert()
    //         .expect("no multiplicative inverse to the element");

    //     PointAffine::new(self.x.mul(z_inverse), self.y.mul(z_inverse))
    // }
}

pub trait GroupOperations {
    fn add(&self, q: PointProjective) -> PointProjective;
}

impl GroupOperations for PointProjective
// where
//     <F as Sub<<<C as CurveExt>::Base as Mul<F>>::Output>>::Output:
//         Mul<<F as Add<<<C as CurveExt>::Base as Mul<F>>::Output>>::Output>,
//     <F as Mul<<F as Sub<<<C as CurveExt>::Base as Mul<F>>::Output>>::Output>>::Output:
//         Sub<<F as Mul<<<C as CurveExt>::Base as Mul<F>>::Output>>::Output>,
//     F: Add<<<C as CurveExt>::Base as std::ops::Mul<F>>::Output>
//         + Sub<<<C as CurveExt>::Base as std::ops::Mul<F>>::Output>
//         + Mul<<<C as CurveExt>::Base as std::ops::Mul<F>>::Output>
//         + Mul<<F as Sub<<<C as CurveExt>::Base as Mul<F>>::Output>>::Output>,
// <C as CurveExt>::Base: Mul<F>,
// <<C as CurveExt>::Base as Mul<F>>::Output: Mul<F>,
{
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
        arithmetic::CurveExt,
        halo2curves::{
            bn256::{Fr, G1Affine},
            ff::PrimeField,
            group::Curve,
            grumpkin::G1,
        },
    };

    use crate::grumpkin::{native::PointProjective, GroupOperations};

    // #[test]
    // fn test_coordinate_conversion() {
    //     let p =
    //         PointProjective::<Fr, G1>::new(Fr::from_u128(3), Fr::from_u128(2), Fr::from_u128(1));

    //     let p_affine = p.to_affine();
    //     let p_projective = p_affine.to_projective();

    //     assert_eq!(p, p_projective);
    // }

    #[test]
    fn test_group_generator() {
        let g = G1::generator();
        let generator = PointProjective::new(g.x, g.y, g.z);

        let zero = PointProjective::new(Fr::zero(), Fr::one(), Fr::zero());

        let p = generator.add(zero);

        assert_eq!(p, generator);
    }
}
