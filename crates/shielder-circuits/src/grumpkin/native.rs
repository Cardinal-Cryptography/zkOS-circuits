use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::{CurveExt, Field},
    halo2curves::{bn256::Fr, grumpkin::G1},
};

use crate::FieldExt;

#[derive(Clone, Copy, Debug)]
pub struct PointAffine<F: Field, C: CurveExt> {
    pub x: F,
    pub y: F,
    _c: PhantomData<C>,
}

impl<F: Field, C: CurveExt> PointAffine<F, C> {
    pub fn new(x: F, y: F) -> Self {
        PointAffine {
            x,
            y,
            _c: PhantomData,
        }
    }

    pub fn to_projective(&self) -> PointProjective<F, C> {
        PointProjective::new(self.x, self.y, F::ONE)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PointProjective<F: Field, C: CurveExt> {
    pub x: F,
    pub y: F,
    pub z: F,
    _c: PhantomData<C>,
}

impl<F: Field, C: CurveExt> PointProjective<F, C> {
    pub fn new(x: F, y: F, z: F) -> Self {
        PointProjective {
            x,
            y,
            z,
            _c: PhantomData,
        }
    }

    pub fn to_affine(&self) -> PointAffine<F, C> {
        let z_inverse = self
            .z
            .invert()
            .expect("no multiplicative inverse to the element");

        PointAffine::new(self.x.mul(z_inverse), self.y.mul(z_inverse))
    }
}

pub trait GroupOperations<F: Field, C: CurveExt> {
    fn add(&self, p: PointProjective<F, C>) -> PointProjective<F, C>;
}

impl<F: Field, C: CurveExt> GroupOperations<F, C> for PointProjective<F, C> {
    fn add(&self, p: PointProjective<F, C>) -> PointProjective<F, C> {
        todo!()
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

    use crate::grumpkin::{
        native::{PointAffine, PointProjective},
        GroupOperations,
    };

    #[test]
    fn test_coordinate_conversion() {
        let p =
            PointProjective::<Fr, G1>::new(Fr::from_u128(3), Fr::from_u128(2), Fr::from_u128(1));

        let p_affine = p.to_affine();
        let p_projective = p_affine.to_projective();

        assert_eq!(p, p_projective);
    }

    #[test]
    fn test_group_generator() {
        let g = G1::generator();

        let b = G1::b();

        let current_point = PointProjective::<Fr, G1>::new(g.x, g.y, g.z);

        let zero = PointProjective::new(Fr::one(), Fr::one(), Fr::zero());

        let p = current_point.add(zero);

        assert_eq!(p, current_point);
    }
}
