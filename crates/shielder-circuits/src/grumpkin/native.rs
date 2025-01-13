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
    fn add(&self, q: PointProjective<F, C>) -> PointProjective<F, C>;
}

impl<F: Field, C: CurveExt> GroupOperations<F, C> for PointProjective<F, C> {
    fn add(&self, q: PointProjective<F, C>) -> PointProjective<F, C> {
        let b3 = C::b() + C::b() + C::b();

        let PointProjective {
            x: x_1,
            y: y_1,
            z: z_1,
            ..
        } = *self;

        let PointProjective {
            x: x_2,
            y: y_2,
            z: z_2,
            ..
        } = q;

        let t_0 = x_1 * x_2;
        // 2. t1 ← Y1 · Y2
        // 3. t2 ← Z1 · Z2
        // 4. t3 ← X1 + Y1
        // 5. t4 ← X2 + Y2
        // 6. t3 ← t3 · t4
        // 7. t4 ← t0 + t1
        // 8. t3 ← t3 − t4
        // 9. t4 ← Y1 + Z1
        // 10. X3 ← Y2 + Z2
        // 11. t4 ← t4 · X3
        // 12. X3 ← t1 + t2
        // 13. t4 ← t4 − X3
        // 14. X3 ← X1 + Z1
        // 15. Y3 ← X2 + Z2
        // 16. X3 ← X3 · Y3
        // 17. Y3 ← t0 + t2
        // 18. Y3 ← X3 − Y3
        // 19. X3 ← t0 + t0
        // 20. t0 ← X3 + t0
        // 21. t2 ← b3 · t2
        // 22. Z3 ← t1 + t2
        // 23. t1 ← t1 − t2
        // 24. Y3 ← b3 · Y3
        // 25. X3 ← t4 · Y3
        // 26. t2 ← t3 · t1
        // 27. X3 ← t2 − X3
        // 28. Y3 ← Y3 · t0
        // 29. t1 ← t1 · Z3
        // 30. Y3 ← t1 + Y3
        // 31. t0 ← t0 · t3
        // 32. Z3 ← Z3 · t4
        // 33. Z3 ← Z3 + t0

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
