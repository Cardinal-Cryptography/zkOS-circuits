use halo2_proofs::{arithmetic::Field, halo2curves::grumpkin::G1};

use crate::FieldExt;

#[derive(Clone, Copy, Debug)]
pub struct PointAffine<F: Field> {
    pub x: F,
    pub y: F,
}

impl<F: Field> PointAffine<F> {
    pub fn new(x: F, y: F) -> Self {
        PointAffine { x, y }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PointProjective<F: Field> {
    pub x: F,
    pub y: F,
    pub z: F,
}

impl<F: Field> PointProjective<F> {
    pub fn new(x: F, y: F, z: F) -> Self {
        PointProjective { x, y, z }
    }
}

// TODO: gen

#[cfg(test)]
mod test {
    use halo2_proofs::halo2curves::{
        bn256::G1Affine,
        ff::PrimeField,
        grumpkin::{Fr, G1},
    };

    use crate::grumpkin::{
        affine_to_projective,
        native::{PointAffine, PointProjective},
        projective_to_affine,
    };

    #[test]
    fn test_coordinate_conversion() {
        let p = PointProjective {
            x: Fr::from_u128(3),
            y: Fr::from_u128(2),
            z: Fr::from_u128(1),
        };

        let p_affine = projective_to_affine(p);
        let p_projective = affine_to_projective(p_affine);

        assert_eq!(p, p_projective);
    }

    #[test]
    fn test_group_generator() {
        // let g = G1::generator();

        let g = G1Affine::generator();

        let generator = PointAffine::new(g.x, g.y);

        println!("GEN {g:?}");

        todo!();
    }
}
