use alloc::vec;

use halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use macros::embeddable;

use super::copy_grumpkin_advices;
use crate::{
    column_pool::{AccessColumn, ColumnPool, ConfigPhase},
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ToAffineGate {
    point_projective: [Column<Advice>; 3],
    point_affine: [Column<Advice>; 2],
    selector: Selector,
}

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "ToAffineGateInput<Fr>",
    embedded = "ToAffineGateInput<crate::AssignedCell>"
)]
pub struct ToAffineGateInput<T> {
    pub point_projective: GrumpkinPoint<T>,
    pub point_affine: GrumpkinPointAffine<T>,
}

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: i32 = 0;
const GATE_NAME: &str = "To affine agte";

impl Gate for ToAffineGate {
    type Input = ToAffineGateInput<AssignedCell>;

    type Advice = (
        [Column<Advice>; 3], // projective
        [Column<Advice>; 2], // affine
        Column<Advice>,      // z_projective^-1
    );

    fn create_gate_custom(
        cs: &mut ConstraintSystem<Fr>,
        (point_projective, point_affine, z_inverse): Self::Advice,
    ) -> Self {
        ensure_unique_columns(&[point_affine.to_vec(), point_projective.to_vec()].concat());
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);

            let x_projective = vc.query_advice(point_projective[0], Rotation(ADVICE_OFFSET));
            let y_projective = vc.query_advice(point_projective[1], Rotation(ADVICE_OFFSET));
            let z_projective = vc.query_advice(point_projective[2], Rotation(ADVICE_OFFSET));

            let x_affine = vc.query_advice(point_affine[0], Rotation(ADVICE_OFFSET));
            let y_affine = vc.query_advice(point_affine[1], Rotation(ADVICE_OFFSET));

            let z_inverse = vc.query_advice(z_inverse, Rotation(ADVICE_OFFSET));
            let one = Expression::Constant(Fr::ONE);

            Constraints::with_selector(
                selector,
                vec![
                    x_affine - x_projective * z_inverse.clone(),
                    y_affine - y_projective * z_inverse.clone(),
                    z_projective * z_inverse - one,
                ],
            )
        });

        todo!()
    }

    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: Self::Input,
    ) -> Result<(), Error> {
        todo!()
    }

    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advice {
        todo!()
    }
}
