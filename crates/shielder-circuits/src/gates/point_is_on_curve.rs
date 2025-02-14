use alloc::vec;

use halo2_proofs::{
    arithmetic::CurveExt,
    halo2curves::{bn256::Fr, grumpkin::G1},
    plonk::{Advice, Column, ConstraintSystem, Constraints, ErrorFront, Expression, Selector},
    poly::Rotation,
};
use macros::embeddable;

use super::copy_grumpkin_advices;
use crate::{
    column_pool::{AccessColumn, ColumnPool, ConfigPhase},
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PointIsOnCurveGate {
    pub selector: Selector,
    pub point: [Column<Advice>; 3],
}

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "PointIsOnCurveGateInput<Fr>",
    embedded = "PointIsOnCurveGateInput<crate::AssignedCell>"
)]
pub struct PointIsOnCurveGateInput<T> {
    pub point: GrumpkinPoint<T>,
}

const SELECTOR_OFFSET: i32 = 0;
const ADVICE_OFFSET: i32 = 0;
const GATE_NAME: &str = "PointIsOnCurve";

impl Gate for PointIsOnCurveGate {
    type Input = PointIsOnCurveGateInput<AssignedCell>;

    type Advice = [Column<Advice>; 3];

    /// The gate checks whether the set of coordinates stisfies the projective closure of the Grumpkin curve:
    /// y^2 * z = x^3 + a * x * z^2 + b * z^3
    fn create_gate_custom(cs: &mut ConstraintSystem<Fr>, point: Self::Advice) -> Self {
        ensure_unique_columns(&point.to_vec());
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let a = Expression::Constant(G1::a());
            let b = Expression::Constant(G1::a());

            let x = vc.query_advice(point[0], Rotation(ADVICE_OFFSET));
            let y = vc.query_advice(point[1], Rotation(ADVICE_OFFSET));
            let z = vc.query_advice(point[2], Rotation(ADVICE_OFFSET));

            Constraints::with_selector(
                vc.query_selector(selector),
                vec![(
                    "y^2 * z = x^3 + a * x * z^2 + b * z^3",
                    y.clone() * y * z.clone() - x.clone() * x.clone() * x.clone()
                        + a * x * z.clone() * z.clone()
                        + b * z.clone() * z.clone() * z,
                )],
            )
        });

        Self { selector, point }
    }

    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        PointIsOnCurveGateInput { point }: Self::Input,
    ) -> Result<(), ErrorFront> {
        synthesizer.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector
                    .enable(&mut region, SELECTOR_OFFSET as usize)?;

                copy_grumpkin_advices(
                    &point,
                    "point",
                    &mut region,
                    self.point,
                    ADVICE_OFFSET as usize,
                )?;

                Ok(())
            },
        )
    }

    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advice {
        pool.ensure_capacity(cs, 7);
        [pool.get_column(0), pool.get_column(1), pool.get_column(2)]
    }
}
