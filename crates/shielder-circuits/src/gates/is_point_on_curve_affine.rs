use alloc::vec;

use halo2_proofs::{
    arithmetic::CurveExt,
    halo2curves::{bn256::Fr, grumpkin::G1},
    plonk::{Advice, Column, ConstraintSystem, Constraints, ErrorFront, Expression, Selector},
    poly::Rotation,
};
use macros::embeddable;

use super::ensure_unique_columns;
use crate::{
    column_pool::{AccessColumn, ColumnPool, ConfigPhase},
    embed::Embed,
    gates::Gate,
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IsPointOnCurveAffineGate {
    pub selector: Selector,
    pub x: Column<Advice>,
    pub y_squared: Column<Advice>,
}

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "IsPointOnCurveAffineGateInput<Fr>",
    embedded = "IsPointOnCurveAffineGateInput<crate::AssignedCell>"
)]
pub struct IsPointOnCurveAffineGateInput<T> {
    pub x: T,
    pub y_squared: T,
}

const SELECTOR_OFFSET: i32 = 0;
const ADVICE_OFFSET: i32 = 0;
const GATE_NAME: &str = "IsPointOnCurveAffine";

impl Gate for IsPointOnCurveAffineGate {
    type Input = IsPointOnCurveAffineGateInput<AssignedCell>;

    type Advice = (Column<Advice>, Column<Advice>);

    /// The gate checks whether a set of coordinates satisfies the projective closure of the Grumpkin curve:
    /// y^2 = x^3 - 17
    fn create_gate_custom(cs: &mut ConstraintSystem<Fr>, (x, y_squared): Self::Advice) -> Self {
        ensure_unique_columns(&[x, y_squared]);
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let b = Expression::Constant(G1::b());
            let x = vc.query_advice(x, Rotation(ADVICE_OFFSET));
            let y_squared = vc.query_advice(y_squared, Rotation(ADVICE_OFFSET));

            Constraints::with_selector(
                vc.query_selector(selector),
                vec![(
                    "y^2 = x^3 - 17",
                    y_squared - x.clone() * x.clone() * x.clone() - b,
                )],
            )
        });

        Self {
            selector,
            x,
            y_squared,
        }
    }

    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        IsPointOnCurveAffineGateInput { x, y_squared }: Self::Input,
    ) -> Result<(), ErrorFront> {
        synthesizer.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector
                    .enable(&mut region, SELECTOR_OFFSET as usize)?;

                x.copy_advice(|| "x", &mut region, self.x, ADVICE_OFFSET as usize)?;
                y_squared.copy_advice(
                    || "y^2",
                    &mut region,
                    self.y_squared,
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
        pool.ensure_capacity(cs, 2);
        (pool.get_column(0), pool.get_column(1))
    }
}

#[cfg(test)]
mod tests {

    use alloc::{vec, vec::Vec};

    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, ff::PrimeField},
    };

    use super::{IsPointOnCurveAffineGate, IsPointOnCurveAffineGateInput};
    use crate::{curve_arithmetic::GrumpkinPointAffine, gates::test_utils::OneGateCircuit, rng};

    fn input(x: Fr, y_squared: Fr) -> IsPointOnCurveAffineGateInput<Fr> {
        IsPointOnCurveAffineGateInput { x, y_squared }
    }

    fn verify(input: IsPointOnCurveAffineGateInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = OneGateCircuit::<IsPointOnCurveAffineGate, _>::new(input);
        MockProver::run(4, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn is_random_point_on_curve() {
        let mut rng = rng();
        let GrumpkinPointAffine { x, y } = GrumpkinPointAffine::random(&mut rng);
        let y_squared = y.square();
        assert!(verify(input(x, y_squared)).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let GrumpkinPointAffine { x, y } =
            GrumpkinPointAffine::new(Fr::from_u128(1), Fr::from_u128(2));
        let y_squared = y.square();
        assert!(verify(input(x, y_squared)).is_err());
    }
}
