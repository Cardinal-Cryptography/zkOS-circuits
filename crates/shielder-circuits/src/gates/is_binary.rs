use alloc::vec;

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

#[cfg(test)]
use crate::column_pool::{ColumnPool, ConfigPhase};
use crate::{gates::Gate, AssignedCell, F};

/// Represents the relation: `x * (1-x) = 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IsBinaryGate {
    advice: Column<Advice>,
    selector: Selector,
}

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;
const GATE_NAME: &str = "IsBinary gate";

impl Gate for IsBinaryGate {
    type Input = AssignedCell;
    type Advices = Column<Advice>;

    /// The gate operates on a single advice columns `A` and enforces that:
    /// `A[x] * (1 - A[x]) = 0`, where `x` is the row where the gate is enabled.
    fn create_gate(cs: &mut ConstraintSystem<F>, advice: Column<Advice>) -> Self {
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);
            let x = vc.query_advice(advice, Rotation(ADVICE_OFFSET as i32));
            Constraints::with_selector(
                selector,
                vec![x.clone() * (Expression::Constant(F::one()) - x)],
            )
        });
        Self { advice, selector }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<F>,
        x: AssignedCell,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector.enable(&mut region, SELECTOR_OFFSET)?;
                x.copy_advice(|| "binary witness", &mut region, self.advice, ADVICE_OFFSET)?;
                Ok(())
            },
        )
    }

    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<F>,
    ) -> Self::Advices {
        pool.ensure_capacity(cs, 1);
        pool.get_any()
    }
}

#[cfg(test)]
mod tests {
    use std::{string::String, vec::Vec};

    use halo2_proofs::{halo2curves::bn256::Fr, plonk::ConstraintSystem};

    use crate::{
        gates::{is_binary::IsBinaryGate, test_utils::verify, Gate as _},
        F,
    };

    #[test]
    fn gate_creation_with_proper_columns_passes() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let col = cs.advice_column();
        IsBinaryGate::create_gate(&mut cs, col);
    }

    #[test]
    fn zero_passes() {
        assert!(verify::<IsBinaryGate, _>(F::zero()).is_ok());
    }

    #[test]
    fn one_passes() {
        assert!(verify::<IsBinaryGate, _>(F::one()).is_ok());
    }

    fn assert_fails(errors: Vec<String>) {
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Constraint 0 in gate 0 ('IsBinary gate') is not satisfied"));
    }

    #[test]
    fn two_fails() {
        assert_fails(verify::<IsBinaryGate, _>(F::from(2)).unwrap_err());
    }

    #[test]
    fn minus_one_fails() {
        assert_fails(verify::<IsBinaryGate, _>(F::one().neg()).unwrap_err());
    }
}
