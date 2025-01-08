use alloc::vec;

use halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
#[cfg(test)]
use {crate::embed::Embed, crate::F, macros::embeddable};

use crate::{
    gates::{utils::expect_unique_columns, Gate},
    AssignedCell,
};

/// Represents the relation: `a + b = c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SumGate {
    advice: [Column<Advice>; 3],
    selector: Selector,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(
    test,
    embeddable(
        receiver = "SumGateInput<F>",
        impl_generics = "",
        embedded = "SumGateInput<crate::AssignedCell<F>>"
    )
)]
pub struct SumGateInput<T> {
    pub summand_1: T,
    pub summand_2: T,
    pub sum: T,
}

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;
const GATE_NAME: &str = "Sum gate";

impl<F: Field> Gate<F> for SumGate {
    type Input = SumGateInput<AssignedCell<F>>;
    type Advices = [Column<Advice>; 3];

    /// The gate operates on three advice columns `A`, `B`, and `C`. It enforces that:
    /// `A[x] + B[x] = C[x]`, where `x` is the row where the gate is enabled.
    fn create_gate(cs: &mut ConstraintSystem<F>, advice: Self::Advices) -> Self {
        expect_unique_columns(&advice, "Advice columns must be unique");
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);
            let summand_1 = vc.query_advice(advice[0], Rotation(ADVICE_OFFSET as i32));
            let summand_2 = vc.query_advice(advice[1], Rotation(ADVICE_OFFSET as i32));
            let sum = vc.query_advice(advice[2], Rotation(ADVICE_OFFSET as i32));
            vec![selector * (summand_1 + summand_2 - sum)]
        });
        Self { advice, selector }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<F>,
        input: Self::Input,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector.enable(&mut region, SELECTOR_OFFSET)?;

                for (idx, (cell, name, offset)) in [
                    (&input.summand_1, "summand 1", ADVICE_OFFSET),
                    (&input.summand_2, "summand 2", ADVICE_OFFSET),
                    (&input.sum, "sum", ADVICE_OFFSET),
                ]
                .into_iter()
                .enumerate()
                {
                    cell.copy_advice(|| name, &mut region, self.advice[idx], offset)?;
                }

                Ok(())
            },
        )
    }

    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut crate::column_pool::ColumnPool<Advice>,
        cs: &mut ConstraintSystem<F>,
    ) -> Self::Advices {
        pool.ensure_capacity(cs, 3);
        pool.get_array()
    }
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use halo2_proofs::{
        dev::{
            metadata::{Constraint, Gate},
            MockProver, VerifyFailure,
        },
        halo2curves::bn256::Fr,
    };

    use crate::gates::{
        sum::{SumGate, SumGateInput},
        test_utils::OneGateCircuit,
    };

    fn input(
        summand_1: impl Into<Fr>,
        summand_2: impl Into<Fr>,
        sum: impl Into<Fr>,
    ) -> SumGateInput<Fr> {
        SumGateInput {
            summand_1: summand_1.into(),
            summand_2: summand_2.into(),
            sum: sum.into(),
        }
    }

    fn failed_constraint() -> Constraint {
        // We have only one constraint in the circuit, so all indices are 0.
        Constraint::from((Gate::from((0, "Sum gate")), 0, ""))
    }

    fn verify(input: SumGateInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = OneGateCircuit::<SumGate, _>::new(input);
        MockProver::run(3, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn zeros_passes() {
        assert!(verify(input(0, 0, 0)).is_ok());
    }

    #[test]
    fn simple_addition_passes() {
        assert!(verify(input(1, 2, 3)).is_ok());
    }

    #[test]
    fn negation_passes() {
        assert!(verify(input(5, Fr::from(5).neg(), 0)).is_ok());
    }

    #[test]
    fn incorrect_sum_fails() {
        let errors = verify(input(2, 2, 3)).expect_err("Verification should fail");

        assert_eq!(errors.len(), 1);
        match &errors[0] {
            VerifyFailure::ConstraintNotSatisfied { constraint, .. } => {
                assert_eq!(constraint, &failed_constraint())
            }
            _ => panic!("Unexpected error"),
        };
    }
}
