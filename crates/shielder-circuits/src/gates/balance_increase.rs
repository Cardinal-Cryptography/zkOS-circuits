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
    gates::{ensure_unique_columns, Gate},
    AssignedCell,
};

/// Enforces the equation `balance_new = balance_old + increase_value * token_indicator`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BalanceIncreaseGate {
    advice: [Column<Advice>; 4],
    selector: Selector,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(
    test,
    embeddable(
        receiver = "BalanceIncreaseGateInput<F>",
        impl_generics = "",
        embedded = "BalanceIncreaseGateInput<crate::AssignedCell<F>>"
    )
)]

pub struct BalanceIncreaseGateInput<T> {
    pub balance_old: T,
    pub increase_value: T,
    pub token_indicator: T,
    pub balance_new: T,
}

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;
const GATE_NAME: &str = "Balance increase gate";
const NUM_ADVICE_COLUMNS: usize = 4;

impl<F: Field> Gate<F> for BalanceIncreaseGate {
    type Input = BalanceIncreaseGateInput<AssignedCell<F>>;
    type Advices = [Column<Advice>; NUM_ADVICE_COLUMNS];

    fn create_gate(cs: &mut ConstraintSystem<F>, advice: Self::Advices) -> Self {
        ensure_unique_columns(&advice);
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);
            let balance_old = vc.query_advice(advice[0], Rotation(ADVICE_OFFSET as i32));
            let increase_value = vc.query_advice(advice[1], Rotation(ADVICE_OFFSET as i32));
            let token_indicator = vc.query_advice(advice[2], Rotation(ADVICE_OFFSET as i32));
            let balance_new = vc.query_advice(advice[3], Rotation(ADVICE_OFFSET as i32));
            vec![selector * (balance_old + increase_value * token_indicator - balance_new)]
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
                    (&input.balance_old, "balance_old", ADVICE_OFFSET),
                    (&input.increase_value, "increase_value", ADVICE_OFFSET),
                    (&input.token_indicator, "token_indicator", ADVICE_OFFSET),
                    (&input.balance_new, "balance_new", ADVICE_OFFSET),
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
        pool.ensure_capacity(cs, NUM_ADVICE_COLUMNS);
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
        plonk::ConstraintSystem,
    };

    use crate::gates::{
        balance_increase::{BalanceIncreaseGate, BalanceIncreaseGateInput},
        test_utils::OneGateCircuit,
        Gate as _,
    };

    fn failed_constraint() -> Constraint {
        // We have only one constraint in the circuit, so all indices are 0.
        Constraint::from((Gate::from((0, "Balance increase gate")), 0, ""))
    }

    // TODO: Replace with gates::test_utils::verify
    // once https://github.com/Cardinal-Cryptography/zkOS-circuits/pull/28 is merged.
    fn verify(input: BalanceIncreaseGateInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = OneGateCircuit::<BalanceIncreaseGate, _>::new(input);
        MockProver::run(3, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn token_enabled_balance_changed_passes() {
        assert!(verify(BalanceIncreaseGateInput {
            balance_old: Fr::from(10),
            increase_value: Fr::from(5),
            token_indicator: Fr::from(1),
            balance_new: Fr::from(15)
        })
        .is_ok());
    }

    #[test]
    fn token_enabled_balance_unchanged_fails() {
        let errors = verify(BalanceIncreaseGateInput {
            balance_old: Fr::from(10),
            increase_value: Fr::from(5),
            token_indicator: Fr::from(1),
            balance_new: Fr::from(0),
        })
        .expect_err("Verification should fail");

        assert_eq!(errors.len(), 1);
        match &errors[0] {
            VerifyFailure::ConstraintNotSatisfied { constraint, .. } => {
                assert_eq!(constraint, &failed_constraint())
            }
            _ => panic!("Unexpected error"),
        };
    }

    #[test]
    fn token_disabled_balance_changed_fails() {
        let errors = verify(BalanceIncreaseGateInput {
            balance_old: Fr::from(10),
            increase_value: Fr::from(5),
            token_indicator: Fr::from(0),
            balance_new: Fr::from(15),
        })
        .expect_err("Verification should fail");

        assert_eq!(errors.len(), 1);
        match &errors[0] {
            VerifyFailure::ConstraintNotSatisfied { constraint, .. } => {
                assert_eq!(constraint, &failed_constraint())
            }
            _ => panic!("Unexpected error"),
        };
    }

    #[test]
    fn token_disabled_balance_unchanged_passes() {
        assert!(verify(BalanceIncreaseGateInput {
            balance_old: Fr::from(10),
            increase_value: Fr::from(5),
            token_indicator: Fr::from(0),
            balance_new: Fr::from(10)
        })
        .is_ok());
    }

    #[test]
    #[should_panic = "Advice columns must be unique"]
    fn gate_creation_with_not_distinct_columns_fails() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let column_1 = cs.advice_column();
        let column_2 = cs.advice_column();
        let column_3 = cs.advice_column();
        BalanceIncreaseGate::create_gate(&mut cs, [column_1, column_2, column_3, column_3]);
    }
}
