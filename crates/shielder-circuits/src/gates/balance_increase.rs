use alloc::vec;

use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
#[cfg(test)]
use {
    crate::column_pool::AccessColumn,
    crate::column_pool::{ColumnPool, ConfigPhase},
    crate::embed::Embed,
    macros::embeddable,
};

use crate::{
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell, Fr,
};

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;
const GATE_NAME: &str = "Balance increase gate";
pub const NUM_ADVICE_COLUMNS: usize = 4;

/// Enforces the equation `balance_new = balance_old + increase_value * token_indicator`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BalanceIncreaseGate {
    advices: BalanceIncreaseGateAdvices,
    selector: Selector,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BalanceIncreaseGateAdvices {
    pub balance_old: Column<Advice>,
    pub increase_value: Column<Advice>,
    pub token_indicator: Column<Advice>,
    pub balance_new: Column<Advice>,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(
    test,
    embeddable(
        receiver = "BalanceIncreaseGateInput<Fr>",
        impl_generics = "",
        embedded = "BalanceIncreaseGateInput<crate::AssignedCell>"
    )
)]
pub struct BalanceIncreaseGateInput<T> {
    pub balance_old: T,
    pub increase_value: T,
    pub token_indicator: T,
    pub balance_new: T,
}

impl Gate for BalanceIncreaseGate {
    type Input = BalanceIncreaseGateInput<AssignedCell>;
    type Advices = BalanceIncreaseGateAdvices;

    fn create_gate(cs: &mut ConstraintSystem<Fr>, advices: Self::Advices) -> Self {
        ensure_unique_columns(&[
            advices.balance_old,
            advices.increase_value,
            advices.token_indicator,
            advices.balance_new,
        ]);
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);
            let balance_old = vc.query_advice(advices.balance_old, Rotation(ADVICE_OFFSET as i32));
            let increase_value =
                vc.query_advice(advices.increase_value, Rotation(ADVICE_OFFSET as i32));
            let token_indicator =
                vc.query_advice(advices.token_indicator, Rotation(ADVICE_OFFSET as i32));
            let balance_new = vc.query_advice(advices.balance_new, Rotation(ADVICE_OFFSET as i32));
            vec![selector * (balance_old + increase_value * token_indicator - balance_new)]
        });
        Self { advices, selector }
    }

    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: Self::Input,
    ) -> Result<(), Error> {
        synthesizer.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector.enable(&mut region, SELECTOR_OFFSET)?;

                input.balance_old.copy_advice(
                    || "balance_old",
                    &mut region,
                    self.advices.balance_old,
                    ADVICE_OFFSET,
                )?;
                input.increase_value.copy_advice(
                    || "increase_value",
                    &mut region,
                    self.advices.increase_value,
                    ADVICE_OFFSET,
                )?;
                input.token_indicator.copy_advice(
                    || "token_indicator",
                    &mut region,
                    self.advices.token_indicator,
                    ADVICE_OFFSET,
                )?;
                input.balance_new.copy_advice(
                    || "balance_new",
                    &mut region,
                    self.advices.balance_new,
                    ADVICE_OFFSET,
                )?;

                Ok(())
            },
        )
    }

    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advices {
        pool.ensure_capacity(cs, NUM_ADVICE_COLUMNS);
        let columns = pool.get_column_array::<NUM_ADVICE_COLUMNS>();
        BalanceIncreaseGateAdvices {
            balance_old: columns[0],
            increase_value: columns[1],
            token_indicator: columns[2],
            balance_new: columns[3],
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::ConstraintSystem};

    use crate::gates::{
        balance_increase::{
            BalanceIncreaseGate, BalanceIncreaseGateAdvices, BalanceIncreaseGateInput,
        },
        test_utils::verify,
        Gate as _,
    };

    #[test]
    fn token_enabled_balance_changed_passes() {
        assert!(verify::<BalanceIncreaseGate, _>(BalanceIncreaseGateInput {
            balance_old: Fr::from(10),
            increase_value: Fr::from(5),
            token_indicator: Fr::from(1),
            balance_new: Fr::from(15)
        })
        .is_ok());
    }

    #[test]
    fn token_enabled_balance_unchanged_fails() {
        let errors = verify::<BalanceIncreaseGate, _>(BalanceIncreaseGateInput {
            balance_old: Fr::from(10),
            increase_value: Fr::from(5),
            token_indicator: Fr::from(1),
            balance_new: Fr::from(10),
        })
        .expect_err("Verification should fail");

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("Constraint 0 in gate 0 ('Balance increase gate') is not satisfied")
        );
    }

    #[test]
    fn token_disabled_balance_changed_fails() {
        let errors = verify::<BalanceIncreaseGate, _>(BalanceIncreaseGateInput {
            balance_old: Fr::from(10),
            increase_value: Fr::from(5),
            token_indicator: Fr::from(0),
            balance_new: Fr::from(15),
        })
        .expect_err("Verification should fail");

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("Constraint 0 in gate 0 ('Balance increase gate') is not satisfied")
        );
    }

    #[test]
    fn token_disabled_balance_unchanged_passes() {
        assert!(verify::<BalanceIncreaseGate, _>(BalanceIncreaseGateInput {
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
        BalanceIncreaseGate::create_gate(
            &mut cs,
            BalanceIncreaseGateAdvices {
                balance_old: column_1,
                increase_value: column_1,
                token_indicator: column_2,
                balance_new: column_3,
            },
        );
    }
}
