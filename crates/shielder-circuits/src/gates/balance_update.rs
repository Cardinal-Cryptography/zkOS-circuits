use alloc::vec;

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
#[cfg(test)]
use {crate::embed::Embed, macros::embeddable};

use crate::{
    gates::{ensure_unique_columns, Gate},
    AssignedCell, F,
};

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;
const GATE_NAME: &str = "Balance update gate";
pub const NUM_ADVICE_COLUMNS: usize = 4;

/// Enforces the equation `balance_new = balance_old + update_value * token_indicator`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BalanceUpdateGate {
    advices: BalanceUpdateGateAdvices,
    selector: Selector,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BalanceUpdateGateAdvices {
    pub balance_old: Column<Advice>,
    pub update_value: Column<Advice>,
    pub token_indicator: Column<Advice>,
    pub balance_new: Column<Advice>,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(
    test,
    embeddable(
        receiver = "BalanceUpdateGateInput<F>",
        impl_generics = "",
        embedded = "BalanceUpdateGateInput<crate::AssignedCell>"
    )
)]
pub struct BalanceUpdateGateInput<T> {
    pub balance_old: T,
    pub update_value: T,
    pub token_indicator: T,
    pub balance_new: T,
}

impl Gate for BalanceUpdateGate {
    type Input = BalanceUpdateGateInput<AssignedCell>;
    type Advices = BalanceUpdateGateAdvices;

    fn create_gate(cs: &mut ConstraintSystem<F>, advices: Self::Advices) -> Self {
        ensure_unique_columns(&[
            advices.balance_old,
            advices.update_value,
            advices.token_indicator,
            advices.balance_new,
        ]);
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);
            let balance_old = vc.query_advice(advices.balance_old, Rotation(ADVICE_OFFSET as i32));
            let update_value =
                vc.query_advice(advices.update_value, Rotation(ADVICE_OFFSET as i32));
            let token_indicator =
                vc.query_advice(advices.token_indicator, Rotation(ADVICE_OFFSET as i32));
            let balance_new = vc.query_advice(advices.balance_new, Rotation(ADVICE_OFFSET as i32));
            vec![selector * (balance_old + update_value * token_indicator - balance_new)]
        });
        Self { advices, selector }
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

                input.balance_old.copy_advice(
                    || "balance_old",
                    &mut region,
                    self.advices.balance_old,
                    ADVICE_OFFSET,
                )?;
                input.update_value.copy_advice(
                    || "update_value",
                    &mut region,
                    self.advices.update_value,
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
        pool: &mut crate::column_pool::ColumnPool<Advice>,
        cs: &mut ConstraintSystem<F>,
    ) -> Self::Advices {
        pool.ensure_capacity(cs, NUM_ADVICE_COLUMNS);
        let columns = pool.get_array::<NUM_ADVICE_COLUMNS>();
        BalanceUpdateGateAdvices {
            balance_old: columns[0],
            update_value: columns[1],
            token_indicator: columns[2],
            balance_new: columns[3],
        }
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::{halo2curves::bn256::Fr, plonk::ConstraintSystem};

    use crate::gates::{
        balance_update::{
            BalanceUpdateGate, BalanceUpdateGateAdvices, BalanceUpdateGateInput,
        },
        test_utils::verify,
        Gate as _,
    };

    #[test]
    fn token_enabled_balance_changed_passes() {
        assert!(verify::<BalanceUpdateGate, _>(BalanceUpdateGateInput {
            balance_old: Fr::from(10),
            update_value: Fr::from(5),
            token_indicator: Fr::from(1),
            balance_new: Fr::from(15)
        })
        .is_ok());
    }

    #[test]
    fn token_enabled_balance_decrease_passes() {
        assert!(verify::<BalanceUpdateGate, _>(BalanceUpdateGateInput {
            balance_old: Fr::from(10),
            update_value: Fr::from(5).neg(),
            token_indicator: Fr::from(1),
            balance_new: Fr::from(5)
        })
        .is_ok());
    }

    #[test]
    fn token_enabled_balance_unchanged_fails() {
        let errors = verify::<BalanceUpdateGate, _>(BalanceUpdateGateInput {
            balance_old: Fr::from(10),
            update_value: Fr::from(5),
            token_indicator: Fr::from(1),
            balance_new: Fr::from(10),
        })
        .expect_err("Verification should fail");

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("Constraint 0 in gate 0 ('Balance update gate') is not satisfied")
        );
    }

    #[test]
    fn token_disabled_balance_changed_fails() {
        let errors = verify::<BalanceUpdateGate, _>(BalanceUpdateGateInput {
            balance_old: Fr::from(10),
            update_value: Fr::from(5),
            token_indicator: Fr::from(0),
            balance_new: Fr::from(15),
        })
        .expect_err("Verification should fail");

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("Constraint 0 in gate 0 ('Balance update gate') is not satisfied")
        );
    }

    #[test]
    fn token_disabled_balance_unchanged_passes() {
        assert!(verify::<BalanceUpdateGate, _>(BalanceUpdateGateInput {
            balance_old: Fr::from(10),
            update_value: Fr::from(5),
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
        BalanceUpdateGate::create_gate(
            &mut cs,
            BalanceUpdateGateAdvices {
                balance_old: column_1,
                update_value: column_1,
                token_indicator: column_2,
                balance_new: column_3,
            },
        );
    }
}
