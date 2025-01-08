use alloc::vec;

use halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
#[cfg(test)]
use {crate::embed::Embed, crate::F, macros::embeddable};

use super::utils::expect_unique_columns;
use crate::{gates::Gate, AssignedCell};

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

impl<F: Field> Gate<F> for BalanceIncreaseGate {
    type Input = BalanceIncreaseGateInput<AssignedCell<F>>;
    type Advices = [Column<Advice>; 4];

    fn create_gate(cs: &mut ConstraintSystem<F>, advice: Self::Advices) -> Self {
        expect_unique_columns(&advice, "BalanceIncreaseGate columns must be unique");
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
        _pool: &mut crate::column_pool::ColumnPool<Advice>,
        _cs: &mut ConstraintSystem<F>,
    ) -> Self::Advices {
        unimplemented!()
    }
}
