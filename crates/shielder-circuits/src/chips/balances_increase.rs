use alloc::{vec, vec::Vec};
use core::array;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Error},
};

use super::shortlist_hash::Shortlist;
use crate::{
    column_pool::ColumnPool,
    consts::NUM_TOKENS,
    gates::{
        balance_increase::{BalanceIncreaseGate, BalanceIncreaseGateInput},
        Gate,
    },
    AssignedCell, F,
};

pub mod off_circuit {
    use core::{
        array,
        ops::{Add, Mul},
    };

    use crate::{chips::shortlist_hash::Shortlist, consts::NUM_TOKENS};

    /// Computes new balances. Works for both `F` and `Value<F>`.
    pub fn increase_balances<T: Add<Output = T> + Mul<Output = T> + Clone>(
        balances_old: &Shortlist<T, NUM_TOKENS>,
        token_indicators: &Shortlist<T, NUM_TOKENS>,
        increase_value: T,
    ) -> Shortlist<T, NUM_TOKENS> {
        Shortlist::new(array::from_fn(|i| {
            balances_old.items()[i].clone()
                + token_indicators.items()[i].clone() * increase_value.clone()
        }))
    }
}

#[derive(Clone, Debug)]
pub struct BalancesIncreaseChip {
    pub gate: BalanceIncreaseGate,
    pub advice_pool: ColumnPool<Advice>,
}

fn values_from_cell_array<const N: usize>(
    cell_array: &Shortlist<AssignedCell, N>,
) -> Shortlist<Value<F>, N> {
    Shortlist::new(array::from_fn(|i| cell_array.items()[i].value().copied()))
}

impl BalancesIncreaseChip {
    pub fn new(gate: BalanceIncreaseGate, advice_pool: ColumnPool<Advice>) -> Self {
        Self { gate, advice_pool }
    }

    pub fn increase_balances(
        &self,
        layouter: &mut impl Layouter<F>,
        balances_old: &Shortlist<AssignedCell, NUM_TOKENS>,
        token_indicators: &Shortlist<AssignedCell, NUM_TOKENS>,
        increase_value: &AssignedCell,
    ) -> Result<Shortlist<AssignedCell, NUM_TOKENS>, Error> {
        let balances_new_values = off_circuit::increase_balances(
            &values_from_cell_array(balances_old),
            &values_from_cell_array(token_indicators),
            increase_value.value().cloned(),
        );

        let mut balances_new: Vec<AssignedCell> = vec![];

        for i in 0..NUM_TOKENS {
            let balance_new = layouter.assign_region(
                || "balance_new",
                |mut region| {
                    region.assign_advice(
                        || "balance_new",
                        self.advice_pool.get_any(),
                        0,
                        || balances_new_values.items()[i],
                    )
                },
            )?;
            balances_new.push(balance_new);

            let gate_input = BalanceIncreaseGateInput {
                balance_old: balances_old.items()[i].clone(),
                increase_value: increase_value.clone(),
                token_indicator: token_indicators.items()[i].clone(),
                balance_new: balances_new[i].clone(),
            };
            self.gate.apply_in_new_region(layouter, gate_input)?;
        }

        Ok(Shortlist::new(
            balances_new.try_into().expect("length must agree"),
        ))
    }
}
