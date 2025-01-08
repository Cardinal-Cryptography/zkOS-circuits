use halo2_proofs::{arithmetic::Field, circuit::Layouter, plonk::Error};

use crate::{
    consts::NUM_TOKENS,
    gates::{
        balance_increase::{BalanceIncreaseGate, BalanceIncreaseGateInput},
        Gate,
    },
    AssignedCell,
};

pub mod off_circuit {
    use core::{
        array,
        ops::{Add, Mul},
    };

    use crate::consts::NUM_TOKENS;

    /// Computes new balances. Works for both `F` and `Value<F>`.
    pub fn increase_balances<F: Add<Output = F> + Mul<Output = F> + Clone>(
        balances_old: &[F; NUM_TOKENS],
        token_indicators: &[F; NUM_TOKENS],
        increase_value: F,
    ) -> [F; NUM_TOKENS] {
        array::from_fn(|i| {
            balances_old[i].clone() + token_indicators[i].clone() * increase_value.clone()
        })
    }
}

#[derive(Clone, Debug)]
pub struct BalancesIncreaseChip {
    pub gate: BalanceIncreaseGate,
}

impl BalancesIncreaseChip {
    pub fn new(gate: BalanceIncreaseGate) -> Self {
        Self { gate }
    }

    pub fn constrain_balances<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        balances_old: &[AssignedCell<F>; NUM_TOKENS],
        token_indicators: &[AssignedCell<F>; NUM_TOKENS],
        increase_value: &AssignedCell<F>,
        balances_new: &[AssignedCell<F>; NUM_TOKENS],
    ) -> Result<(), Error> {
        for i in 0..NUM_TOKENS {
            let gate_input = BalanceIncreaseGateInput {
                balance_old: balances_old[i].clone(),
                increase_value: increase_value.clone(),
                token_indicator: token_indicators[i].clone(),
                balance_new: balances_new[i].clone(),
            };
            self.gate.apply_in_new_region(layouter, gate_input)?;
        }
        Ok(())
    }
}
