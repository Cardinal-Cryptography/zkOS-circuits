use alloc::{vec, vec::Vec};
use core::array;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Error},
};

use super::{range_check::RangeCheckChip, shortlist_hash::Shortlist};
use crate::{
    column_pool::ColumnPool,
    consts::{NUM_TOKENS, RANGE_PROOF_NUM_WORDS},
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
        token_indicators: &[T; NUM_TOKENS],
        increase_value: T,
    ) -> Shortlist<T, NUM_TOKENS> {
        Shortlist::new(array::from_fn(|i| {
            balances_old.items()[i].clone() + token_indicators[i].clone() * increase_value.clone()
        }))
    }
}

#[derive(Clone, Debug)]
pub struct BalancesIncreaseChip {
    pub gate: BalanceIncreaseGate,
    pub advice_pool: ColumnPool<Advice>,
    pub range_check: RangeCheckChip,
}

fn values_from_cell_array<const N: usize>(cell_array: &[AssignedCell; N]) -> [Value<F>; N] {
    array::from_fn(|i| cell_array[i].value().copied())
}

impl BalancesIncreaseChip {
    pub fn new(
        gate: BalanceIncreaseGate,
        range_check: RangeCheckChip,
        advice_pool: ColumnPool<Advice>,
    ) -> Self {
        Self {
            gate,
            range_check,
            advice_pool,
        }
    }

    pub fn increase_balances(
        &self,
        layouter: &mut impl Layouter<F>,
        balances_old: &Shortlist<AssignedCell, NUM_TOKENS>,
        token_indicators: &[AssignedCell; NUM_TOKENS],
        increase_value: &AssignedCell,
    ) -> Result<Shortlist<AssignedCell, NUM_TOKENS>, Error> {
        let balances_new_values = off_circuit::increase_balances(
            &Shortlist::new(values_from_cell_array(balances_old.items())),
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
            self.range_check
                .constrain_value::<RANGE_PROOF_NUM_WORDS>(layouter, balance_new.clone())?;
            balances_new.push(balance_new);

            let gate_input = BalanceIncreaseGateInput {
                balance_old: balances_old.items()[i].clone(),
                update_value: increase_value.clone(),
                token_indicator: token_indicators[i].clone(),
                balance_new: balances_new[i].clone(),
            };
            self.gate.apply_in_new_region(layouter, gate_input)?;
        }

        Ok(Shortlist::new(
            balances_new.try_into().expect("length must agree"),
        ))
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use assert2::assert;
    use halo2_proofs::{
        circuit::floor_planner::V1,
        dev::MockProver,
        plonk::{Circuit, Column, ConstraintSystem, Instance},
    };

    use super::*;
    use crate::{config_builder::ConfigsBuilder, embed::Embed, F};

    #[derive(Clone, Debug, Default)]
    struct BalanceIncreaseCircuit {
        balances_old: Shortlist<F, NUM_TOKENS>,
        update_value: F,
        token_indicators: [F; NUM_TOKENS],
    }

    impl Circuit<F> for BalanceIncreaseCircuit {
        type Config = (ColumnPool<Advice>, BalancesIncreaseChip, Column<Instance>);
        type FloorPlanner = V1;

        fn configure(constraint_system: &mut ConstraintSystem<F>) -> Self::Config {
            let instance = constraint_system.instance_column();
            constraint_system.enable_equality(instance);

            let configs_builder = ConfigsBuilder::new(constraint_system).with_poseidon();
            let pool = configs_builder.advice_pool();

            let configs_builder = configs_builder.with_balances_increase();

            (pool, configs_builder.balances_increase_chip(), instance)
        }

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn synthesize(
            &self,
            (pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let balances_old_embedded =
                self.balances_old
                    .map(Value::known)
                    .embed(&mut layouter, &pool, "balances_old")?;
            let update_value = self
                .update_value
                .embed(&mut layouter, &pool, "update_value")?;
            let token_indicators = self.token_indicators.map(Value::known).embed(
                &mut layouter,
                &pool,
                "token_indicators",
            )?;

            let balances_new_embedded = chip.increase_balances(
                &mut layouter,
                &balances_old_embedded,
                &token_indicators,
                &update_value,
            )?;

            for i in 0..NUM_TOKENS {
                layouter.constrain_instance(
                    balances_new_embedded.items()[i].cell(),
                    instance,
                    i,
                )?;
            }

            Ok(())
        }
    }

    #[test]
    fn test_simple_balance_change_at_0() {
        test_balance_change([10, 20, 30, 40, 50, 60], 100, 0, [110, 20, 30, 40, 50, 60]);
    }

    #[test]
    fn test_simple_balance_change_at_3() {
        test_balance_change([10, 20, 30, 40, 50, 60], 100, 3, [10, 20, 30, 140, 50, 60]);
    }

    #[test]
    fn test_balance_reduction() {
        test_balance_change([10, 20, 30, 40, 50, 60], -20, 3, [10, 20, 30, 20, 50, 60]);
    }

    #[test]
    #[should_panic]
    fn test_balance_reduction_overflows_0() {
        let _ = run_balance_change([10, 20, 30, 40, 50, 60], -100, 3, [10, 20, 30, -60, 50, 60]);
    }

    fn test_balance_change(
        balances_old: [u64; NUM_TOKENS],
        update_value: i64,
        token_id: usize,
        expected_new_balances: [i64; NUM_TOKENS],
    ) {
        let result =
            run_balance_change(balances_old, update_value, token_id, expected_new_balances)
                .expect("Mock prover should run successfully")
                .verify();

        assert!(result == Ok(()));
    }

    fn run_balance_change(
        balances_old: [u64; NUM_TOKENS],
        update_value: i64,
        token_id: usize,
        expected_new_balances: [i64; NUM_TOKENS],
    ) -> Result<MockProver<F>, Error> {
        let token_indicators = array::from_fn(|i| ((i == token_id) as u64).into());

        MockProver::run(
            9,
            &BalanceIncreaseCircuit {
                balances_old: Shortlist::new(balances_old.map(|x| x.into())),
                update_value: into_field(update_value),
                token_indicators,
            },
            vec![expected_new_balances.map(into_field).into()],
        )
    }

    fn into_field(x: i64) -> F {
        if x < 0 {
            let x: F = (-x as u64).into();
            x.neg()
        } else {
            (x as u64).into()
        }
    }
}
