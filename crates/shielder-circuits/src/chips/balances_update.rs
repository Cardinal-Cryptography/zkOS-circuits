use alloc::{vec, vec::Vec};
use core::array;

use halo2_proofs::{circuit::Value, plonk::Error};

use super::{range_check::RangeCheckChip, shortlist_hash::Shortlist};
use crate::{
    consts::{NUM_TOKENS, RANGE_PROOF_NUM_WORDS},
    gates::{
        balance_update::{BalanceUpdateGate, BalanceUpdateGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell, Fr,
};

pub mod off_circuit {
    use core::{
        array,
        ops::{Add, Mul},
    };

    use crate::{chips::shortlist_hash::Shortlist, consts::NUM_TOKENS};

    /// Computes new balances. Works for both `F` and `Value<F>`.
    pub fn update_balances<T: Add<Output = T> + Mul<Output = T> + Clone>(
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
pub struct BalancesUpdateChip {
    pub gate: BalanceUpdateGate,
    pub range_check: RangeCheckChip,
}

fn values_from_cell_array<const N: usize>(cell_array: &[AssignedCell; N]) -> [Value<Fr>; N] {
    array::from_fn(|i| cell_array[i].value().copied())
}

impl BalancesUpdateChip {
    pub fn new(gate: BalanceUpdateGate, range_check: RangeCheckChip) -> Self {
        Self { gate, range_check }
    }

    pub fn update_balances(
        &self,
        synthesizer: &mut impl Synthesizer,
        balances_old: &Shortlist<AssignedCell, NUM_TOKENS>,
        token_indicators: &[AssignedCell; NUM_TOKENS],
        increase_value: &AssignedCell,
    ) -> Result<Shortlist<AssignedCell, NUM_TOKENS>, Error> {
        let balances_new_values = off_circuit::update_balances(
            &Shortlist::new(values_from_cell_array(balances_old.items())),
            &values_from_cell_array(token_indicators),
            increase_value.value().cloned(),
        );

        let mut balances_new: Vec<AssignedCell> = vec![];

        for i in 0..NUM_TOKENS {
            let balance_new =
                synthesizer.assign_value("balance_new", balances_new_values.items()[i])?;
            self.range_check
                .constrain_value::<RANGE_PROOF_NUM_WORDS>(synthesizer, balance_new.clone())?;
            balances_new.push(balance_new);

            let gate_input = BalanceUpdateGateInput {
                balance_old: balances_old.items()[i].clone(),
                update_value: increase_value.clone(),
                token_indicator: token_indicators[i].clone(),
                balance_new: balances_new[i].clone(),
            };
            self.gate.apply_in_new_region(synthesizer, gate_input)?;
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
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Instance},
    };

    use super::*;
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        embed::Embed as _,
        synthesizer::create_synthesizer,
    };

    #[derive(Clone, Debug, Default)]
    struct BalanceUpdateCircuit {
        balances_old: Shortlist<Fr, NUM_TOKENS>,
        update_value: Fr,
        token_indicators: [Fr; NUM_TOKENS],
    }

    impl Circuit<Fr> for BalanceUpdateCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            BalancesUpdateChip,
            Column<Instance>,
        );
        type FloorPlanner = V1;

        fn configure(constraint_system: &mut ConstraintSystem<Fr>) -> Self::Config {
            let instance = constraint_system.instance_column();
            constraint_system.enable_equality(instance);

            let configs_builder = ConfigsBuilder::new(constraint_system).with_poseidon();
            let configs_builder = configs_builder.with_balances_update();
            let chip = configs_builder.balances_update_chip();

            (configs_builder.finish(), chip, instance)
        }

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn synthesize(
            &self,
            (pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let pool = pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &pool);

            let balances_old_embedded = self
                .balances_old
                .map(Value::known)
                .embed(&mut synthesizer, "balances_old")?;
            let update_value = self.update_value.embed(&mut synthesizer, "update_value")?;
            let token_indicators = self
                .token_indicators
                .map(Value::known)
                .embed(&mut synthesizer, "token_indicators")?;

            let balances_new_embedded = chip.update_balances(
                &mut synthesizer,
                &balances_old_embedded,
                &token_indicators,
                &update_value,
            )?;

            for i in 0..NUM_TOKENS {
                synthesizer.constrain_instance(
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
    ) -> Result<MockProver<Fr>, Error> {
        let token_indicators = array::from_fn(|i| ((i == token_id) as u64).into());

        MockProver::run(
            9,
            &BalanceUpdateCircuit {
                balances_old: Shortlist::new(balances_old.map(|x| x.into())),
                update_value: into_field(update_value),
                token_indicators,
            },
            vec![expected_new_balances.map(into_field).into()],
        )
    }

    fn into_field(x: i64) -> Fr {
        if x < 0 {
            let x: Fr = (-x as u64).into();
            x.neg()
        } else {
            (x as u64).into()
        }
    }
}
