use core::array;

use gates::{IndexGate, IndexGateInput};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, ConstraintSystem, Error},
};
use strum::IntoEnumIterator;
use strum_macros::{EnumCount, EnumIter};

use crate::{
    column_pool::{ColumnPool, ConfigPhase, SynthesisPhase},
    consts::NUM_TOKENS,
    gates::Gate,
    instance_wrapper::InstanceWrapper,
    todo::Todo,
    AssignedCell, F,
};

pub mod off_circuit {
    use core::array;

    use halo2_proofs::{arithmetic::Field, circuit::Value};

    use crate::{consts::NUM_TOKENS, F};

    pub fn index_from_indicators(indicators: &[F; NUM_TOKENS]) -> F {
        // All `indicators` must be from {0, 1}.
        assert!(indicators.iter().all(|&x| x == F::ZERO || x == F::ONE));
        // Exactly one indicator must be equal to 1.
        assert_eq!(1, indicators.iter().filter(|&&x| x == F::ONE).count());

        let index = indicators
            .iter()
            .position(|&x| x == F::ONE)
            .expect("at least 1 positive indicator");
        F::from(index as u64)
    }

    pub fn index_from_indicator_values(indicators: &[Value<F>; NUM_TOKENS]) -> Value<F> {
        // All indicators must be from {0, 1}.
        for indicator in indicators.iter() {
            indicator.assert_if_known(|v| *v == F::ZERO || *v == F::ONE);
        }
        // Exactly one indicator must be equal to 1.
        indicators
            .iter()
            .copied()
            .reduce(|a, b| a + b)
            .expect("at least one indicator")
            .assert_if_known(|v| *v == F::ONE);

        // Produce the index by calculating Σ i * indicators[i].
        let multiplied_indicators: [Value<F>; NUM_TOKENS] =
            array::from_fn(|i| indicators[i].map(|v| v * F::from(i as u64)));
        multiplied_indicators
            .iter()
            .copied()
            .reduce(|a, b| a + b)
            .expect("at least one indicator")
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum TokenIndexInstance {
    TokenIndex,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum TokenIndexConstraints {
    TokenIndexInstanceIsConstrainedToAdvice,
}

// TODO: Constrain indicators to the set {0,1}.
// TODO: Constrain that exactly one indicator has value 1.
// A chip that manages the token index indicator variables and related constraints.
// Assumes that the indicator variables are binary and their sum is exactly 1.
#[derive(Clone, Debug)]
pub struct TokenIndexChip {
    index_gate: IndexGate,
    public_inputs: InstanceWrapper<TokenIndexInstance>,
}

impl TokenIndexChip {
    pub fn new(
        system: &mut ConstraintSystem<F>,
        advice_pool: &mut ColumnPool<Advice, ConfigPhase>,
        public_inputs: InstanceWrapper<TokenIndexInstance>,
    ) -> Self {
        // TODO ensure capacity
        let index_gate = IndexGate::create_gate(system, advice_pool.get_array());
        Self {
            index_gate,
            public_inputs,
        }
    }

    /// Constrains the token index public input to match the enabled indicator.
    pub fn constrain_index<Constraints: From<TokenIndexConstraints> + Ord + IntoEnumIterator>(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        indicators: &[AssignedCell; NUM_TOKENS],
        todo: &mut Todo<Constraints>,
    ) -> Result<(), Error> {
        let indicator_values = array::from_fn(|i| indicators[i].value().cloned());
        let index_value = off_circuit::index_from_indicator_values(&indicator_values);

        self.constrain_index_impl(layouter, advice_pool, indicators, todo, index_value)
    }

    fn constrain_index_impl<Constraints: From<TokenIndexConstraints> + Ord + IntoEnumIterator>(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        indicators: &[AssignedCell; NUM_TOKENS],
        todo: &mut Todo<Constraints>,
        index_value: Value<F>,
    ) -> Result<(), Error> {
        let index_cell = layouter.assign_region(
            || "Token index",
            |mut region| {
                region.assign_advice(|| "Token index", advice_pool.get_any(), 0, || index_value)
            },
        )?;

        self.index_gate.apply_in_new_region(
            layouter,
            IndexGateInput {
                variables: array::from_fn(|i| {
                    if i == NUM_TOKENS {
                        index_cell.clone()
                    } else {
                        indicators[i].clone()
                    }
                }),
            },
        )?;

        self.public_inputs
            .constrain_cells(layouter, [(index_cell, TokenIndexInstance::TokenIndex)])?;
        todo.check_off(Constraints::from(
            TokenIndexConstraints::TokenIndexInstanceIsConstrainedToAdvice,
        ))
    }
}

pub mod gates {
    use core::array;

    use halo2_proofs::arithmetic::Field;

    use crate::{
        consts::NUM_TOKENS,
        gates::linear_equation::{
            LinearEquationGate, LinearEquationGateConfig, LinearEquationGateInput,
        },
        AssignedCell, F,
    };

    pub const NUM_INDEX_GATE_COLUMNS: usize = NUM_TOKENS + 1;

    /// `0 * indicators[0] + 1 * indicators[1] + 2 * indicators[2] + ... = index`.
    pub type IndexGate = LinearEquationGate<NUM_INDEX_GATE_COLUMNS, IndexGateConfig>;
    pub type IndexGateInput = LinearEquationGateInput<AssignedCell, NUM_INDEX_GATE_COLUMNS>;

    #[derive(Clone, Debug)]
    pub enum IndexGateConfig {}

    impl LinearEquationGateConfig<NUM_INDEX_GATE_COLUMNS> for IndexGateConfig {
        fn coefficients() -> [F; NUM_INDEX_GATE_COLUMNS] {
            array::from_fn(|i| {
                if i == NUM_TOKENS {
                    F::ONE.neg()
                } else {
                    F::from(i as u64)
                }
            })
        }

        fn constant_term() -> F {
            F::ZERO
        }

        fn gate_name() -> &'static str {
            "Token index gate"
        }
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{floor_planner, Layouter, Value},
        dev::{
            metadata::{Constraint, Gate},
            VerifyFailure,
        },
        plonk::{Advice, Circuit, ConstraintSystem, Error},
    };

    use super::{gates, TokenIndexChip, TokenIndexConstraints, TokenIndexInstance};
    use crate::{
        circuits::test_utils::expect_prover_success_and_run_verification,
        column_pool::{ColumnPool, ConfigPhase, PreSynthesisPhase},
        consts::NUM_TOKENS,
        embed::Embed,
        instance_wrapper::InstanceWrapper,
        test_utils::expect_instance_permutation_failures,
        todo::Todo,
        F,
    };

    #[derive(Clone, Debug, Default)]
    struct TestCircuit {
        pub indicators: [Value<F>; NUM_TOKENS],

        pub token_index: Value<F>,
    }

    impl TestCircuit {
        pub fn new(indicators: [impl Into<F>; NUM_TOKENS], token_index: impl Into<F>) -> Self {
            Self {
                indicators: indicators.map(|v| Value::known(v.into())),
                token_index: Value::known(token_index.into()),
            }
        }
    }

    impl Circuit<F> for TestCircuit {
        type Config = (TokenIndexChip, ColumnPool<Advice, PreSynthesisPhase>);
        type FloorPlanner = floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let mut advice_pool = ColumnPool::<Advice, ConfigPhase>::new();
            advice_pool.ensure_capacity(meta, gates::NUM_INDEX_GATE_COLUMNS);
            let public_inputs = InstanceWrapper::<TokenIndexInstance>::new(meta);

            (
                TokenIndexChip::new(meta, &mut advice_pool, public_inputs),
                advice_pool.conclude_configuration(),
            )
        }

        fn synthesize(
            &self,
            (chip, advice_pool): Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let advice_pool = advice_pool.start_synthesis();

            let indicators = self
                .indicators
                .embed(&mut layouter, &advice_pool, "indicators")?;
            let mut todo = Todo::<TokenIndexConstraints>::new();

            chip.constrain_index_impl(
                &mut layouter,
                &advice_pool,
                &indicators,
                &mut todo,
                self.token_index,
            )?;
            todo.assert_done()
        }
    }

    #[test]
    fn native_token_passes() {
        let circuit = TestCircuit::new([1, 0, 0, 0, 0, 0], 0);
        let pub_input = [0];

        assert!(
            expect_prover_success_and_run_verification(circuit, &pub_input.map(F::from)).is_ok()
        );
    }

    #[test]
    fn last_token_passes() {
        let circuit = TestCircuit::new([0, 0, 0, 0, 0, 1], 5);
        let pub_input = [5];

        assert!(
            expect_prover_success_and_run_verification(circuit, &pub_input.map(F::from)).is_ok()
        );
    }

    #[test]
    fn index_witness_is_constrained() {
        let circuit = TestCircuit::new([1, 0, 0, 0, 0, 0], 1);
        let pub_input = [1];

        let failures = expect_prover_success_and_run_verification(circuit, &pub_input.map(F::from))
            .expect_err("Verification must fail");

        assert_eq!(1, failures.len());
        match &failures[0] {
            VerifyFailure::ConstraintNotSatisfied { constraint, .. } => {
                assert_eq!(
                    &Constraint::from((Gate::from((0, "Token index gate")), 0, "")),
                    constraint
                );
            }
            _ => panic!("Unexpected error"),
        }
    }

    #[test]
    fn index_pub_input_is_constrained() {
        let circuit = TestCircuit::new([1, 0, 0, 0, 0, 0], 0);
        let pub_input = [1];

        let failures = expect_prover_success_and_run_verification(circuit, &pub_input.map(F::from))
            .expect_err("Verification must fail");

        expect_instance_permutation_failures(&failures, "Token index", 0);
    }
}
