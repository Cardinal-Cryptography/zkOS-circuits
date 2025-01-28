use core::{array, cmp::max};

use gates::{
    IndexGate, IndexGateInput, IndicatorSumGate, IndicatorSumGateInput, NUM_INDEX_GATE_COLUMNS,
};
use halo2_proofs::plonk::{Advice, ConstraintSystem, Error};
use strum::IntoEnumIterator;
use strum_macros::{EnumCount, EnumIter};

use crate::{
    column_pool::{AccessColumn, ColumnPool, ConfigPhase},
    consts::NUM_TOKENS,
    gates::{is_binary::IsBinaryGate, Gate},
    instance_wrapper::InstanceWrapper,
    synthesizer::Synthesizer,
    todo::Todo,
    AssignedCell, Fr, Value,
};

pub mod off_circuit {
    use alloc::vec::Vec;

    use halo2_proofs::arithmetic::Field;

    use crate::{consts::NUM_TOKENS, Fr, Value};

    pub fn index_from_indicators(indicators: &[Fr; NUM_TOKENS]) -> Fr {
        let index = indicators
            .iter()
            .position(|&x| x == Fr::ONE)
            .expect("at least 1 indicator equal to 1");
        Fr::from(index as u64)
    }

    pub fn index_from_indicator_values(indicators: &[Value; NUM_TOKENS]) -> Value {
        halo2_proofs::circuit::Value::<Vec<_>>::from_iter(*indicators)
            .map(|vec| vec.try_into().unwrap())
            .map(|array| index_from_indicators(&array))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter, EnumCount)]
pub enum TokenIndexInstance {
    TokenIndex,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, EnumIter)]
pub enum TokenIndexConstraints {
    TokenIndicatorsAreCorrect,
    TokenIndexInstanceIsConstrainedToAdvice,
}

// A chip that manages the token index indicator variables:
//  (1) `constrain_indicators` enforces that the indicators are binary and exactly one is enabled,
//  (2) `constrain_index` enforces that the token index public input matches the enabled indicator.
//
// (1) is achieved via a sum constraint, which is correct because indicators are constrained to
// be binary and `NUM_TOKENS` is smaller than the field characteristic.
#[derive(Clone, Debug)]
pub struct TokenIndexChip {
    is_binary_gate: IsBinaryGate,
    indicator_sum_gate: IndicatorSumGate,
    index_gate: IndexGate,
    public_inputs: InstanceWrapper<TokenIndexInstance>,
}

impl TokenIndexChip {
    pub fn new(
        system: &mut ConstraintSystem<Fr>,
        advice_pool: &mut ColumnPool<Advice, ConfigPhase>,
        public_inputs: InstanceWrapper<TokenIndexInstance>,
    ) -> Self {
        advice_pool.ensure_capacity(system, max(NUM_TOKENS, NUM_INDEX_GATE_COLUMNS));

        let is_binary_gate_advice = advice_pool.get_any_column();
        let indicator_sum_gate_advices = advice_pool.get_column_array();
        let index_gate_advices = advice_pool.get_column_array();

        Self {
            is_binary_gate: IsBinaryGate::create_gate(system, is_binary_gate_advice),
            indicator_sum_gate: IndicatorSumGate::create_gate(system, indicator_sum_gate_advices),
            index_gate: IndexGate::create_gate(system, index_gate_advices),
            public_inputs,
        }
    }

    pub fn constrain_indicators<
        Constraints: From<TokenIndexConstraints> + Ord + IntoEnumIterator,
    >(
        &self,
        synthesizer: &mut impl Synthesizer,
        indicators: &[AssignedCell; NUM_TOKENS],
        todo: &mut Todo<Constraints>,
    ) -> Result<(), Error> {
        for indicator in indicators.iter() {
            self.is_binary_gate
                .apply_in_new_region(synthesizer, indicator.clone())?;
        }

        self.indicator_sum_gate.apply_in_new_region(
            synthesizer,
            IndicatorSumGateInput {
                variables: indicators.clone(),
            },
        )?;

        todo.check_off(Constraints::from(
            TokenIndexConstraints::TokenIndicatorsAreCorrect,
        ))
    }

    /// Constrains the token index public input to match the enabled indicator.
    pub fn constrain_index<Constraints: From<TokenIndexConstraints> + Ord + IntoEnumIterator>(
        &self,
        synthesizer: &mut impl Synthesizer,
        indicators: &[AssignedCell; NUM_TOKENS],
        todo: &mut Todo<Constraints>,
    ) -> Result<(), Error> {
        let indicator_values = indicators.each_ref().map(|v| v.value().cloned());
        let index_value = off_circuit::index_from_indicator_values(&indicator_values);
        self.constrain_index_impl(synthesizer, indicators, todo, index_value)
    }

    fn constrain_index_impl<Constraints: From<TokenIndexConstraints> + Ord + IntoEnumIterator>(
        &self,
        synthesizer: &mut impl Synthesizer,
        indicators: &[AssignedCell; NUM_TOKENS],
        todo: &mut Todo<Constraints>,
        index_value: Value,
    ) -> Result<(), Error> {
        let index_cell = synthesizer.assign_value("Token index", index_value)?;

        self.index_gate.apply_in_new_region(
            synthesizer,
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
            .constrain_cells(synthesizer, [(index_cell, TokenIndexInstance::TokenIndex)])?;
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
        AssignedCell, Fr,
    };

    pub const NUM_INDEX_GATE_COLUMNS: usize = NUM_TOKENS + 1;

    /// `0 * indicators[0] + 1 * indicators[1] + 2 * indicators[2] + ... = index`.
    pub type IndexGate = LinearEquationGate<NUM_INDEX_GATE_COLUMNS, IndexGateConfig>;
    pub type IndexGateInput = LinearEquationGateInput<NUM_INDEX_GATE_COLUMNS, AssignedCell>;

    #[derive(Clone, Debug)]
    pub enum IndexGateConfig {}

    impl LinearEquationGateConfig<NUM_INDEX_GATE_COLUMNS> for IndexGateConfig {
        fn coefficients() -> [Fr; NUM_INDEX_GATE_COLUMNS] {
            array::from_fn(|i| {
                if i == NUM_TOKENS {
                    Fr::ONE.neg()
                } else {
                    Fr::from(i as u64)
                }
            })
        }

        fn constant_term() -> Fr {
            Fr::ZERO
        }

        fn gate_name() -> &'static str {
            "Token index gate"
        }
    }

    /// `indicators[0] + indicators[1] + ... = 1`.
    pub type IndicatorSumGate = LinearEquationGate<NUM_TOKENS, IndicatorSumGateConfig>;
    pub type IndicatorSumGateInput = LinearEquationGateInput<NUM_TOKENS, AssignedCell>;

    #[derive(Clone, Debug)]
    pub enum IndicatorSumGateConfig {}

    impl LinearEquationGateConfig<NUM_TOKENS> for IndicatorSumGateConfig {
        fn coefficients() -> [Fr; NUM_TOKENS] {
            [Fr::ONE; NUM_TOKENS]
        }

        fn constant_term() -> Fr {
            Fr::ONE
        }

        fn gate_name() -> &'static str {
            "Indicator sum gate"
        }
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::{
        arithmetic::Field,
        circuit::{floor_planner, Layouter},
        plonk::{Advice, Circuit, ConstraintSystem, Error},
    };
    use parameterized::parameterized;

    use super::{gates, TokenIndexChip, TokenIndexConstraints, TokenIndexInstance};
    use crate::{
        circuits::test_utils::expect_prover_success_and_run_verification,
        column_pool::{ColumnPool, ConfigPhase, PreSynthesisPhase},
        consts::NUM_TOKENS,
        embed::Embed,
        instance_wrapper::InstanceWrapper,
        synthesizer::create_synthesizer,
        test_utils::{expect_gate_failure, expect_instance_permutation_failures},
        todo::Todo,
        Fr, Value,
    };

    #[derive(Clone, Debug, Default)]
    struct TestCircuit {
        pub indicators: [Value; NUM_TOKENS],

        pub token_index: Value,
    }

    impl TestCircuit {
        pub fn new(indicators: [impl Into<Fr>; NUM_TOKENS], token_index: impl Into<Fr>) -> Self {
            Self {
                indicators: indicators.map(|v| Value::known(v.into())),
                token_index: Value::known(token_index.into()),
            }
        }
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = (TokenIndexChip, ColumnPool<Advice, PreSynthesisPhase>);
        type FloorPlanner = floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
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
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let advice_pool = advice_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &advice_pool);

            let indicators = self.indicators.embed(&mut synthesizer, "indicators")?;
            let mut todo = Todo::<TokenIndexConstraints>::new();

            chip.constrain_indicators(&mut synthesizer, &indicators, &mut todo)?;

            chip.constrain_index_impl(&mut synthesizer, &indicators, &mut todo, self.token_index)?;
            todo.assert_done()
        }
    }

    #[test]
    fn native_token_passes() {
        let circuit = TestCircuit::new([1, 0, 0, 0, 0, 0], 0);
        let pub_input = [0];

        assert!(
            expect_prover_success_and_run_verification(circuit, &pub_input.map(Fr::from)).is_ok()
        );
    }

    #[test]
    fn last_token_passes() {
        let circuit = TestCircuit::new([0, 0, 0, 0, 0, 1], 5);
        let pub_input = [5];

        assert!(
            expect_prover_success_and_run_verification(circuit, &pub_input.map(Fr::from)).is_ok()
        );
    }

    #[test]
    fn indicators_are_constrained_to_be_binary() {
        // This test targets the `IsBinary` gate while keeping all other constraints satisfied.
        let indicators = [
            Fr::from(2),
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ONE.neg(),
        ];

        let circuit = TestCircuit::new(indicators, Fr::from(5).neg());
        let pub_input = [Fr::from(5).neg()];

        let failures =
            expect_prover_success_and_run_verification(circuit, &pub_input.map(Fr::from))
                .expect_err("Verification must fail");

        assert_eq!(failures.len(), 2); // 2 indicators are nonbinary.
        for failure in failures {
            expect_gate_failure(&failure, "IsBinary gate");
        }
    }

    #[parameterized(witnesses = {
        ([0, 0, 0, 0, 0, 0], 0),
        ([1, 1, 0, 0, 0, 0], 1),
        ([1, 1, 1, 1, 1, 1], 15)
    })]
    fn indicators_are_constrained_to_sum_to_one(witnesses: ([u64; NUM_TOKENS], u64)) {
        let (indicators, token_index) = witnesses;

        let circuit = TestCircuit::new(indicators, token_index);
        let pub_input = [token_index];

        let failures =
            expect_prover_success_and_run_verification(circuit, &pub_input.map(Fr::from))
                .expect_err("Verification must fail");

        assert_eq!(failures.len(), 1);
        expect_gate_failure(&failures[0], "Indicator sum gate");
    }

    #[test]
    fn index_witness_is_constrained() {
        let circuit = TestCircuit::new([1, 0, 0, 0, 0, 0], 1);
        let pub_input = [1];

        let failures =
            expect_prover_success_and_run_verification(circuit, &pub_input.map(Fr::from))
                .expect_err("Verification must fail");

        assert_eq!(failures.len(), 1);
        expect_gate_failure(&failures[0], "Token index gate");
    }

    #[test]
    fn index_pub_input_is_constrained() {
        let circuit = TestCircuit::new([1, 0, 0, 0, 0, 0], 0);
        let pub_input = [1];

        let failures =
            expect_prover_success_and_run_verification(circuit, &pub_input.map(Fr::from))
                .expect_err("Verification must fail");

        expect_instance_permutation_failures(&failures, "Token index", 0);
    }
}
