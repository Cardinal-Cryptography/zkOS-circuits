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
