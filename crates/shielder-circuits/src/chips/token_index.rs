use core::array;

use halo2_proofs::plonk::Error;
use strum::IntoEnumIterator;
use strum_macros::{EnumCount, EnumIter};

use crate::{
    consts::NUM_TOKENS, instance_wrapper::InstanceWrapper, synthesizer::Synthesizer, todo::Todo,
    AssignedCell,
};

pub mod off_circuit {
    use core::array;

    use halo2_proofs::arithmetic::Field;

    use crate::{consts::NUM_TOKENS, Fr, Value};

    pub fn index_from_indicators(indicators: &[Fr; NUM_TOKENS]) -> Fr {
        // All `indicators` must be from {0, 1}.
        assert!(indicators.iter().all(|&x| x == Fr::ZERO || x == Fr::ONE));
        // Exactly one indicator must be equal to 1.
        assert_eq!(1, indicators.iter().filter(|&&x| x == Fr::ONE).count());

        let index = indicators
            .iter()
            .position(|&x| x == Fr::ONE)
            .expect("at least 1 positive indicator");
        Fr::from(index as u64)
    }

    pub fn index_from_indicator_values(indicators: &[Value; NUM_TOKENS]) -> Value {
        // All indicators must be from {0, 1}.
        for indicator in indicators.iter() {
            indicator.assert_if_known(|v| *v == Fr::ZERO || *v == Fr::ONE);
        }
        // Exactly one indicator must be equal to 1.
        indicators
            .iter()
            .copied()
            .reduce(|a, b| a + b)
            .expect("at least one indicator")
            .assert_if_known(|v| *v == Fr::ONE);

        // Produce the index by calculating Σ i * indicators[i].
        let multiplied_indicators: [Value; NUM_TOKENS] =
            array::from_fn(|i| indicators[i].map(|v| v * Fr::from(i as u64)));
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

// TODO: Replace the hacky underconstrained index production with a gate application.
// TODO: Constrain indicators to the set {0,1}.
// TODO: Constrain that exactly one indicator has value 1.
// A chip that manages the token index indicator variables and related constraints.
#[derive(Clone, Debug)]
pub struct TokenIndexChip {
    public_inputs: InstanceWrapper<TokenIndexInstance>,
}

impl TokenIndexChip {
    pub fn new(public_inputs: InstanceWrapper<TokenIndexInstance>) -> Self {
        Self { public_inputs }
    }

    /// Temporary hack: the function should apply a gate to produce the index from indicators,
    /// by the formula `index = 0 * indicators[0] + 1 * indicators[1] + 2 * indicators[2] + ...`,
    /// but for now it just produces a cell with an unconstrained value.
    pub fn constrain_index<Constraints: From<TokenIndexConstraints> + Ord + IntoEnumIterator>(
        &self,
        synthesizer: &mut impl Synthesizer,
        indicators: &[AssignedCell; NUM_TOKENS],
        todo: &mut Todo<Constraints>,
    ) -> Result<(), Error> {
        let values = array::from_fn(|i| indicators[i].value().cloned());
        let index = off_circuit::index_from_indicator_values(&values);
        let cell = synthesizer.assign_value("Token index", index)?;

        self.public_inputs
            .constrain_cells(synthesizer, [(cell, TokenIndexInstance::TokenIndex)])?;
        todo.check_off(Constraints::from(
            TokenIndexConstraints::TokenIndexInstanceIsConstrainedToAdvice,
        ))
    }
}
