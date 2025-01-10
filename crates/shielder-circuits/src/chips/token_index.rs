use core::{array, marker::PhantomData};

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};
use strum::IntoEnumIterator;
use strum_macros::{EnumCount, EnumIter};

use crate::{
    column_pool::ColumnPool, consts::NUM_TOKENS, instance_wrapper::InstanceWrapper, todo::Todo,
    AssignedCell, FieldExt,
};

pub mod off_circuit {
    use core::array;

    use halo2_proofs::circuit::Value;

    use crate::{consts::NUM_TOKENS, FieldExt};

    pub fn index_from_indicators<F: FieldExt>(indicators: &[F; NUM_TOKENS]) -> F {
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

    pub fn index_from_indicator_values<F: FieldExt>(
        indicators: &[Value<F>; NUM_TOKENS],
    ) -> Value<F> {
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

// TODO: Replace the hacky underconstrained index production with a gate application.
// TODO: Constrain indicators to the set {0,1}.
// TODO: Constrain that exactly one indicator has value 1.
// A chip that manages the token index indicator variables and related constraints.
#[derive(Clone, Debug)]
pub struct TokenIndexChip<F: FieldExt> {
    advice_pool: ColumnPool<Advice>,
    public_inputs: InstanceWrapper<TokenIndexInstance>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> TokenIndexChip<F> {
    pub fn new(
        advice_pool: ColumnPool<Advice>,
        public_inputs: InstanceWrapper<TokenIndexInstance>,
    ) -> Self {
        Self {
            advice_pool,
            public_inputs,
            _marker: PhantomData,
        }
    }

    /// Temporary hack: the function should apply a gate to produce the index from indicators,
    /// by the formula `index = 0 * indicators[0] + 1 * indicators[1] + 2 * indicators[2] + ...`,
    /// but for now it just produces a cell with an unconstrained value.
    pub fn constrain_index<Constraints: From<TokenIndexConstraints> + Ord + IntoEnumIterator>(
        &self,
        layouter: &mut impl Layouter<F>,
        indicators: &[AssignedCell<F>; NUM_TOKENS],
        todo: &mut Todo<Constraints>,
    ) -> Result<(), Error> {
        let values = array::from_fn(|i| indicators[i].value().cloned());
        let index = off_circuit::index_from_indicator_values(&values);

        let cell = layouter.assign_region(
            || "Token index",
            |mut region| {
                region.assign_advice(|| "Token index", self.advice_pool.get_any(), 0, || index)
            },
        )?;

        self.public_inputs
            .constrain_cells(layouter, [(cell, TokenIndexInstance::TokenIndex)])?;
        todo.check_off(Constraints::from(
            TokenIndexConstraints::TokenIndexInstanceIsConstrainedToAdvice,
        ))
    }
}
