use core::{array, marker::PhantomData};

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{column_pool::ColumnPool, consts::NUM_TOKENS, AssignedCell, FieldExt};

pub mod off_circuit {
    use core::array;

    use halo2_proofs::circuit::Value;

    use crate::{consts::NUM_TOKENS, FieldExt};

    pub fn index_from_indicators<F: FieldExt>(indicators: &[F; NUM_TOKENS]) -> F {
        let index = indicators
            .iter()
            .position(|&x| x == F::ONE)
            .expect("there must be 1 positive indicator");
        F::from(index as u64)
    }

    pub fn index_from_indicator_values<F: FieldExt>(
        indicators: &[Value<F>; NUM_TOKENS],
    ) -> Value<F> {
        let multiplied_indicators: [Value<F>; NUM_TOKENS] =
            array::from_fn(|i| indicators[i].map(|v| v * F::from(i as u64)));
        multiplied_indicators
            .iter()
            .copied()
            .reduce(|a, b| a + b)
            .expect("at least one indicator")
    }
}

// TODO: Replace the hacky underconstrained index production with a gate application.
// TODO: Constrain indicators to the set {0,1}.
// TODO: Constrain that exactly one indicator has value 1.
// A chip that manages the token index indicator variables and related constraints.
#[derive(Clone, Debug)]
pub struct TokenIndexChip<F: FieldExt> {
    advice_pool: ColumnPool<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> TokenIndexChip<F> {
    pub fn new(advice_pool: ColumnPool<Advice>) -> Self {
        Self {
            advice_pool,
            _marker: PhantomData,
        }
    }

    /// Temporary hack: the function should apply a gate to produce the index from indicators,
    /// by the formula `index = 0 * indicators[0] + 1 * indicators[1] + 2 * indicators[2] + ...`,
    /// but for now it just produces a cell with an unconstrained value.
    pub fn index_from_indicators(
        &self,
        layouter: &mut impl Layouter<F>,
        indicators: &[AssignedCell<F>; NUM_TOKENS],
    ) -> Result<AssignedCell<F>, Error> {
        let values = array::from_fn(|i| indicators[i].value().cloned());
        let index = off_circuit::index_from_indicator_values(&values);

        layouter.assign_region(
            || "Token index",
            |mut region| {
                region.assign_advice(|| "Token index", self.advice_pool.get_any(), 0, || index)
            },
        )
    }
}
