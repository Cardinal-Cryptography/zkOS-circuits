use alloc::{format, string::String, vec, vec::Vec};

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::{ColumnPool, SynthesisPhase},
    AssignedCell, F,
};

/// Represents a type that can be embedded into a circuit (i.e., converted to an `AssignedCell`).
pub trait Embed {
    /// The resulting type of the embedding. For single values, this would be `AssignedCell`.
    type Embedded;

    /// Embeds the instance into the circuit.
    fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error>;
}

impl Embed for Fr {
    type Embedded = AssignedCell;

    fn embed(
        &self,
        layouter: &mut impl Layouter<Fr>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        let value = Value::known(*self);
        value.embed(layouter, advice_pool, annotation)
    }
}

impl<E: Embed> Embed for &E {
    type Embedded = E::Embedded;

    fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        (*self).embed(layouter, advice_pool, annotation)
    }
}

impl Embed for Value<F> {
    type Embedded = AssignedCell;

    fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        let annotation = annotation.into();
        layouter.assign_region(
            || &annotation,
            |mut region| region.assign_advice(|| &annotation, advice_pool.get_any(), 0, || *self),
        )
    }
}

impl<E: Embed, const N: usize> Embed for [E; N] {
    type Embedded = [E::Embedded; N];

    fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        Ok(self
            .iter()
            .collect::<Vec<_>>()
            .embed(layouter, advice_pool, annotation)?
            .try_into()
            .map_err(|_| ())
            .expect("Safe unwrap"))
    }
}

impl<E: Embed> Embed for Vec<E> {
    type Embedded = Vec<E::Embedded>;

    fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice, SynthesisPhase>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        let annotation = annotation.into();
        let mut embedded = vec![];
        for (i, item) in self.iter().enumerate() {
            embedded.push(item.embed(layouter, advice_pool, format!("{}[{}]", annotation, i))?);
        }
        Ok(embedded)
    }
}
