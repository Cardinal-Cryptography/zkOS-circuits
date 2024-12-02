use alloc::{format, string::String, vec};

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Error},
};

use crate::{column_pool::ColumnPool, AssignedCell, Field};

/// Represents a type that can be embedded into a circuit (i.e., converted to an `AssignedCell`).
pub trait Embed<F: Field> {
    /// The resulting type of the embedding. For single values, this would be `AssignedCell<F>`.
    type Embedded;

    /// Embeds the instance into the circuit.
    fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error>;
}

impl<F: Field> Embed<F> for Value<F> {
    type Embedded = AssignedCell<F>;

    fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        let annotation = annotation.into();
        layouter.assign_region(
            || &annotation,
            |mut region| region.assign_advice(|| &annotation, advice_pool.get_any(), 0, || *self),
        )
    }
}

impl<F: Field, E: Embed<F>, const N: usize> Embed<F> for [E; N] {
    type Embedded = [E::Embedded; N];

    fn embed(
        &self,
        layouter: &mut impl Layouter<F>,
        advice_pool: &ColumnPool<Advice>,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        let annotation = annotation.into();
        let mut embedded = vec![];
        for (i, item) in self.iter().enumerate() {
            embedded.push(item.embed(layouter, advice_pool, format!("{}[{}]", annotation, i))?);
        }
        Ok(embedded.try_into().map_err(|_| ()).expect("Safe unwrap"))
    }
}
