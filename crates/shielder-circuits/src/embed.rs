use alloc::{format, string::String, vec, vec::Vec};

use halo2_proofs::plonk::Error;

use crate::{synthesizer::Synthesizer, AssignedCell, Fr, Value};

/// Represents a type that can be embedded into a circuit (i.e., converted to an `AssignedCell`).
pub trait Embed {
    /// The resulting type of the embedding. For single values, this would be `AssignedCell`.
    type Embedded;

    /// Embeds the instance into the circuit.
    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error>;
}

impl Embed for Fr {
    type Embedded = AssignedCell;

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        let value = Value::known(*self);
        value.embed(synthesizer, annotation)
    }
}

impl<E: Embed> Embed for &E {
    type Embedded = E::Embedded;

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        (*self).embed(synthesizer, annotation)
    }
}

impl Embed for Value {
    type Embedded = AssignedCell;

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        synthesizer.assign_value(annotation, *self)
    }
}

impl<E: Embed, const N: usize> Embed for [E; N] {
    type Embedded = [E::Embedded; N];

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        Ok(self
            .iter()
            .collect::<Vec<_>>()
            .embed(synthesizer, annotation)?
            .try_into()
            .map_err(|_| ())
            .expect("Safe unwrap"))
    }
}

impl<E: Embed> Embed for Vec<E> {
    type Embedded = Vec<E::Embedded>;

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, Error> {
        let annotation = annotation.into();
        let mut embedded = vec![];
        for (i, item) in self.iter().enumerate() {
            embedded.push(item.embed(synthesizer, format!("{}[{}]", annotation, i))?);
        }
        Ok(embedded)
    }
}
