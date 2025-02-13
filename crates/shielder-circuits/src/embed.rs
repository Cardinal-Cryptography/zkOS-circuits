use alloc::{format, string::String, vec, vec::Vec};

use halo2_proofs::plonk::ErrorFront;

use crate::{curve_arithmetic::GrumpkinPoint, synthesizer::Synthesizer, AssignedCell, Fr, Value};

/// Represents a type that can be embedded into a circuit (i.e., converted to an `AssignedCell`).
pub trait Embed {
    /// The resulting type of the embedding. For single values, this would be `AssignedCell`.
    type Embedded;

    /// Embeds the instance into the circuit.
    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, ErrorFront>;
}

impl Embed for Fr {
    type Embedded = AssignedCell;

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, ErrorFront> {
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
    ) -> Result<Self::Embedded, ErrorFront> {
        (*self).embed(synthesizer, annotation)
    }
}

impl Embed for Value {
    type Embedded = AssignedCell;

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, ErrorFront> {
        synthesizer.assign_value(annotation, *self)
    }
}

impl<E: Embed, const N: usize> Embed for [E; N] {
    type Embedded = [E::Embedded; N];

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, ErrorFront> {
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
    ) -> Result<Self::Embedded, ErrorFront> {
        let annotation = annotation.into();
        let mut embedded = vec![];
        for (i, item) in self.iter().enumerate() {
            embedded.push(item.embed(synthesizer, format!("{}[{}]", annotation, i))?);
        }
        Ok(embedded)
    }
}

impl<E: Embed> Embed for GrumpkinPoint<E>
where
    E::Embedded: Clone,
{
    type Embedded = GrumpkinPoint<E::Embedded>;

    fn embed(
        &self,
        synthesizer: &mut impl Synthesizer,
        annotation: impl Into<String>,
    ) -> Result<Self::Embedded, ErrorFront> {
        let embedded_arr = [&self.x, &self.y, &self.z].embed(synthesizer, annotation)?;
        Ok(GrumpkinPoint {
            x: embedded_arr[0].clone(),
            y: embedded_arr[1].clone(),
            z: embedded_arr[2].clone(),
        })
    }
}
