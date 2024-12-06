use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};

use crate::Field;

pub mod membership;
pub mod range_check;
pub mod sum;

/// `Gate` expresses a concept of a gadget in a circuit that:
///   1. Takes in some values (assigned cells).
///   2. Within a dedicated region, constrained-copies the inputs to the region, enables a selector
///      and applies some constraints.
pub trait Gate<F: Field>: Sized {
    /// The type that represents the values structure that the gate operates on.
    type Values;
    /// How the gate expects advice columns to be passed to it during creation.
    type Advices;

    /// Register the gate in the `ConstraintSystem`. It should create a new gate instance.
    fn create_gate(cs: &mut ConstraintSystem<F>, advice: Self::Advices) -> Self;

    /// Apply the gate in a new region. The gate MUST enable its selector, copy (constrained if
    /// applicable) the inputs to the region and return new `Gate::Values` struct with the newly
    /// created assigned cells.
    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<F>,
        input: Self::Values,
    ) -> Result<(), Error>;
}
