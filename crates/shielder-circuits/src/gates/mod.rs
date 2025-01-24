use alloc::collections::BTreeSet;

use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};

#[cfg(test)]
use crate::column_pool::{ColumnPool, ConfigPhase};
use crate::{synthesizer::Synthesizer, Fr};

pub mod balance_increase;
pub mod is_binary;
pub mod linear_equation;
pub mod membership;
pub mod point_double;
pub mod points_add;
pub mod sum;

#[cfg(test)]
pub mod test_utils;

/// `Gate` expresses a concept of a gadget in a circuit that:
///   1. Takes in some values (assigned cells).
///   2. Within a dedicated region, constrained-copies the inputs to the region, enables a selector
///      and applies some constraints.
pub trait Gate: Sized {
    /// Represents the value structure that the gate operates on.
    type Input;
    /// How the gate expects advice columns to be passed to it during creation.
    type Advices;

    /// Register the gate in the `ConstraintSystem`. It should create a new gate instance.
    fn create_gate(cs: &mut ConstraintSystem<Fr>, advice: Self::Advices) -> Self;

    /// Apply the gate in a new region. The gate MUST enable its selector, copy (constrained if
    /// applicable) the inputs to the region and return new `Gate::Values` struct with the newly
    /// created assigned cells.
    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: Self::Input,
    ) -> Result<(), Error>;

    /// Organize the advices in a way that the gate expects them to be passed during creation.
    ///
    /// This should be used only in tests. In production, it shouldn't be a gate responsibility to
    /// govern advice columns.
    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advices;
}

fn ensure_unique_columns(advice: &[Column<Advice>]) {
    let set = BTreeSet::from_iter(advice.iter().map(|column| column.index()));
    assert_eq!(set.len(), advice.len(), "Advice columns must be unique");
}
