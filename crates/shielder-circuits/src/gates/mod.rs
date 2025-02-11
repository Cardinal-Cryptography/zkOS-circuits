use alloc::collections::BTreeSet;

use halo2_proofs::{
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, ErrorFront},
};

use crate::{
    column_pool::{ColumnPool, ConfigPhase},
    curve_arithmetic::GrumpkinPoint,
    synthesizer::Synthesizer,
    AssignedCell, Fr,
};

pub mod membership;
pub mod point_double;
pub mod points_add;
pub mod scalar_multiply;
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
    type Advice;

    /// Register the gate in the `ConstraintSystem`. It will use the provided `pool` to maintain
    /// needed columns.
    fn create_gate(
        cs: &mut ConstraintSystem<Fr>,
        pool: &mut ColumnPool<Advice, ConfigPhase>,
    ) -> Self {
        let advice = Self::organize_advice_columns(pool, cs);
        Self::create_gate_custom(cs, advice)
    }

    /// Register the gate in the `ConstraintSystem` with already prepared advice columns.
    fn create_gate_custom(cs: &mut ConstraintSystem<Fr>, advice: Self::Advice) -> Self;

    /// Apply the gate in a new region. The gate MUST enable its selector, copy (constrained if
    /// applicable) the inputs to the region and return new `Gate::Values` struct with the newly
    /// created assigned cells.
    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: Self::Input,
    ) -> Result<(), ErrorFront>;

    /// Organize the advices in a way that the gate expects them to be passed during creation.
    ///
    /// This should be treated as a suggestion, not a requirement. The gate consumer is free to pass
    /// `advice: Self::Advice` in any way they see fit.
    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advice;
}

pub fn ensure_unique_columns(advice: &[Column<Advice>]) {
    let set = BTreeSet::from_iter(advice.iter().map(|column| column.index()));
    assert_eq!(set.len(), advice.len(), "Advice columns must be unique");
}

pub fn copy_grumpkin_advices(
    assigned_point: &GrumpkinPoint<AssignedCell>,
    annotation: &str,
    region: &mut Region<'_, Fr>,
    columns: [Column<Advice>; 3],
    advice_offset: usize,
) -> Result<GrumpkinPoint<AssignedCell>, Error> {
    ensure_unique_columns(&columns);

    let x = assigned_point.x.copy_advice(
        || alloc::format!("{}[x]", annotation),
        region,
        columns[0],
        advice_offset,
    )?;
    let y = assigned_point.y.copy_advice(
        || alloc::format!("{}[y]", annotation),
        region,
        columns[1],
        advice_offset,
    )?;
    let z = assigned_point.z.copy_advice(
        || alloc::format!("{}[z]", annotation),
        region,
        columns[2],
        advice_offset,
    )?;
    Ok(GrumpkinPoint::new(x, y, z))
}
