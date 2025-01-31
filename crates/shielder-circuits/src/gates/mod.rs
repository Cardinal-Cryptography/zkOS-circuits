use alloc::collections::BTreeSet;

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};

#[cfg(test)]
use crate::column_pool::{ColumnPool, ConfigPhase};
use crate::{curve_arithmetic::GrumpkinPoint, synthesizer::Synthesizer, AssignedCell, Fr};

pub mod balance_increase;
pub mod is_binary;
pub mod linear_equation;
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

pub fn copy_grumpkin_advices(
    assigned_point: &GrumpkinPoint<AssignedCell>,
    annotation: &str,
    region: &mut Region<'_, Fr>,
    columns: [Column<Advice>; 3],
    advice_offset: usize,
) -> Result<GrumpkinPoint<AssignedCell>, Error> {
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

pub fn assign_grumpkin_advices(
    point_value: &GrumpkinPoint<Value<Fr>>,
    annotation: &str,
    region: &mut Region<'_, Fr>,
    columns: [Column<Advice>; 3],
    offset: usize,
) -> Result<GrumpkinPoint<AssignedCell>, Error> {
    let x = region.assign_advice(
        || alloc::format!("{}[x]", annotation),
        columns[0],
        offset,
        || point_value.x,
    )?;

    let y = region.assign_advice(
        || alloc::format!("{}[y]", annotation),
        columns[1],
        offset,
        || point_value.y,
    )?;

    let z = region.assign_advice(
        || alloc::format!("{}[z]", annotation),
        columns[2],
        offset,
        || point_value.z,
    )?;

    Ok(GrumpkinPoint::new(x, y, z))
}
