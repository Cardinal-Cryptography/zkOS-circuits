use alloc::vec;

use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use macros::embeddable;

use crate::{
    column_pool::{AccessColumn, ConfigPhase},
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell, Fr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ToAffine {
    point_projective: [Column<Advice>; 3],
    point_affine: [Column<Advice>; 2],
    selector: Selector,
}
