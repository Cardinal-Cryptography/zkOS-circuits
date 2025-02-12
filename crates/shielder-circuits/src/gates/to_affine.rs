use alloc::vec;

use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use macros::embeddable;

use super::copy_grumpkin_advices;
use crate::{
    column_pool::{AccessColumn, ColumnPool, ConfigPhase},
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ToAffine {
    point_projective: [Column<Advice>; 3],
    point_affine: [Column<Advice>; 2],
    selector: Selector,
}

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "ToAffineGateInput<Fr>",
    embedded = "ToAffineGateInput<crate::AssignedCell>"
)]
pub struct ToAffineGateInput<T> {
    pub point_projective: GrumpkinPoint<T>,
    pub point_affine: GrumpkinPointAffine<T>,
}
