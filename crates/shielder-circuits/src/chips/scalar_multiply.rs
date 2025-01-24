use halo2_proofs::{circuit::Value, plonk::Error};

use super::point_double::PointDoubleChip;
use crate::{
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{points_add::PointsAddGate, Gate},
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct ScalarMultiplyChipInput<T> {
    pub n: T,
    pub p: GrumpkinPoint<T>,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct ScalarMultiplyChipOutput<T> {
    pub r: GrumpkinPoint<T>,
}

/// Chip that computes the result of adding a point P on the grumpoin to itself n times.
///
/// nP = S
#[derive(Clone, Debug)]
pub struct ScalarMultiplyChip {
    pub points_add: PointsAddGate,
    pub point_double: PointDoubleChip,
}

impl ScalarMultiplyChip {
    pub fn new(points_add: PointsAddGate, point_double: PointDoubleChip) -> Self {
        Self {
            point_double,
            points_add,
        }
    }
}
