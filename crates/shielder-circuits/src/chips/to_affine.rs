use halo2_proofs::{circuit::Value, plonk::ErrorFront};

use crate::{
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    gates::{
        point_double::{PointDoubleGate, PointDoubleGateInput},
        to_affine::ToAffineGate,
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct ToAffineChipInput<T> {
    pub point_projective: GrumpkinPoint<T>,
    pub point_projective_z_inverse: T,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct ToAffineChipOutput<T> {
    pub point_affine: GrumpkinPointAffine<T>,
}

/// Chip that converts a point in projective coordinates to affine coordinates.
#[derive(Clone, Debug)]
pub struct ToAffineChip {
    pub gate: ToAffineGate,
}

impl ToAffineChip {
    pub fn new(gate: ToAffineGate) -> Self {
        Self { gate }
    }

    pub fn to_affine(
        &self,
        synthesizer: &mut impl Synthesizer,
        ToAffineChipInput {
            point_projective,
            point_projective_z_inverse,
        }: &ToAffineChipInput<AssignedCell>,
    ) -> Result<ToAffineChipOutput<AssignedCell>, ErrorFront> {
        //

        // let point_affine: GrumpkinPointAffine<AssignedCell> = point_projective.into();

        //
        todo!()
    }
}
