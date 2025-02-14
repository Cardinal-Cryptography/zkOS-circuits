use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr, plonk::ErrorFront};

use crate::{
    curve_arithmetic::{self, GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    gates::{
        point_double::{PointDoubleGate, PointDoubleGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell, Value,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct ToProjectiveChipInput<T> {
    pub point_affine: GrumpkinPointAffine<T>,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct ToProjectiveChipOutput<T> {
    pub point_projective: GrumpkinPoint<T>,
}

/// Chip that converts between a point in affine to a point in projective coordinates
#[derive(Clone, Debug)]
pub struct ToProjectiveChip;

impl ToProjectiveChip {
    pub fn new() -> Self {
        Self
    }

    pub fn to_projective(
        &self,
        synthesizer: &mut impl Synthesizer,
        ToProjectiveChipInput { point_affine }: &ToProjectiveChipInput<AssignedCell>,
    ) -> Result<ToProjectiveChipOutput<AssignedCell>, ErrorFront> {
        let GrumpkinPointAffine { x, y } = point_affine;

        let one = synthesizer.assign_constant("ONE", Fr::ONE)?;

        Ok(ToProjectiveChipOutput {
            point_projective: GrumpkinPoint {
                x: x.clone(),
                y: y.clone(),
                z: one,
            },
        })
    }
}

#[cfg(test)]
mod tests {

    use std::{vec, vec::Vec};

    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, group::Group, grumpkin::G1},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Instance},
    };

    use super::*;
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
    };
}
