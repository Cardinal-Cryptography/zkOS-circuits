use halo2_proofs::{circuit::Value, plonk::ErrorFront};

use crate::{
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    gates::{
        point_double::{PointDoubleGate, PointDoubleGateInput},
        to_affine::{ToAffineGate, ToAffineGateInput},
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
        let point_affine_value = curve_arithmetic::projective_to_affine(
            point_projective.clone().into(),
            point_projective_z_inverse.value().cloned(),
        );
        let point_affine = point_affine_value.embed(synthesizer, "point_affine")?;

        self.gate.apply_in_new_region(
            synthesizer,
            ToAffineGateInput {
                point_projective: point_projective.clone(),
                point_affine: point_affine.clone(),
                point_projective_z_inverse: point_projective_z_inverse.clone(),
            },
        )?;

        Ok(ToAffineChipOutput { point_affine })
    }
}

#[cfg(test)]
mod tests {

    use std::{vec, vec::Vec};

    use halo2_proofs::{
        arithmetic::Field,
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

    #[derive(Clone, Debug, Default)]
    struct ToAffineCircuit(ToAffineChipInput<Fr>);

    impl Circuit<Fr> for ToAffineCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            ToAffineChip,
            Column<Instance>,
        );

        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            // public input column
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            // register chip
            let configs_builder = ConfigsBuilder::new(meta);
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            todo!()
        }
    }
}
