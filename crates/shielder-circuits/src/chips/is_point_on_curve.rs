use halo2_proofs::plonk::ErrorFront;

use crate::{
    curve_arithmetic::{self, GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    gates::{
        is_point_on_curve::{IsPointOnCurveGate, IsPointOnCurveGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct IsPointOnCurveChipInput<T> {
    pub point: GrumpkinPoint<T>,
}

/// Chip that checks a point in projective coordinates is on the Grumpkin curve.
#[derive(Clone, Debug)]
pub struct IsPointOnCurveChip {
    pub gate: IsPointOnCurveGate,
}

impl IsPointOnCurveChip {
    pub fn new(gate: IsPointOnCurveGate) -> Self {
        Self { gate }
    }

    pub fn is_point_on_curve(
        &self,
        synthesizer: &mut impl Synthesizer,
        IsPointOnCurveChipInput { point }: &IsPointOnCurveChipInput<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        self.gate.apply_in_new_region(
            synthesizer,
            IsPointOnCurveGateInput {
                point: point.clone(),
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, group::Group, grumpkin::G1},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Instance},
    };

    use super::{IsPointOnCurveChip, IsPointOnCurveChipInput};
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
    };

    #[derive(Clone, Debug, Default)]
    struct IsPointOnCurveCircuit(IsPointOnCurveChipInput<Fr>);

    impl Circuit<Fr> for IsPointOnCurveCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            IsPointOnCurveChip,
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
            // let configs_builder = ConfigsBuilder::new(meta).with_to_affine_chip();
            // let chip = configs_builder.to_affine_chip();

            // (configs_builder.finish(), chip, instance)

            todo!()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), halo2_frontend::plonk::Error> {
            todo!()
        }
    }
}
