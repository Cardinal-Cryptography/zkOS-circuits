use halo2_proofs::plonk::ErrorFront;

use crate::{
    curve_arithmetic::{self, GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    gates::{
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
            let configs_builder = ConfigsBuilder::new(meta).with_to_affine_chip();
            let chip = configs_builder.to_affine_chip();

            (configs_builder.finish(), chip, instance)
        }

        fn synthesize(
            &self,
            (column_pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            let ToAffineChipInput {
                point_projective,
                point_projective_z_inverse,
            } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let point_projective = point_projective.embed(&mut synthesizer, "P")?;
            let z_inverse = point_projective_z_inverse.embed(&mut synthesizer, "z_inverse")?;

            let ToAffineChipOutput { point_affine } = chip.to_affine(
                &mut synthesizer,
                &ToAffineChipInput {
                    point_projective,
                    point_projective_z_inverse: z_inverse,
                },
            )?;

            synthesizer.constrain_instance(point_affine.x.cell(), instance, 0)?;
            synthesizer.constrain_instance(point_affine.y.cell(), instance, 1)?;

            Ok(())
        }
    }

    fn input(
        point_projective: GrumpkinPoint<Fr>,
        point_projective_z_inverse: Fr,
    ) -> ToAffineChipInput<Fr> {
        ToAffineChipInput {
            point_projective,
            point_projective_z_inverse,
        }
    }

    fn verify(
        input: ToAffineChipInput<Fr>,
        expected: ToAffineChipOutput<Fr>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = ToAffineCircuit(input);
        MockProver::run(
            4,
            &circuit,
            vec![vec![expected.point_affine.x, expected.point_affine.y]],
        )
        .expect("Mock prover should run")
        .verify()
    }

    #[test]
    fn coordinate_conversion() {
        let mut rng = rng();

        let point_projective: GrumpkinPoint<Fr> = GrumpkinPoint::random(&mut rng).into();
        let point_affine: GrumpkinPointAffine<Fr> = point_projective.into();
        let z_inverse = point_projective
            .z
            .invert()
            .expect("z coordinate has an inverse");

        let input = input(point_projective, z_inverse);
        let output = ToAffineChipOutput { point_affine };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let rng = rng();

        let point_projective: GrumpkinPoint<Fr> = G1::random(&mut rng.clone()).into();
        let point_affine: GrumpkinPointAffine<Fr> = curve_arithmetic::normalize_point(
            curve_arithmetic::point_double(point_projective, *GRUMPKIN_3B),
        )
        .into();
        let z_inverse = point_projective
            .z
            .invert()
            .expect("z coordinate has an inverse");

        let input = input(point_projective, z_inverse);
        let output = ToAffineChipOutput { point_affine };

        assert!(verify(input, output).is_err());
    }
}
