use halo2_proofs::plonk::ErrorFront;

use crate::{
    curve_arithmetic::GrumpkinPointAffine,
    gates::{
        is_point_on_curve_affine::{IsPointOnCurveAffineGate, IsPointOnCurveAffineGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct IsPointOnCurveAffineChipInput<T> {
    pub point: GrumpkinPointAffine<T>,
}

/// Chip that checks whether a point in affine coordinates is on the Grumpkin curve.
#[derive(Clone, Debug)]
pub struct IsPointOnCurveAffineChip {
    pub gate: IsPointOnCurveAffineGate,
}

impl IsPointOnCurveAffineChip {
    pub fn new(gate: IsPointOnCurveAffineGate) -> Self {
        Self { gate }
    }

    pub fn is_point_on_curve_affine(
        &self,
        synthesizer: &mut impl Synthesizer,
        IsPointOnCurveAffineChipInput { point }: &IsPointOnCurveAffineChipInput<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        self.gate.apply_in_new_region(
            synthesizer,
            IsPointOnCurveAffineGateInput {
                point: point.clone(),
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use alloc::{vec, vec::Vec};

    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, ff::PrimeField},
        plonk::{Advice, Circuit, ConstraintSystem, ErrorFront},
    };

    use super::{IsPointOnCurveAffineChip, IsPointOnCurveAffineChipInput};
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        curve_arithmetic::GrumpkinPointAffine,
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
    };

    #[derive(Clone, Debug, Default)]
    struct IsPointOnCurveAffineCircuit(IsPointOnCurveAffineChipInput<Fr>);

    impl Circuit<Fr> for IsPointOnCurveAffineCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            IsPointOnCurveAffineChip,
        );

        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let configs_builder = ConfigsBuilder::new(meta).with_is_point_on_curve_affine_chip();
            let chip = configs_builder.is_point_on_curve_affine_chip();

            (configs_builder.finish(), chip)
        }

        fn synthesize(
            &self,
            (column_pool, chip): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            let IsPointOnCurveAffineChipInput { point } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let point = point.embed(&mut synthesizer, "P")?;

            chip.is_point_on_curve_affine(
                &mut synthesizer,
                &IsPointOnCurveAffineChipInput { point },
            )?;

            Ok(())
        }
    }

    fn input(point: GrumpkinPointAffine<Fr>) -> IsPointOnCurveAffineChipInput<Fr> {
        IsPointOnCurveAffineChipInput { point }
    }

    fn verify(input: IsPointOnCurveAffineChipInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = IsPointOnCurveAffineCircuit(input);
        MockProver::run(4, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn is_random_point_on_curve() {
        let mut rng = rng();
        let point: GrumpkinPointAffine<Fr> = GrumpkinPointAffine::random(&mut rng).into();
        let input = input(point);
        assert!(verify(input).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let point: GrumpkinPointAffine<Fr> =
            GrumpkinPointAffine::new(Fr::from_u128(1), Fr::from_u128(2));
        assert!(verify(input(point)).is_err());
    }
}
