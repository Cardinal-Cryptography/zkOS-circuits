use halo2_proofs::plonk::Error;

use crate::{
    curve_arithmetic::GrumpkinPoint,
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
    ) -> Result<(), Error> {
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
    use alloc::{vec, vec::Vec};

    use halo2_proofs::{
        arithmetic::Field,
        circuit::{floor_planner::V1, Layouter},
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, ff::PrimeField},
        plonk::{Advice, Circuit, ConstraintSystem},
    };

    use super::{IsPointOnCurveChip, IsPointOnCurveChipInput};
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        curve_arithmetic::GrumpkinPoint,
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
    };

    #[derive(Clone, Debug, Default)]
    struct IsPointOnCurveCircuit(IsPointOnCurveChipInput<Fr>);

    impl Circuit<Fr> for IsPointOnCurveCircuit {
        type Config = (ColumnPool<Advice, PreSynthesisPhase>, IsPointOnCurveChip);

        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let configs_builder = ConfigsBuilder::new(meta).with_is_point_on_curve_chip();
            let chip = configs_builder.is_point_on_curve_chip();

            (configs_builder.finish(), chip)
        }

        fn synthesize(
            &self,
            (column_pool, chip): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let IsPointOnCurveChipInput { point } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let point = point.embed(&mut synthesizer, "P")?;

            chip.is_point_on_curve(&mut synthesizer, &IsPointOnCurveChipInput { point })?;

            Ok(())
        }
    }

    fn input(point: GrumpkinPoint<Fr>) -> IsPointOnCurveChipInput<Fr> {
        IsPointOnCurveChipInput { point }
    }

    fn verify(input: IsPointOnCurveChipInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = IsPointOnCurveCircuit(input);
        MockProver::run(4, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn is_random_point_on_curve() {
        let mut rng = rng();

        let point: GrumpkinPoint<Fr> = GrumpkinPoint::random(&mut rng).into();
        let input = input(point);
        assert!(verify(input).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let point: GrumpkinPoint<Fr> =
            GrumpkinPoint::new(Fr::from_u128(1), Fr::from_u128(2), Fr::ONE);
        assert!(verify(input(point)).is_err());
    }
}
