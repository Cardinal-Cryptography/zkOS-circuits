use halo2_proofs::plonk::ErrorFront;

use crate::{
    curve_arithmetic::{self},
    embed::Embed,
    gates::{
        is_point_on_curve_affine::{IsPointOnCurveAffineGate, IsPointOnCurveAffineGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell,
};

/// chip that checks whether x^3-17 forms a quadratic residue on the Grumpkin curve
#[derive(Clone, Debug)]
pub struct IsQuadraticResidueChip {
    pub gate: IsPointOnCurveAffineGate,
}

impl IsQuadraticResidueChip {
    pub fn new(gate: IsPointOnCurveAffineGate) -> Self {
        Self { gate }
    }

    pub fn check_coordinate(
        &self,
        synthesizer: &mut impl Synthesizer,
        x: AssignedCell,
    ) -> Result<(), ErrorFront> {
        let x_value = x.value().cloned();
        let y_squared_value = curve_arithmetic::quadratic_residue_given_x_affine(x_value);
        let y_squared = y_squared_value.embed(synthesizer, "y^2")?;

        self.gate
            .apply_in_new_region(synthesizer, IsPointOnCurveAffineGateInput { x, y_squared })?;

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

    use super::IsQuadraticResidueChip;
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        curve_arithmetic::GrumpkinPointAffine,
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
    };

    #[derive(Clone, Debug, Default)]
    struct IsQuadraticResidueCircuit(Fr);

    impl Circuit<Fr> for IsQuadraticResidueCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            IsQuadraticResidueChip,
        );

        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let configs_builder = ConfigsBuilder::new(meta).with_is_quadratic_residue_chip();
            let chip = configs_builder.is_quadratic_residue_chip();

            (configs_builder.finish(), chip)
        }

        fn synthesize(
            &self,
            (column_pool, chip): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let x = self.0.embed(&mut synthesizer, "x")?;
            chip.check_coordinate(&mut synthesizer, x)?;

            Ok(())
        }
    }

    fn verify(x: Fr) -> Result<(), Vec<VerifyFailure>> {
        let circuit = IsQuadraticResidueCircuit(x);
        MockProver::run(4, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn is_random_point_on_curve() {
        let mut rng = rng();
        let GrumpkinPointAffine { x, .. } = GrumpkinPointAffine::random(&mut rng).into();
        assert!(verify(x).is_ok());
    }

    // TODO
    #[test]
    fn incorrect_inputs() {
        let GrumpkinPointAffine { x, .. } =
            GrumpkinPointAffine::new(Fr::from_u128(1), Fr::from_u128(2));
        assert!(verify(x).is_err());
    }
}
