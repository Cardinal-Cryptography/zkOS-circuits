use halo2_proofs::plonk::ErrorFront;

use crate::{
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{
        point_double::{PointDoubleGate, PointDoubleGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell, Value,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct PointDoubleChipInput<T> {
    pub p: GrumpkinPoint<T>,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct PointDoubleChipOutput<T> {
    pub s: GrumpkinPoint<T>,
}

/// Chip that doubles a point on a Grumpkin curve.
///
/// P + Q = S
#[derive(Clone, Debug)]
pub struct PointDoubleChip {
    pub gate: PointDoubleGate,
}

impl PointDoubleChip {
    pub fn new(gate: PointDoubleGate) -> Self {
        Self { gate }
    }

    pub fn point_double(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: &PointDoubleChipInput<AssignedCell>,
    ) -> Result<PointDoubleChipOutput<AssignedCell>, ErrorFront> {
        let s_value = curve_arithmetic::point_double::<Value>(input.p.clone().into());

        let s = s_value.embed(synthesizer, "S")?;

        let gate_input = PointDoubleGateInput {
            p: input.p.clone(),
            s: s.clone(),
        };

        self.gate.apply_in_new_region(synthesizer, gate_input)?;

        Ok(PointDoubleChipOutput { s })
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
    struct PointDoubleCircuit(PointDoubleChipInput<Fr>);

    impl Circuit<Fr> for PointDoubleCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            PointDoubleChip,
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
            let configs_builder = ConfigsBuilder::new(meta).with_point_double_chip();
            let chip = configs_builder.point_double_chip();

            (configs_builder.finish(), chip, instance)
        }

        fn synthesize(
            &self,
            (column_pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            let PointDoubleChipInput { p } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let p = p.embed(&mut synthesizer, "P")?;

            let PointDoubleChipOutput { s } =
                chip.point_double(&mut synthesizer, &PointDoubleChipInput { p })?;

            synthesizer.constrain_instance(s.x.cell(), instance, 0)?;
            synthesizer.constrain_instance(s.y.cell(), instance, 1)?;
            synthesizer.constrain_instance(s.z.cell(), instance, 2)?;

            Ok(())
        }
    }

    fn input(p: G1) -> PointDoubleChipInput<Fr> {
        PointDoubleChipInput { p: p.into() }
    }

    fn verify(
        input: PointDoubleChipInput<Fr>,
        expected: PointDoubleChipOutput<Fr>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = PointDoubleCircuit(input);
        MockProver::run(
            4,
            &circuit,
            vec![vec![expected.s.x, expected.s.y, expected.s.z]],
        )
        .expect("Mock prover should run")
        .verify()
    }

    #[test]
    fn double_point_at_infinity() {
        let p = G1 {
            x: Fr::ZERO,
            y: Fr::ONE,
            z: Fr::ZERO,
        };

        let expected = p + p;

        let input = input(p);
        let output = PointDoubleChipOutput { s: expected.into() };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn double_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());

        let expected = p + p;

        let input = input(p);
        let output = PointDoubleChipOutput { s: expected.into() };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let s = G1::random(rng.clone());

        let input = input(p);
        let output = PointDoubleChipOutput { s: s.into() };

        assert!(verify(input, output).is_err());
    }
}
