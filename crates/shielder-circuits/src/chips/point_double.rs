use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{
        point_double::{PointDoubleGate, PointDoubleGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct PointDoubleChipInput<T> {
    pub p: [T; 3],
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct PointDoubleChipOutput<T> {
    pub s: [T; 3],
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
    ) -> Result<PointDoubleChipOutput<AssignedCell>, Error> {
        let GrumpkinPoint { x, y, z } = curve_arithmetic::point_double(
            GrumpkinPoint::new(
                input.p[0].value().copied(),
                input.p[1].value().copied(),
                input.p[2].value().copied(),
            ),
            Value::known(*GRUMPKIN_3B),
        );

        let s = [x, y, z].embed(synthesizer, "S")?;

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
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
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
        ) -> Result<(), Error> {
            let PointDoubleChipInput { p } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let p = p.embed(&mut synthesizer, "P")?;

            let PointDoubleChipOutput { s } =
                chip.point_double(&mut synthesizer, &PointDoubleChipInput { p })?;

            synthesizer.constrain_instance(s[0].cell(), instance, 0)?;
            synthesizer.constrain_instance(s[1].cell(), instance, 1)?;
            synthesizer.constrain_instance(s[2].cell(), instance, 2)?;

            Ok(())
        }
    }

    fn input(p: G1) -> PointDoubleChipInput<Fr> {
        PointDoubleChipInput { p: [p.x, p.y, p.z] }
    }

    fn verify(
        input: PointDoubleChipInput<Fr>,
        expected: PointDoubleChipOutput<Fr>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = PointDoubleCircuit(input);
        MockProver::run(
            4,
            &circuit,
            vec![vec![expected.s[0], expected.s[1], expected.s[2]]],
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
        let output = PointDoubleChipOutput {
            s: [expected.x, expected.y, expected.z],
        };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn double_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());

        let expected = p + p;

        let input = input(p);
        let output = PointDoubleChipOutput {
            s: [expected.x, expected.y, expected.z],
        };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let s = G1::random(rng.clone());

        let input = input(p);
        let output = PointDoubleChipOutput { s: [s.x, s.y, s.z] };

        assert!(verify(input, output).is_err());
    }
}
