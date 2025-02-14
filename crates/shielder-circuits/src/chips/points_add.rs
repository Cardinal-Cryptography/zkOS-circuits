use halo2_proofs::plonk::ErrorFront;

use crate::{
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{
        points_add::{PointsAddGate, PointsAddGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell, Value,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct PointsAddChipInput<T> {
    pub p: GrumpkinPoint<T>,
    pub q: GrumpkinPoint<T>,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct PointsAddChipOutput<T> {
    pub s: GrumpkinPoint<T>,
}

/// Chip that adds two points on a Grumpkin curve.
///
/// P + Q = S
#[derive(Clone, Debug)]
pub struct PointsAddChip {
    pub gate: PointsAddGate,
}

impl PointsAddChip {
    pub fn new(gate: PointsAddGate) -> Self {
        Self { gate }
    }

    pub fn points_add(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: &PointsAddChipInput<AssignedCell>,
    ) -> Result<PointsAddChipOutput<AssignedCell>, ErrorFront> {
        let s_value =
            curve_arithmetic::points_add::<Value>(input.p.clone().into(), input.q.clone().into());

        let s = s_value.embed(synthesizer, "S")?;

        let gate_input = PointsAddGateInput {
            p: input.p.clone(),
            q: input.q.clone(),
            s: s.clone(),
        };

        self.gate.apply_in_new_region(synthesizer, gate_input)?;

        Ok(PointsAddChipOutput { s })
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
        plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
    };

    use super::{PointsAddChip, PointsAddChipInput, PointsAddChipOutput};
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
    };

    #[derive(Clone, Debug, Default)]
    struct PointsAddCircuit(PointsAddChipInput<Fr>);

    impl Circuit<Fr> for PointsAddCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            PointsAddChip,
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
            // register point add chip
            let configs_builder = ConfigsBuilder::new(meta).with_points_add_chip();
            let chip = configs_builder.points_add_chip();

            (configs_builder.finish(), chip, instance)
        }

        fn synthesize(
            &self,
            (column_pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
            let PointsAddChipInput { p, q } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let p = p.embed(&mut synthesizer, "P")?;
            let q = q.embed(&mut synthesizer, "Q")?;

            let PointsAddChipOutput { s } =
                chip.points_add(&mut synthesizer, &PointsAddChipInput { p, q })?;

            synthesizer.constrain_instance(s.x.cell(), instance, 0)?;
            synthesizer.constrain_instance(s.y.cell(), instance, 1)?;
            synthesizer.constrain_instance(s.z.cell(), instance, 2)?;

            Ok(())
        }
    }

    fn input(p: G1, q: G1) -> PointsAddChipInput<Fr> {
        PointsAddChipInput {
            p: p.into(),
            q: q.into(),
        }
    }

    fn verify(
        input: PointsAddChipInput<Fr>,
        expected: PointsAddChipOutput<Fr>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = PointsAddCircuit(input);
        MockProver::run(
            4,
            &circuit,
            vec![vec![expected.s.x, expected.s.y, expected.s.z]],
        )
        .expect("Mock prover should run")
        .verify()
    }

    #[test]
    fn adding_points_at_infinity() {
        let p = G1 {
            x: Fr::ZERO,
            y: Fr::ONE,
            z: Fr::ZERO,
        };
        let q = G1 {
            x: Fr::ZERO,
            y: Fr::ONE,
            z: Fr::ZERO,
        };
        let expected = p + q;

        let input = input(p, q);
        let output = PointsAddChipOutput { s: expected.into() };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn adding_random_points() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let expected = p + q;

        let input = input(p, q);
        let output = PointsAddChipOutput { s: expected.into() };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let s = G1::random(rng.clone());

        let input = input(p, q);
        let output = PointsAddChipOutput { s: s.into() };

        assert!(verify(input, output).is_err());
    }
}
