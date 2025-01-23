use alloc::vec::Vec;

use halo2_proofs::{
    arithmetic::CurveExt,
    circuit::{Layouter, Value},
    halo2curves::grumpkin::G1,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::{ColumnPool, SynthesisPhase},
    curve_operations,
    gates::{
        point_double::{PointDoubleGate, PointDoubleGateInput},
        Gate,
    },
    AssignedCell, F,
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
        layouter: &mut impl Layouter<F>,
        column_pool: &ColumnPool<Advice, SynthesisPhase>,
        input: &PointDoubleChipInput<AssignedCell>,
    ) -> Result<PointDoubleChipOutput<AssignedCell>, Error> {
        let b3 = Value::known(G1::b() + G1::b() + G1::b());
        let s_value = curve_operations::point_double(
            [
                input.p[0].value().copied(),
                input.p[1].value().copied(),
                input.p[2].value().copied(),
            ],
            b3,
        );

        let s: Vec<AssignedCell> = s_value
            .into_iter()
            .map(|value| {
                layouter
                    .assign_region(
                        || "s",
                        |mut region| {
                            region.assign_advice(|| "s", column_pool.get_any(), 0, || value)
                        },
                    )
                    .expect("can assign advice from a value")
            })
            .collect();

        let s: [AssignedCell; 3] = s.try_into().unwrap_or_else(|v: Vec<AssignedCell>| {
            panic!("Expected a Vec of length {} but it was {}", 3, v.len())
        });

        let gate_input = PointDoubleGateInput {
            p: input.p.clone(),
            s: s.clone(),
        };

        self.gate.apply_in_new_region(layouter, gate_input)?;

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
            let p = p.embed(&mut layouter, &column_pool, "P")?;

            let PointDoubleChipOutput { s } =
                chip.point_double(&mut layouter, &column_pool, &PointDoubleChipInput { p })?;

            layouter.constrain_instance(s[0].cell(), instance, 0)?;
            layouter.constrain_instance(s[1].cell(), instance, 1)?;
            layouter.constrain_instance(s[2].cell(), instance, 2)?;

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
