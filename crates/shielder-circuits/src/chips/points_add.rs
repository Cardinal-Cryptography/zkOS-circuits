use alloc::vec::Vec;

use halo2_proofs::{
    arithmetic::CurveExt,
    circuit::{Layouter, Value},
    halo2curves::grumpkin::G1,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::ColumnPool,
    curve_operations,
    gates::{
        points_add::{PointsAddGate, PointsAddGateInput},
        Gate,
    },
    AssignedCell, F,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct PointsAddChipInput<T> {
    pub p: [T; 3],
    pub q: [T; 3],
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct PointsAddChipOutput<T> {
    pub s: [T; 3],
}

/// Chip that adds two points on a Grumpkin EC.
///
/// P + Q = S
#[derive(Clone, Debug)]
pub struct PointsAddChip {
    pub advice_pool: ColumnPool<Advice>,
    pub gate: PointsAddGate,
}

impl PointsAddChip {
    pub fn new(gate: PointsAddGate, advice_pool: ColumnPool<Advice>) -> Self {
        Self { gate, advice_pool }
    }

    pub fn point_add(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &PointsAddChipInput<AssignedCell>,
    ) -> Result<PointsAddChipOutput<AssignedCell>, Error> {
        let b3 = Value::known(G1::b() + G1::b() + G1::b());
        let s_value = curve_operations::points_add(
            [
                input.p[0].value().copied(),
                input.p[1].value().copied(),
                input.p[2].value().copied(),
            ],
            [
                input.q[0].value().copied(),
                input.q[1].value().copied(),
                input.q[2].value().copied(),
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
                            region.assign_advice(|| "s", self.advice_pool.get_any(), 0, || value)
                        },
                    )
                    .expect("can assign advice from a value")
            })
            .collect();

        let s: [AssignedCell; 3] = s.try_into().unwrap_or_else(|v: Vec<AssignedCell>| {
            panic!("Expected a Vec of length {} but it was {}", 3, v.len())
        });

        let gate_input = PointsAddGateInput {
            p: input.p.clone(),
            q: input.q.clone(),
            s: s.clone(),
        };

        self.gate.apply_in_new_region(layouter, gate_input)?;

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
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use super::{PointsAddChip, PointsAddChipInput, PointsAddChipOutput};
    use crate::{column_pool::ColumnPool, config_builder::ConfigsBuilder, embed::Embed, rng};

    #[derive(Clone, Debug, Default)]
    struct PointsAddCircuit(PointsAddChipInput<Fr>);

    impl Circuit<Fr> for PointsAddCircuit {
        type Config = (ColumnPool<Advice>, PointsAddChip, Column<Instance>);

        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            // public input column
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            // register point add chip
            let configs_builder = ConfigsBuilder::new(meta).with_point_add_chip();

            (
                configs_builder.advice_pool(),
                configs_builder.points_add_chip(),
                instance,
            )
        }

        fn synthesize(
            &self,
            (advice_pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let PointsAddChipInput { p, q } = self.0;

            let p = p.embed(&mut layouter, &advice_pool, "P")?;
            let q = q.embed(&mut layouter, &advice_pool, "Q")?;

            let PointsAddChipOutput { s } =
                chip.point_add(&mut layouter, &PointsAddChipInput { p, q })?;

            layouter.constrain_instance(s[0].cell(), instance, 0)?;
            layouter.constrain_instance(s[1].cell(), instance, 1)?;
            layouter.constrain_instance(s[2].cell(), instance, 2)?;

            Ok(())
        }
    }

    fn input(p: G1, q: G1) -> PointsAddChipInput<Fr> {
        PointsAddChipInput {
            p: [p.x, p.y, p.z],
            q: [q.x, q.y, q.z],
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
            vec![vec![expected.s[0], expected.s[1], expected.s[2]]],
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
        let output = PointsAddChipOutput {
            s: [expected.x, expected.y, expected.z],
        };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn adding_random_points() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let expected = p + q;

        let input = input(p, q);
        let output = PointsAddChipOutput {
            s: [expected.x, expected.y, expected.z],
        };

        assert!(verify(input, output).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let s = G1::random(rng.clone());

        let input = input(p, q);
        let output = PointsAddChipOutput { s: [s.x, s.y, s.z] };

        assert!(verify(input, output).is_ok());
    }
}
