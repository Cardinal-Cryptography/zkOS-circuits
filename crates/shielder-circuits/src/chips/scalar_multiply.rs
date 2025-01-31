use core::ops::{Add, Mul, Sub};

use halo2_proofs::{arithmetic::Field, circuit::Value, halo2curves::bn256::Fr, plonk::Error};
use rayon::result;

use super::{point_double::PointDoubleChip, points_add::PointsAddChip};
use crate::{
    chips::{point_double::PointDoubleChipInput, points_add::PointsAddChipInput},
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint, V},
    embed::Embed,
    gates::{
        scalar_multiply::{self, ScalarMultiplyGate, ScalarMultiplyGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct ScalarMultiplyChipInput<T> {
    pub p: GrumpkinPoint<T>,
    pub scalar_bits: [T; 254],
}

impl<T: Default + Copy> Default for ScalarMultiplyChipInput<T> {
    fn default() -> Self {
        Self {
            p: GrumpkinPoint::default(),
            scalar_bits: [T::default(); 254],
        }
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct ScalarMultiplyChipOutput<T> {
    pub s: GrumpkinPoint<T>,
}

/// Chip that computes the result of adding a point P on the grumpkin curve to itself n times.
///
/// nP = S
#[derive(Clone, Debug)]
pub struct ScalarMultiplyChip {
    pub gate: ScalarMultiplyGate,
}

impl ScalarMultiplyChip {
    pub fn new(gate: ScalarMultiplyGate) -> Self {
        Self { gate }
    }

    pub fn scalar_multiply(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: &ScalarMultiplyChipInput<AssignedCell>,
    ) -> Result<ScalarMultiplyChipOutput<AssignedCell>, Error> {
        let ScalarMultiplyChipInput { scalar_bits, p } = input;

        let bits: Vec<V> = scalar_bits
            .iter()
            .map(|cell| V(cell.value().cloned()))
            .collect();
        let bits: [V; 254] = bits.try_into().expect("not 254 bit array");
        let input: GrumpkinPoint<V> = GrumpkinPoint {
            x: V(p.x.value().cloned()),
            y: V(p.y.value().cloned()),
            z: V(p.z.value().cloned()),
        };

        let r_value: GrumpkinPoint<V> = curve_arithmetic::scalar_multiply(
            input,
            bits,
            V(Value::known(*GRUMPKIN_3B)),
            V(Value::known(Fr::ZERO)),
            V(Value::known(Fr::ONE)),
        );

        let result = r_value.embed(synthesizer, "S")?;

        self.gate.apply_in_new_region(
            synthesizer,
            ScalarMultiplyGateInput {
                scalar_bits: scalar_bits.clone(),
                result: result.clone(),
                input: p.clone(),
            },
        )?;

        Ok(ScalarMultiplyChipOutput { s: result })
    }
}

#[cfg(test)]
mod tests {

    use alloc::{vec, vec::Vec};

    use halo2_proofs::{
        arithmetic::Field,
        circuit::{floor_planner::V1, Layouter},
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use super::{ScalarMultiplyChipInput, ScalarMultiplyChipOutput};
    use crate::{
        chips::{
            point_double::{PointDoubleChip, PointDoubleChipInput},
            points_add::{PointsAddChip, PointsAddChipInput},
        },
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        consts::GRUMPKIN_3B,
        curve_arithmetic::{self, field_element_to_bits, GrumpkinPoint},
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
        Value,
    };

    #[derive(Clone, Debug, Default)]
    struct ScalarMultiplyCircuit(ScalarMultiplyChipInput<Fr>);

    impl Circuit<Fr> for ScalarMultiplyCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            PointDoubleChip,
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
            // register chip
            let configs_builder = ConfigsBuilder::new(meta)
                .with_point_double_chip()
                .with_points_add_chip();
            let points_add = configs_builder.points_add_chip();
            let point_double = configs_builder.point_double_chip();

            (configs_builder.finish(), point_double, points_add, instance)
        }

        fn synthesize(
            &self,
            (column_pool, point_double, points_add, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let ScalarMultiplyChipInput { p, scalar_bits } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            Ok(())
        }
    }

    fn input(p: G1, scalar_bits: [Fr; 254]) -> ScalarMultiplyChipInput<Fr> {
        ScalarMultiplyChipInput {
            p: p.into(),
            scalar_bits: scalar_bits.into(),
        }
    }

    fn verify(
        input: ScalarMultiplyChipInput<Fr>,
        expected: ScalarMultiplyChipOutput<Fr>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = ScalarMultiplyCircuit(input);
        MockProver::run(
            10,
            &circuit,
            vec![vec![expected.s.x, expected.s.y, expected.s.z]],
        )
        .expect("Mock prover should run")
        .verify()
    }

    #[test]
    fn multiply_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());

        // println!("P: {p:?}");

        let n = Fr::from_u128(3);
        let bits = field_element_to_bits(n);

        // println!("BITS: {bits:?}");

        let expected = curve_arithmetic::scalar_multiply(
            p.into(),
            bits.clone(),
            *GRUMPKIN_3B,
            Fr::ZERO,
            Fr::ONE,
        );

        let input = input(p, bits);
        let output = ScalarMultiplyChipOutput { s: expected };

        assert!(verify(input, output).is_ok());
        // assert!(false)
    }
}
