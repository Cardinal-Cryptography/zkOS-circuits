use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr, plonk::Error};

use crate::{
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{
        scalar_multiply::{ScalarMultiplyGate, ScalarMultiplyGateInput},
        Gate,
    },
    synthesizer::Synthesizer,
    AssignedCell, Value,
};

#[derive(Clone, Debug)]
pub struct ScalarMultiplyChipInput<T> {
    pub input: GrumpkinPoint<T>,
    pub scalar_bits: [T; 254],
}

impl<T: Default + Copy> Default for ScalarMultiplyChipInput<T> {
    fn default() -> Self {
        Self {
            input: GrumpkinPoint::default(),
            scalar_bits: [T::default(); 254],
        }
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct ScalarMultiplyChipOutput<T> {
    pub result: GrumpkinPoint<T>,
}

/// Chip that computes the result of adding a point P on the Grumpkin curve to itself n times.
///
/// n * P = S
#[derive(Clone, Debug)]
pub struct ScalarMultiplyChip {
    pub multiply_gate: ScalarMultiplyGate,
}

impl ScalarMultiplyChip {
    pub fn new(multiply_gate: ScalarMultiplyGate) -> Self {
        Self { multiply_gate }
    }

    pub fn scalar_multiply(
        &self,
        synthesizer: &mut impl Synthesizer,
        inputs: &ScalarMultiplyChipInput<AssignedCell>,
    ) -> Result<ScalarMultiplyChipOutput<AssignedCell>, Error> {
        let ScalarMultiplyChipInput { scalar_bits, input } = inputs;

        let mut result_value: GrumpkinPoint<Value> = GrumpkinPoint::<Fr>::zero().into();
        let mut input_value: GrumpkinPoint<Value> = input.clone().into();

        for bit in scalar_bits.iter() {
            let input = input_value.embed(synthesizer, "input")?;
            let result = result_value.embed(synthesizer, "result")?;

            let mut is_one = false;
            bit.value().map(|f| {
                is_one = Fr::ONE == *f;
            });

            let mut next_result_value = result_value;
            if is_one {
                next_result_value = curve_arithmetic::points_add(
                    result_value,
                    input_value,
                    Value::known(*GRUMPKIN_3B),
                );
            }

            let next_result = next_result_value.embed(synthesizer, "next_result")?;

            let next_input_value =
                curve_arithmetic::point_double(input_value, Value::known(*GRUMPKIN_3B));
            let next_input = next_input_value.embed(synthesizer, "next_input")?;

            self.multiply_gate.apply_in_new_region(
                synthesizer,
                ScalarMultiplyGateInput {
                    bit: bit.clone(),
                    input,
                    result,
                    next_input,
                    next_result,
                },
            )?;

            input_value = next_input_value;
            result_value = next_result_value;
        }

        Ok(ScalarMultiplyChipOutput {
            result: result_value.embed(synthesizer, "final result")?,
        })
    }
}

#[cfg(test)]
mod tests {

    use alloc::{vec, vec::Vec};
    use std::println;

    use halo2_proofs::{
        arithmetic::Field,
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use super::{ScalarMultiplyChip, ScalarMultiplyChipInput, ScalarMultiplyChipOutput};
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        consts::GRUMPKIN_3B,
        curve_arithmetic::{self, field_element_to_bits},
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
    };

    #[derive(Clone, Debug, Default)]
    struct ScalarMultiplyCircuit(ScalarMultiplyChipInput<Fr>);

    impl Circuit<Fr> for ScalarMultiplyCircuit {
        type Config = (
            ColumnPool<Advice, PreSynthesisPhase>,
            ScalarMultiplyChip,
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
            let configs_builder = ConfigsBuilder::new(meta).with_scalar_multiply_chip();
            let chip = configs_builder.scalar_multiply_chip();

            (configs_builder.finish(), chip, instance)
        }

        fn synthesize(
            &self,
            (column_pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let ScalarMultiplyChipInput { input, scalar_bits } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let input = input.embed(&mut synthesizer, "input")?;
            let scalar_bits = scalar_bits.embed(&mut synthesizer, "scalar_bits")?;

            let ScalarMultiplyChipOutput { result } = chip.scalar_multiply(
                &mut synthesizer,
                &ScalarMultiplyChipInput { input, scalar_bits },
            )?;

            synthesizer.constrain_instance(result.x.cell(), instance, 0)?;
            synthesizer.constrain_instance(result.y.cell(), instance, 1)?;
            synthesizer.constrain_instance(result.z.cell(), instance, 2)?;

            Ok(())
        }
    }

    fn input(p: G1, scalar_bits: [Fr; 254]) -> ScalarMultiplyChipInput<Fr> {
        ScalarMultiplyChipInput {
            input: p.into(),
            scalar_bits: scalar_bits.into(),
        }
    }

    // fn verify(
    //     input: ScalarMultiplyChipInput<Fr>,
    //     expected: ScalarMultiplyChipOutput<Fr>,
    // ) -> Result<(), Vec<VerifyFailure>> {
    //     let circuit = ScalarMultiplyCircuit(input);
    //     let res = MockProver::run(
    //         10,
    //         &circuit,
    //         vec![vec![
    //             expected.result.x,
    //             expected.result.y,
    //             expected.result.z,
    //         ]],
    //     )
    //     .expect("Mock prover should run")
    //     .verify();

    //     // println!("{res:?}");

    //     res
    // }

    fn verify(
        input: ScalarMultiplyChipInput<Fr>,
        expected: ScalarMultiplyChipOutput<Fr>,
    ) -> Result<(), Vec<String>> {
        let res = MockProver::run(
            10,
            &ScalarMultiplyCircuit(input),
            vec![vec![
                expected.result.x,
                expected.result.y,
                expected.result.z,
            ]],
        )
        .expect("Mock prover should run successfully")
        .verify()
        .map_err(|errors| {
            errors
                .into_iter()
                .map(|failure| failure.to_string())
                .collect()
        });

        println!("{res:?}");

        res
    }

    #[test]
    fn multiply_random_point() {
        let rng = rng();
        let p = G1::random(rng.clone());
        let n = Fr::from_u128(3);
        let bits = field_element_to_bits(n);

        let expected = curve_arithmetic::scalar_multiply(
            p.into(),
            bits.clone(),
            *GRUMPKIN_3B,
            Fr::ZERO,
            Fr::ONE,
        );

        println!("EXPECTED : {expected:?}");

        let input = input(p, bits);
        let output = ScalarMultiplyChipOutput { result: expected };

        assert!(verify(input, output).is_ok());
    }
}
