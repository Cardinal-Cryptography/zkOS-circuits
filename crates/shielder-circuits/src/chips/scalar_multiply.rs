use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr, plonk::ErrorFront};

use super::sum::SumChip;
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
    /// point on the Grunmpkin curve
    pub input: GrumpkinPoint<T>,
    /// scalar bits in LE representation
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
    pub sum_chip: SumChip,
}

impl ScalarMultiplyChip {
    pub fn new(multiply_gate: ScalarMultiplyGate, sum_chip: SumChip) -> Self {
        Self {
            multiply_gate,
            sum_chip,
        }
    }

    fn constrain_point_at_infinity(
        &self,
        synthesizer: &mut impl Synthesizer,
        point_at_infinity: GrumpkinPoint<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        let one = synthesizer.assign_constant("ONE", Fr::ONE)?;
        self.sum_chip
            .constrain_zero(synthesizer, point_at_infinity.x)?;
        self.sum_chip
            .constrain_equal(synthesizer, point_at_infinity.y, one)?;
        self.sum_chip
            .constrain_zero(synthesizer, point_at_infinity.z)?;

        Ok(())
    }

    fn constrain_points_equality(
        &self,
        synthesizer: &mut impl Synthesizer,
        left: GrumpkinPoint<AssignedCell>,
        right: GrumpkinPoint<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        self.sum_chip
            .constrain_equal(synthesizer, left.x, right.x)?;
        self.sum_chip
            .constrain_equal(synthesizer, left.y, right.y)?;
        self.sum_chip
            .constrain_equal(synthesizer, left.z, right.z)?;
        Ok(())
    }

    pub fn scalar_multiply(
        &self,
        synthesizer: &mut impl Synthesizer,
        inputs: &ScalarMultiplyChipInput<AssignedCell>,
    ) -> Result<ScalarMultiplyChipOutput<AssignedCell>, ErrorFront> {
        let ScalarMultiplyChipInput { scalar_bits, input } = inputs;

        let mut input_value: GrumpkinPoint<Value> = input.clone().into();
        let mut result_value: GrumpkinPoint<Value> = GrumpkinPoint::<Fr>::zero().into();
        let mut last_result = None;

        for (i, bit) in scalar_bits.iter().enumerate() {
            let input = input_value.embed(synthesizer, "input")?;
            let result = result_value.embed(synthesizer, "result")?;
            if i.eq(&0) {
                self.constrain_point_at_infinity(synthesizer, result.clone())?;
                self.constrain_points_equality(synthesizer, input.clone(), inputs.input.clone())?;
            }

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
                    next_result: next_result.clone(),
                },
            )?;

            input_value = next_input_value;
            result_value = next_result_value;

            if i.eq(&(scalar_bits.len() - 1)) {
                last_result = Some(next_result);
            }
        }

        Ok(ScalarMultiplyChipOutput {
            result: last_result.expect("last result is returned"),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    use halo2_proofs::{
        arithmetic::Field,
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
        plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
    };

    use super::{ScalarMultiplyChip, ScalarMultiplyChipInput, ScalarMultiplyChipOutput};
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        consts::GRUMPKIN_3B,
        curve_arithmetic::{self, field_element_to_le_bits},
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

            let fixed = meta.fixed_column();
            meta.enable_constant(fixed);

            // register chip
            let configs_builder = ConfigsBuilder::new(meta).with_scalar_multiply_chip();
            let chip = configs_builder.scalar_multiply_chip();

            (configs_builder.finish(), chip, instance)
        }

        fn synthesize(
            &self,
            (column_pool, chip, instance): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), ErrorFront> {
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

    fn verify(
        input: ScalarMultiplyChipInput<Fr>,
        expected: ScalarMultiplyChipOutput<Fr>,
    ) -> Result<(), Vec<String>> {
        MockProver::run(
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
        })
    }

    #[test]
    fn multiply_random_point() {
        let rng = rng();
        let p = G1::random(rng.clone());
        let n = Fr::from_u128(3);
        let bits = field_element_to_le_bits(n);

        let expected = curve_arithmetic::scalar_multiply(
            p.into(),
            bits.clone(),
            *GRUMPKIN_3B,
            Fr::ZERO,
            Fr::ONE,
        );

        let input = input(p, bits);
        let output = ScalarMultiplyChipOutput { result: expected };

        assert!(verify(input, output).is_ok());
    }
}
