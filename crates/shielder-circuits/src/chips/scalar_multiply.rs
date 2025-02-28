use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr, plonk::Error};

use super::sum::SumChip;
use crate::gates::scalar_multiply::TransitionPair;
use crate::{
    consts::FIELD_BITS,
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
    /// points on the Grumpkin curve to be multiplied
    pub input1: GrumpkinPoint<T>,
    pub input2: GrumpkinPoint<T>,
    /// scalar bits in LE representation
    pub scalar_bits: [T; FIELD_BITS],
}

impl<T: Default + Copy> Default for ScalarMultiplyChipInput<T> {
    fn default() -> Self {
        Self {
            input1: GrumpkinPoint::default(),
            input2: GrumpkinPoint::default(),
            scalar_bits: [T::default(); FIELD_BITS],
        }
    }
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
    ) -> Result<(GrumpkinPoint<AssignedCell>, GrumpkinPoint<AssignedCell>), Error> {
        let ScalarMultiplyChipInput { scalar_bits, input1, input2 } = inputs;

        let mut input1_value: GrumpkinPoint<Value> = input1.clone().into();
        let mut input2_value: GrumpkinPoint<Value> = input2.clone().into();

        let mut result1_value: GrumpkinPoint<Value> = GrumpkinPoint::<Fr>::zero().into();
        let mut result2_value: GrumpkinPoint<Value> = GrumpkinPoint::<Fr>::zero().into();
        let mut last_result1 = None;
        let mut last_result2 = None;

        for (i, bit) in scalar_bits.iter().enumerate() {
            let input1 = input1_value.embed(synthesizer, "input1")?;
            let input2 = input2_value.embed(synthesizer, "input2")?;
            let result1 = result1_value.embed(synthesizer, "result1")?;
            let result2 = result2_value.embed(synthesizer, "result2")?;

            if i.eq(&0) {
                self.constrain_point_at_infinity(synthesizer, result1.clone())?;
                self.constrain_point_at_infinity(synthesizer, result2.clone())?;
                self.constrain_points_equality(synthesizer, input1.clone(), inputs.input1.clone())?;
                self.constrain_points_equality(synthesizer, input2.clone(), inputs.input2.clone())?;
            }

            let mut is_one = false;
            bit.value().map(|f| {
                is_one = Fr::ONE == *f;
            });

            let mut next_result1_value = result1_value;
            let mut next_result2_value = result2_value;
            if is_one {
                next_result1_value = curve_arithmetic::points_add(result1_value, input1_value);
                next_result2_value = curve_arithmetic::points_add(result2_value, input2_value);
            }

            let next_result1 = next_result1_value.embed(synthesizer, "next_result")?;
            let next_result2 = next_result2_value.embed(synthesizer, "next_result")?;

            let next_input1_value = curve_arithmetic::point_double(input1_value);
            let next_input2_value = curve_arithmetic::point_double(input2_value);
            let next_input1 = next_input1_value.embed(synthesizer, "next_input1")?;
            let next_input2 = next_input2_value.embed(synthesizer, "next_input2")?;

            self.multiply_gate.apply_in_new_region(
                synthesizer,
                ScalarMultiplyGateInput {
                    bit: bit.clone(),
                    input1: TransitionPair {
                        current: input1,
                        next: next_input1,
                    },
                    input2: TransitionPair {
                        current: input2,
                        next: next_input2,
                    },
                    result1: TransitionPair {
                        current: result1,
                        next: next_result1.clone(),
                    },
                    result2: TransitionPair {
                        current: result2,
                        next: next_result2.clone(),
                    },
                },
            )?;

            input1_value = next_input1_value;
            input2_value = next_input2_value;
            result1_value = next_result1_value;
            result2_value = next_result2_value;

            if i.eq(&(scalar_bits.len() - 1)) {
                last_result1 = Some(next_result1);
                last_result2 = Some(next_result2);
            }
        }

        Ok((last_result1.expect("last result is returned"), last_result2.expect("last result is returned")))
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
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use super::{ScalarMultiplyChip, ScalarMultiplyChipInput};
    use crate::{
        column_pool::{ColumnPool, PreSynthesisPhase},
        config_builder::ConfigsBuilder,
        consts::FIELD_BITS,
        curve_arithmetic::{self, field_element_to_le_bits},
        embed::Embed,
        rng,
        synthesizer::create_synthesizer,
        GrumpkinPoint,
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
        ) -> Result<(), Error> {
            let ScalarMultiplyChipInput { input, scalar_bits } = self.0;

            let column_pool = column_pool.start_synthesis();
            let mut synthesizer = create_synthesizer(&mut layouter, &column_pool);

            let input = input.embed(&mut synthesizer, "input")?;
            let scalar_bits = scalar_bits.embed(&mut synthesizer, "scalar_bits")?;

            let result = chip.scalar_multiply(
                &mut synthesizer,
                &ScalarMultiplyChipInput { input, scalar_bits },
            )?;

            synthesizer.constrain_instance(result.x.cell(), instance, 0)?;
            synthesizer.constrain_instance(result.y.cell(), instance, 1)?;
            synthesizer.constrain_instance(result.z.cell(), instance, 2)?;

            Ok(())
        }
    }

    fn input(p: G1, scalar_bits: [Fr; FIELD_BITS]) -> ScalarMultiplyChipInput<Fr> {
        ScalarMultiplyChipInput {
            input: p.into(),
            scalar_bits: scalar_bits.into(),
        }
    }

    fn verify(
        input: ScalarMultiplyChipInput<Fr>,
        expected: GrumpkinPoint<Fr>,
    ) -> Result<(), Vec<String>> {
        MockProver::run(
            10,
            &ScalarMultiplyCircuit(input),
            vec![vec![expected.x, expected.y, expected.z]],
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

        let expected = curve_arithmetic::scalar_multiply(p.into(), bits.clone());

        let input = input(p, bits);

        assert!(verify(input, expected).is_ok());
    }
}
