use alloc::vec;

use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use macros::embeddable;

use super::copy_grumpkin_advices;
use crate::{
    column_pool::{AccessColumn, ColumnPool, ConfigPhase},
    curve_arithmetic::{self, GrumpkinPoint},
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScalarMultiplyGate {
    pub selector: Selector,
    pub scalar_dibits: Column<Advice>,
    pub result: [Column<Advice>; 3],
    pub input: [Column<Advice>; 3],
}

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "ScalarMultiplyGateInput<Fr>",
    embedded = "ScalarMultiplyGateInput<crate::AssignedCell>"
)]
pub struct ScalarMultiplyGateInput<T> {
    pub dibit: T,
    pub input: GrumpkinPoint<T>,
    pub result: GrumpkinPoint<T>,
    pub next_input: GrumpkinPoint<T>,
    pub next_result: GrumpkinPoint<T>,
}

const SELECTOR_OFFSET: i32 = 0;
const ADVICE_OFFSET: i32 = 0;
const GATE_NAME: &str = "Scalar multiply gate";

impl Gate for ScalarMultiplyGate {
    type Input = ScalarMultiplyGateInput<AssignedCell>;

    type Advice = (
        Column<Advice>,      // scalar_bit
        [Column<Advice>; 3], // input
        [Column<Advice>; 3], // result
    );

    /// The gate operates on an advice column `scalar_dibit`, a triplet (representing projective coordinates of a point on an EC) of `input` advice columns
    /// and a triplet of `result` columns.
    ///
    /// It is the kernel of the double-and-add algorithm for point by scalar multiplication on an EC.
    /// Constraints:
    ///
    /// result[i + 1] = 3 * input[i] + result[i]  if dibit == 11
    ///               = 2 * input[i] + result[i]  if dibit == 10
    ///               =     input[i] + result[i]  if dibit == 01
    ///               =                result[i]  if dibit == 00
    /// input[i + 1]  = 4 * input[i]
    fn create_gate_custom(
        cs: &mut ConstraintSystem<Fr>,
        (scalar_dibits, input, result): Self::Advice,
    ) -> Self {
        ensure_unique_columns(&[vec![scalar_dibits], input.to_vec(), result.to_vec()].concat());
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let dibit = vc.query_advice(scalar_dibits, Rotation(ADVICE_OFFSET));

            let input_x = vc.query_advice(input[0], Rotation(ADVICE_OFFSET));
            let input_y = vc.query_advice(input[1], Rotation(ADVICE_OFFSET));
            let input_z = vc.query_advice(input[2], Rotation(ADVICE_OFFSET));

            let result_x = vc.query_advice(result[0], Rotation(ADVICE_OFFSET));
            let result_y = vc.query_advice(result[1], Rotation(ADVICE_OFFSET));
            let result_z = vc.query_advice(result[2], Rotation(ADVICE_OFFSET));

            let next_input_x = vc.query_advice(input[0], Rotation(ADVICE_OFFSET + 1));
            let next_input_y = vc.query_advice(input[1], Rotation(ADVICE_OFFSET + 1));
            let next_input_z = vc.query_advice(input[2], Rotation(ADVICE_OFFSET + 1));

            let next_result_x = vc.query_advice(result[0], Rotation(ADVICE_OFFSET + 1));
            let next_result_y = vc.query_advice(result[1], Rotation(ADVICE_OFFSET + 1));
            let next_result_z = vc.query_advice(result[2], Rotation(ADVICE_OFFSET + 1));

            // INPUT MULTIPLIES ----------------------------------------------------------------------
            let input = GrumpkinPoint::new(input_x, input_y, input_z);
            let input_2 = curve_arithmetic::point_double(input.clone());
            let input_3 = curve_arithmetic::points_add(input.clone(), input_2.clone());
            let input_4 = curve_arithmetic::points_add(input_2.clone(), input_2.clone());
            // ----------------------------------------------------------------------------------------

            // RESULT-INPUT VARIANTS ------------------------------------------------------------------
            let result = GrumpkinPoint::new(result_x.clone(), result_y.clone(), result_z.clone());
            let result_input_1 = curve_arithmetic::points_add(input.clone(), result.clone());
            let result_input_2 = curve_arithmetic::points_add(input_2.clone(), result.clone());
            let result_input_3 = curve_arithmetic::points_add(input_3.clone(), result.clone());
            // ----------------------------------------------------------------------------------------

            // DIBIT CHECKS ---------------------------------------------------------------------------
            let dibit_is_zero = (Expression::Constant(Fr::from(1)) - dibit.clone())
                * (Expression::Constant(Fr::from(2)) - dibit.clone())
                * (Expression::Constant(Fr::from(3)) - dibit.clone());
            let dibit_is_one = dibit.clone()
                * (Expression::Constant(Fr::from(2)) - dibit.clone())
                * (Expression::Constant(Fr::from(3)) - dibit.clone());
            let dibit_is_two = dibit.clone()
                * (Expression::Constant(Fr::from(1)) - dibit.clone())
                * (Expression::Constant(Fr::from(3)) - dibit.clone());
            let dibit_is_three = dibit.clone()
                * (Expression::Constant(Fr::from(1)) - dibit.clone())
                * (Expression::Constant(Fr::from(2)) - dibit.clone());
            // ----------------------------------------------------------------------------------------

            Constraints::with_selector(
                vc.query_selector(selector),
                vec![
                    // `bit` is a valid bit
                    (
                        "bit is a {0, 1, 2, 3} value",
                        dibit.clone()
                            * (Expression::Constant(Fr::from(1)) - dibit.clone())
                            * (Expression::Constant(Fr::from(2)) - dibit.clone())
                            * (Expression::Constant(Fr::from(3)) - dibit.clone()),
                    ),
                    // --------------------------------------------------------------------------------
                    // if dibit == 0: next_result = result
                    (
                        "dibit=0 [x]",
                        dibit_is_zero.clone() * (next_result_x.clone() - result_x),
                    ),
                    (
                        "dibit=0 [y]",
                        dibit_is_zero.clone() * (next_result_y.clone() - result_y),
                    ),
                    (
                        "dibit=0 [z]",
                        dibit_is_zero.clone() * (next_result_z.clone() - result_z),
                    ),
                    // --------------------------------------------------------------------------------
                    // if dibit == 1: next_result = result + input
                    (
                        "dibit=1 [x]",
                        dibit_is_one.clone() * (next_result_x.clone() - result_input_1.x),
                    ),
                    (
                        "dibit=1 [y]",
                        dibit_is_one.clone() * (next_result_y.clone() - result_input_1.y),
                    ),
                    (
                        "dibit=1 [z]",
                        dibit_is_one.clone() * (next_result_z.clone() - result_input_1.z),
                    ),
                    // --------------------------------------------------------------------------------
                    // if dibit == 2: next_result = result + 2 * input
                    (
                        "dibit=2 [x]",
                        dibit_is_two.clone() * (next_result_x.clone() - result_input_2.x),
                    ),
                    (
                        "dibit=2 [y]",
                        dibit_is_two.clone() * (next_result_y.clone() - result_input_2.y),
                    ),
                    (
                        "dibit=2 [z]",
                        dibit_is_two.clone() * (next_result_z.clone() - result_input_2.z),
                    ),
                    // --------------------------------------------------------------------------------
                    // if dibit == 3: next_result = result + 3 * input
                    (
                        "dibit=3 [x]",
                        dibit_is_three.clone() * (next_result_x.clone() - result_input_3.x),
                    ),
                    (
                        "dibit=3 [y]",
                        dibit_is_three.clone() * (next_result_y.clone() - result_input_3.y),
                    ),
                    (
                        "dibit=3 [z]",
                        dibit_is_three.clone() * (next_result_z.clone() - result_input_3.z),
                    ),
                    // --------------------------------------------------------------------------------
                    // next_input = 4 * input
                    ("x: next_input = 4 * input", next_input_x - input_4.x),
                    ("y: next_input = 4 * input", next_input_y - input_4.y),
                    ("z: next_input = 4 * input", next_input_z - input_4.z),
                ],
            )
        });

        Self {
            selector,
            scalar_dibits,
            input,
            result,
        }
    }

    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        ScalarMultiplyGateInput {
            dibit,
            input,
            result,
            next_input,
            next_result,
        }: Self::Input,
    ) -> Result<(), Error> {
        synthesizer.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector
                    .enable(&mut region, SELECTOR_OFFSET as usize)?;

                dibit.copy_advice(
                    || "dibit",
                    &mut region,
                    self.scalar_dibits,
                    ADVICE_OFFSET as usize,
                )?;

                copy_grumpkin_advices(
                    &input,
                    "input",
                    &mut region,
                    self.input,
                    ADVICE_OFFSET as usize,
                )?;

                copy_grumpkin_advices(
                    &result,
                    "result",
                    &mut region,
                    self.result,
                    ADVICE_OFFSET as usize,
                )?;

                copy_grumpkin_advices(
                    &next_input,
                    "next_input",
                    &mut region,
                    self.input,
                    ADVICE_OFFSET as usize + 1,
                )?;

                copy_grumpkin_advices(
                    &next_result,
                    "next_result",
                    &mut region,
                    self.result,
                    ADVICE_OFFSET as usize + 1,
                )?;

                Ok(())
            },
        )
    }

    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advice {
        pool.ensure_capacity(cs, 7);
        (
            pool.get_column(0),                                           // scalar_bits
            [pool.get_column(1), pool.get_column(2), pool.get_column(3)], // input
            [pool.get_column(4), pool.get_column(5), pool.get_column(6)], // result
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
    };

    use super::*;
    use crate::{gates::test_utils::OneGateCircuit, rng};

    fn verify(input: ScalarMultiplyGateInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = OneGateCircuit::<ScalarMultiplyGate, _>::new(input);
        MockProver::run(10, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn bit_is_zero() {
        let rng = rng();
        let bit = Fr::from_u128(0);

        let input = G1::random(rng.clone()).into();
        let result = G1::random(rng.clone()).into();

        let next_input = curve_arithmetic::point_double(input);
        let next_result = result;

        assert!(verify(ScalarMultiplyGateInput {
            bit,
            input,
            result,
            next_input,
            next_result
        })
        .is_ok());
    }

    #[test]
    fn bit_is_one() {
        let rng = rng();
        let bit = Fr::from_u128(1);

        let input = G1::random(rng.clone()).into();
        let result = G1::random(rng.clone()).into();

        let next_input = curve_arithmetic::point_double(input);
        let next_result = curve_arithmetic::points_add(input, result);

        assert!(verify(ScalarMultiplyGateInput {
            bit,
            input,
            result,
            next_input,
            next_result
        })
        .is_ok());
    }

    #[test]
    fn bit_is_invalid() {
        let rng = rng();
        let bit = Fr::from_u128(2);

        let input = G1::random(rng.clone()).into();
        let result = G1::random(rng.clone()).into();

        let next_input = curve_arithmetic::point_double(input);
        let next_result = curve_arithmetic::points_add(input, result);

        assert!(verify(ScalarMultiplyGateInput {
            bit,
            input,
            result,
            next_input,
            next_result
        })
        .is_err());
    }
}
