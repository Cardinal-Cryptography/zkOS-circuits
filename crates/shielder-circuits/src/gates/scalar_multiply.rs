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
    pub bit: Column<Advice>,
    pub input1: [Column<Advice>; 3],
    pub input2: [Column<Advice>; 3],
    pub result1: [Column<Advice>; 3],
    pub result2: [Column<Advice>; 3],
}

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "TransitionPair<Fr>",
    embedded = "TransitionPair<crate::AssignedCell>"
)]
pub struct TransitionPair<T> {
    pub current: GrumpkinPoint<T>,
    pub next: GrumpkinPoint<T>,
}

#[derive(Clone, Debug, Default)]
#[embeddable(
    receiver = "ScalarMultiplyGateInput<Fr>",
    embedded = "ScalarMultiplyGateInput<crate::AssignedCell>"
)]
pub struct ScalarMultiplyGateInput<T> {
    pub bit: T,

    pub input1: TransitionPair<T>,
    pub input2: TransitionPair<T>,

    pub result1: TransitionPair<T>,
    pub result2: TransitionPair<T>,
}

const SELECTOR_OFFSET: i32 = 0;
const BIT_OFFSET: i32 = 0;
const CURRENT_VALUE_OFFSET: i32 = 0;
const NEXT_VALUE_OFFSET: i32 = 1;
const GATE_NAME: &str = "Tandem scalar multiply gate";

pub struct ScalarMultiplyGateAdvice {
    bit: Column<Advice>,
    input1: [Column<Advice>; 3],
    input2: [Column<Advice>; 3],
    result1: [Column<Advice>; 3],
    result2: [Column<Advice>; 3],
}

impl Gate for ScalarMultiplyGate {
    type Input = ScalarMultiplyGateInput<AssignedCell>;

    type Advice = ScalarMultiplyGateAdvice;

    /// The gate operates on an advice column `scalar_bit`, a triplet (representing projective coordinates of a point on an EC)
    /// of two `input` advice columns  and a triplet of corresponing `result` columns.
    ///
    /// It is the kernel of the double-and-add algorithm for point by scalar multiplication on an EC.
    ///
    /// Constraints (for j in {1, 2}):
    ///
    ///   - result_j[i + 1] = result_j[i] + input_j[i]  if bit == 1
    ///                     = result_j[i]               if bit == 0
    ///   - input_j[i + 1]  = 2 * input_j[i]
    ///   - bit is a valid binary value
    fn create_gate_custom(cs: &mut ConstraintSystem<Fr>, advice: Self::Advice) -> Self {
        ensure_unique_columns(
            &[
                vec![advice.bit],
                advice.input1.to_vec(),
                advice.input2.to_vec(),
                advice.result1.to_vec(),
                advice.result2.to_vec(),
            ]
            .concat(),
        );

        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let bit = vc.query_advice(advice.bit, Rotation(BIT_OFFSET));

            let read_point = |cols, offset| {
                GrumpkinPoint::new(
                    vc.query_advice(cols[0], Rotation(offset)),
                    vc.query_advice(cols[1], Rotation(offset)),
                    vc.query_advice(cols[2], Rotation(offset)),
                )
            };

            let input1 = read_point(advice.input1, CURRENT_VALUE_OFFSET);
            let next_input1 = read_point(advice.input1, NEXT_VALUE_OFFSET);

            let input2 = read_point(advice.input2, CURRENT_VALUE_OFFSET);
            let next_input2 = read_point(advice.input1, NEXT_VALUE_OFFSET);

            let result1 = read_point(advice.result1, CURRENT_VALUE_OFFSET);
            let next_result1 = read_point(advice.result1, NEXT_VALUE_OFFSET);

            let result2 = read_point(advice.result2, CURRENT_VALUE_OFFSET);
            let next_result2 = read_point(advice.result2, NEXT_VALUE_OFFSET);

            let input_plus_result1 = curve_arithmetic::points_add(input1.clone(), result1);
            let input_plus_result2 = curve_arithmetic::points_add(input2.clone(), result2);

            let doubled_input1 = curve_arithmetic::point_double(input1);
            let doubled_input2 = curve_arithmetic::point_double(input2);

            Constraints::with_selector(
                vc.query_selector(selector),
                vec![
                    (
                        "bit is a valid binary value",
                        bit.clone() * (Expression::Constant(Fr::one()) - bit.clone()),
                    ),
                    // next_result = input + result (if bit == 1) else result
                    (
                        "next_result = input + result if bit == 1 else result (1st set, x coord)",
                        next_result1.x
                            - bit.clone() * (input_plus_result1.x - result1.x.clone())
                            - result1.x,
                    ),
                    (
                        "next_result = input + result if bit == 1 else result (1st set, y coord)",
                        next_result1.y
                            - bit.clone() * (input_plus_result1.y - result1.y.clone())
                            - result1.y,
                    ),
                    (
                        "next_result = input + result if bit == 1 else result (1st set, z coord)",
                        next_result1.z
                            - bit.clone() * (input_plus_result1.z - result1.z.clone())
                            - result1.z,
                    ),
                    // second set
                    (
                        "next_result = input + result if bit == 1 else result (2nd set, x coord)",
                        next_result2.x
                            - bit.clone() * (input_plus_result2.x - result2.x.clone())
                            - result2.x,
                    ),
                    (
                        "next_result = input + result if bit == 1 else result (2nd set, y coord)",
                        next_result2.y
                            - bit.clone() * (input_plus_result2.y - result2.y.clone())
                            - result2.y,
                    ),
                    (
                        "next_result = input + result if bit == 1 else result (2nd set, z coord)",
                        next_result2.z
                            - bit.clone() * (input_plus_result2.z - result2.z.clone())
                            - result2.z,
                    ),
                    // next_input = 2 * input
                    (
                        "next_input = 2 * input (1st set, x coord)",
                        next_input1.x - doubled_input1.x,
                    ),
                    (
                        "next_input = 2 * input (1st set, y coord)",
                        next_input1.y - doubled_input1.y,
                    ),
                    (
                        "next_input = 2 * input (1st set, z coord)",
                        next_input1.z - doubled_input1.z,
                    ),
                    // second set
                    (
                        "next_input = 2 * input (2nd set, x coord)",
                        next_input2.x - doubled_input2.x,
                    ),
                    (
                        "next_input = 2 * input (2nd set, y coord)",
                        next_input2.y - doubled_input2.y,
                    ),
                    (
                        "next_input = 2 * input (2nd set, z coord)",
                        next_input2.z - doubled_input2.z,
                    ),
                ],
            )
        });

        Self {
            selector,
            bit: advice.bit,
            input1: advice.input1,
            input2: advice.input2,
            result1: advice.result1,
            result2: advice.result2,
        }
    }

    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        ScalarMultiplyGateInput {
            bit,
            input1,
            input2,
            result1,
            result2,
        }: Self::Input,
    ) -> Result<(), Error> {
        synthesizer.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector
                    .enable(&mut region, SELECTOR_OFFSET as usize)?;

                bit.copy_advice(|| "bit", &mut region, self.bit, BIT_OFFSET as usize)?;

                for (cells, ann, cols) in [
                    (&input1, "input1", self.input1),
                    (&input2, "input2", self.input2),
                    (&result1, "result1", self.result1),
                    (&result2, "result2", self.result2),
                ] {
                    copy_grumpkin_advices(
                        &cells.current,
                        ann,
                        &mut region,
                        cols,
                        CURRENT_VALUE_OFFSET as usize,
                    )?;
                    copy_grumpkin_advices(
                        &cells.next,
                        alloc::format!("{ann} next"),
                        &mut region,
                        cols,
                        NEXT_VALUE_OFFSET as usize,
                    )?;
                }

                Ok(())
            },
        )
    }

    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advice {
        pool.ensure_capacity(cs, 13);
        ScalarMultiplyGateAdvice {
            bit: pool.get_column(0),
            input1: [pool.get_column(1), pool.get_column(2), pool.get_column(3)],
            input2: [pool.get_column(4), pool.get_column(5), pool.get_column(6)],
            resul1: [pool.get_column(7), pool.get_column(8), pool.get_column(9)],
            result2: [
                pool.get_column(10),
                pool.get_column(11),
                pool.get_column(12),
            ],
        }
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
