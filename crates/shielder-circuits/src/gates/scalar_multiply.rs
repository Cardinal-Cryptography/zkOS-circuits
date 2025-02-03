use alloc::vec;

use halo2_proofs::{
    arithmetic::Field,
    circuit::Value,
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
#[cfg(test)]
use {
    crate::{
        column_pool::{AccessColumn, ColumnPool, ConfigPhase},
        embed::Embed,
    },
    macros::embeddable,
};

use super::{assign_grumpkin_advices, copy_grumpkin_advices};
use crate::{
    consts::GRUMPKIN_3B,
    curve_arithmetic::{self, GrumpkinPoint},
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScalarMultiplyGate {
    pub selector: Selector,
    pub scalar_bits: Column<Advice>,
    pub result: [Column<Advice>; 3],
    pub input: [Column<Advice>; 3],
}

#[derive(Clone, Debug)]
#[cfg_attr(
    test,
    embeddable(
        receiver = "ScalarMultiplyGateInput<Fr>",
        impl_generics = "",
        embedded = "ScalarMultiplyGateInput<crate::AssignedCell>"
    )
)]
pub struct ScalarMultiplyGateInput<T> {
    pub scalar_bits: [T; 254],
    pub input: GrumpkinPoint<T>,
}

impl<T: Default + Copy> Default for ScalarMultiplyGateInput<T> {
    fn default() -> Self {
        Self {
            input: GrumpkinPoint::default(),
            scalar_bits: [T::default(); 254],
        }
    }
}

const SELECTOR_OFFSET: i32 = 0;
const ADVICE_OFFSET: i32 = 0;
const GATE_NAME: &str = "Scalar multiply gate";

impl Gate for ScalarMultiplyGate {
    type Input = ScalarMultiplyGateInput<AssignedCell>;

    type Advices = (
        Column<Advice>,      // scalar_bits
        [Column<Advice>; 3], // input
        [Column<Advice>; 3], // result
    );

    fn create_gate(
        cs: &mut ConstraintSystem<Fr>,
        (scalar_bits, input, result): Self::Advices,
    ) -> Self {
        ensure_unique_columns(&[vec![scalar_bits], input.to_vec(), result.to_vec()].concat());
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let bit = vc.query_advice(scalar_bits, Rotation(ADVICE_OFFSET));

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

            let input = GrumpkinPoint::new(input_x, input_y, input_z);
            let result = GrumpkinPoint::new(result_x.clone (), result_y.clone (), result_z.clone ());

            let GrumpkinPoint {
                x: added_x,
                y: added_y,
                z: added_z,
            } = curve_arithmetic::points_add(
                result,
                input.clone(),
                Expression::Constant(*GRUMPKIN_3B),
            );

            let GrumpkinPoint {
                x: doubled_x,
                y: doubled_y,
                z: doubled_z,
            } = curve_arithmetic::point_double(input, Expression::Constant(*GRUMPKIN_3B));

            Constraints::with_selector(
                vc.query_selector(selector),
                vec![
                    // next_result = P + result (if bit == 1) else next_result = result
                    ("x: next_result = input + result if bit == 1; next_result = result if bit == 0", bit.clone () * (added_x - result_x.clone ()) - (next_result_x - result_x)),
                    ("y: next_result = input + result if bit == 1; next_result = result if bit == 0", bit.clone () * (added_y - result_y.clone ()) - (next_result_y - result_y)),
                    ("z: next_result = input + result if bit == 1; next_result = result if bit == 0", bit.clone () * (added_z - result_z.clone ()) - (next_result_z - result_z)),
                    // next_P = 2 * P
                    ("x: next_input = 2 * input", next_input_x - doubled_x),
                    ("y: next_input = 2 * input", next_input_y - doubled_y),
                    ("z: next_input = 2 * input", next_input_z - doubled_z),

                ],
            )
        });

        Self {
            selector,
            scalar_bits,
            input,
            result,
        }
    }

    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        ScalarMultiplyGateInput { scalar_bits, input }: Self::Input,
    ) -> Result<(), Error> {
        synthesizer.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector
                    .enable(&mut region, SELECTOR_OFFSET as usize)?;

                let mut input = copy_grumpkin_advices(
                    &input,
                    "initial input",
                    &mut region,
                    self.input,
                    ADVICE_OFFSET as usize,
                )?;

                let mut result = assign_grumpkin_advices(
                    &GrumpkinPoint::new(
                        Value::known(Fr::ZERO),
                        Value::known(Fr::ONE),
                        Value::known(Fr::ZERO),
                    ),
                    "initial result",
                    &mut region,
                    self.result,
                    ADVICE_OFFSET as usize,
                )?;

                for (i, bit) in scalar_bits.iter().enumerate() {
                    self.selector.enable(&mut region, i)?;

                    bit.copy_advice(
                        || alloc::format!("bit[{i}]"),
                        &mut region,
                        self.scalar_bits,
                        i,
                    )?;

                    let doubled = curve_arithmetic::point_double(
                        input.clone().into(),
                        Value::known(*GRUMPKIN_3B),
                    );

                    // TODO: conditional addition
                    let mut is_one = false;
                    bit.value().map(|f| {
                        is_one = Fr::ONE == *f;
                    });

                    if is_one {
                        let added = curve_arithmetic::points_add(
                            result.clone().into(),
                            input.clone().into(),
                            Value::known(*GRUMPKIN_3B),
                        );

                        result = assign_grumpkin_advices(
                            &added,
                            "result",
                            &mut region,
                            self.result,
                            i + 1,
                        )?
                    } else {
                        result = assign_grumpkin_advices(
                            &GrumpkinPoint::new(
                                result.x.value().cloned(),
                                result.y.value().cloned(),
                                result.z.value().cloned(),
                            ),
                            "result",
                            &mut region,
                            self.result,
                            i + 1,
                        )?
                    };

                    input =
                        assign_grumpkin_advices(&doubled, "input", &mut region, self.input, i + 1)?;
                }

                Ok(())
            },
        )
    }

    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advices {
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

    use std::{vec, vec::Vec};

    use curve_arithmetic::field_element_to_bits;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, ff::PrimeField, group::Group, grumpkin::G1},
    };

    use super::*;
    use crate::{gates::test_utils::OneGateCircuit, rng};

    fn input(
        scalar_bits: [Fr; 254],
        p: G1,
        // result: G1
    ) -> ScalarMultiplyGateInput<Fr> {
        ScalarMultiplyGateInput {
            scalar_bits,
            // result: result.into(),
            input: p.into(),
        }
    }

    fn verify(input: ScalarMultiplyGateInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = OneGateCircuit::<ScalarMultiplyGate, _>::new(input);
        MockProver::run(10, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn multiply_random_points() {
        let rng = rng();

        let p = G1::random(rng.clone());

        let n = Fr::from_u128(3);
        let bits = field_element_to_bits(n);

        // let result =
        //     curve_arithmetic::scalar_multiply(p.into(), bits, *GRUMPKIN_3B, Fr::ZERO, Fr::ONE);

        assert!(verify(input(
            bits, p,
            // result.into()
        ))
        .is_ok());
    }
}
