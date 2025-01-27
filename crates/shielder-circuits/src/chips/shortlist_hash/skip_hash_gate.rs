use alloc::vec;

use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};
use macros::embeddable;

#[cfg(test)]
use crate::column_pool::{AccessColumn, ColumnPool, ConfigPhase};
use crate::{
    consts::POSEIDON_RATE,
    embed::Embed,
    gates::{ensure_unique_columns, Gate},
    synthesizer::Synthesizer,
    AssignedCell, Fr,
};

const INPUT_WIDTH: usize = POSEIDON_RATE - 1;

#[derive(Clone, Debug)]
#[embeddable(
    receiver = "SkipHashGateInput<Fr>",
    impl_generics = "",
    embedded = "SkipHashGateInput<AssignedCell>"
)]
pub struct SkipHashGateInput<T> {
    pub input: [T; INPUT_WIDTH],
    pub sum_inverse: T,
    pub hash: T,
    pub result: T,
}

impl<T: Default + Copy> Default for SkipHashGateInput<T> {
    fn default() -> Self {
        Self {
            input: [T::default(); INPUT_WIDTH],
            sum_inverse: T::default(),
            hash: T::default(),
            result: T::default(),
        }
    }
}

/// SkipHash gate represents the relation `R(result, sum, hash)` defined as:
///
/// `result := if (sum == 0) { 0 } else { hash }`
///
/// In order to implement it with arithmetic constraints, it is convenient to introduce an auxiliary
/// one `R'(result, sum, hash, sum_inverse)`, defined as:
///
/// `if (sum == 0) { result := 0    && sum_inverse is arbitrary`
/// `else          { result := hash && sum_inverse = 1 / sum }`
///
/// It is quite straightforward to see that `(result, sum, hash) ∈ R` if and only if there exists
/// `sum_inverse` such that `(result, sum, hash, sum_inverse) ∈ R'`.
///
/// `R'` can be implemented with the following constraints:
///   - `sum * sum * sum_inverse  = sum`        // if `sum == 0` then `sum_inverse` can be arbitrary
///                                                otherwise `sum_inverse = 1 / sum`
///   - `sum * sum_inverse * hash = result`     // if `sum == 0` then `result = 0`, otherwise
///                                                `result = hash` (given the previous constraint)
///
/// For usage convenience, instead of `sum`, we take `input` array and compute `sum` as a sum of
/// the elements.
#[derive(Clone, Debug)]
pub struct SkipHashGate {
    selector: Selector,
    advice: SkipHashGateInput<Column<Advice>>,
}

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;
const GATE_NAME: &str = "SkipHash gate";

impl Gate for SkipHashGate {
    type Input = SkipHashGateInput<AssignedCell>;
    type Advices = SkipHashGateInput<Column<Advice>>;

    fn create_gate(cs: &mut ConstraintSystem<Fr>, advice: Self::Advices) -> Self {
        ensure_unique_columns(
            &[
                advice.input.to_vec(),
                vec![advice.hash, advice.sum_inverse, advice.result],
            ]
            .concat(),
        );

        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let sum = advice
                .input
                .map(|col| vc.query_advice(col, Rotation(ADVICE_OFFSET as i32)))
                .into_iter()
                .reduce(|a, b| a + b)
                .expect("At least one input column is expected");

            let sum_inverse = vc.query_advice(advice.sum_inverse, Rotation(ADVICE_OFFSET as i32));
            let hash = vc.query_advice(advice.hash, Rotation(ADVICE_OFFSET as i32));
            let result = vc.query_advice(advice.result, Rotation(ADVICE_OFFSET as i32));

            Constraints::with_selector(
                vc.query_selector(selector),
                vec![
                    sum.clone() * sum_inverse.clone() * hash - result,
                    sum.clone() * sum.clone() * sum_inverse - sum,
                ],
            )
        });

        Self { selector, advice }
    }

    fn apply_in_new_region(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: Self::Input,
    ) -> Result<(), Error> {
        synthesizer.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector.enable(&mut region, SELECTOR_OFFSET)?;

                for (i, column) in input.input.iter().enumerate() {
                    column.copy_advice(
                        || alloc::format!("input_{i}"),
                        &mut region,
                        self.advice.input[i],
                        ADVICE_OFFSET,
                    )?;
                }

                let rest = [
                    (&input.sum_inverse, "sum inverse", self.advice.sum_inverse),
                    (&input.hash, "hash", self.advice.hash),
                    (&input.result, "result", self.advice.result),
                ];

                for (cell, name, advice) in rest.into_iter() {
                    cell.copy_advice(|| name, &mut region, advice, ADVICE_OFFSET)?;
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
        pool.ensure_capacity(cs, INPUT_WIDTH + 3);
        SkipHashGateInput {
            input: pool.get_column_array(),
            sum_inverse: pool.get_column(INPUT_WIDTH),
            hash: pool.get_column(INPUT_WIDTH + 1),
            result: pool.get_column(INPUT_WIDTH + 2),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::rust_2015::{String, Vec};

    use halo2_proofs::plonk::ConstraintSystem;

    use crate::{
        chips::shortlist_hash::skip_hash_gate::{SkipHashGate, SkipHashGateInput},
        column_pool::{AccessColumn, ColumnPool},
        consts::NUM_TOKENS,
        gates::{test_utils::verify, Gate},
        Fr,
    };

    #[test]
    fn gate_creation_with_proper_columns_passes() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let advice = SkipHashGate::organize_advice_columns(&mut ColumnPool::new(), &mut cs);
        SkipHashGate::create_gate(&mut cs, advice);
    }

    #[test]
    #[should_panic = "Advice columns must be unique"]
    fn gate_creation_with_not_distinct_columns_fails() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let mut pool = ColumnPool::new();
        let advice = SkipHashGate::organize_advice_columns(&mut pool, &mut cs);
        let mut advice = advice;
        advice.result = pool.get_column(0);
        SkipHashGate::create_gate(&mut cs, advice);
    }

    fn input(
        input: [impl Into<Fr>; NUM_TOKENS],
        sum_inverse: impl Into<Fr>,
        hash: impl Into<Fr>,
        result: impl Into<Fr>,
    ) -> SkipHashGateInput<Fr> {
        SkipHashGateInput {
            input: input.map(|x| x.into()),
            sum_inverse: sum_inverse.into(),
            hash: hash.into(),
            result: result.into(),
        }
    }

    #[test]
    fn if_sum_is_zero_result_is_zero_and_inverse_can_be_zero() {
        assert!(verify::<SkipHashGate, _>(input([0; NUM_TOKENS], 0, 41, 0)).is_ok());
    }

    #[test]
    fn if_sum_is_zero_result_is_zero_and_inverse_can_be_anything() {
        assert!(verify::<SkipHashGate, _>(input([0; NUM_TOKENS], 41, 41, 0)).is_ok());
    }

    #[test]
    fn zero_sum_with_negatives() {
        assert!(verify::<SkipHashGate, _>(input(
            [
                Fr::from(1),
                Fr::from(2),
                Fr::from(3),
                Fr::from(6).neg(),
                Fr::from(5),
                Fr::from(5).neg(),
            ],
            17, // anything
            41,
            0
        ))
        .is_ok());
    }

    #[test]
    fn if_sum_is_nonzero_result_is_hash_and_inverse_is_correct() {
        assert!(verify::<SkipHashGate, _>(input(
            [1; NUM_TOKENS],
            Fr::from(NUM_TOKENS as u64).invert().unwrap(),
            41,
            41
        ))
        .is_ok());
    }

    fn assert_fails(res: Result<(), Vec<String>>) {
        let errors = res.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Constraint 0 in gate 0 ('SkipHash gate') is not satisfied"));
    }

    #[test]
    fn if_sum_is_zero_result_must_be_zero() {
        assert_fails(verify::<SkipHashGate, _>(input([0; NUM_TOKENS], 0, 41, 1)));
    }

    #[test]
    fn if_sum_is_nonzero_result_must_be_equal_to_hash() {
        assert_fails(verify::<SkipHashGate, _>(input(
            [1; NUM_TOKENS],
            Fr::from(NUM_TOKENS as u64).invert().unwrap(),
            41,
            42,
        )));
    }

    #[test]
    fn if_sum_is_nonzero_inverse_must_be_inverse() {
        let errors = verify::<SkipHashGate, _>(input([1; NUM_TOKENS], 1, 41, 41)).unwrap_err();
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("Constraint 0 in gate 0 ('SkipHash gate') is not satisfied"));
        assert!(errors[1].contains("Constraint 1 in gate 0 ('SkipHash gate') is not satisfied"));
    }
}
