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
    use halo2_proofs::plonk::ConstraintSystem;

    use crate::{
        chips::shortlist_hash::skip_hash_gate::SkipHashGate,
        column_pool::{AccessColumn, ColumnPool},
        gates::Gate,
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
}
