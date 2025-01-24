use alloc::vec;

use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};
use macros::embeddable;

#[cfg(test)]
use crate::column_pool::{ColumnPool, ConfigPhase};
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

const SELECTOR_OFFSET: i32 = 0;
const ADVICE_OFFSET: i32 = 0;
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
                .map(|col| vc.query_advice(col, Rotation(ADVICE_OFFSET)))
                .into_iter()
                .reduce(|a, b| a + b)
                .expect("At least one input column is expected");

            let sum_inverse = vc.query_advice(advice.sum_inverse, Rotation(ADVICE_OFFSET));
            let hash = vc.query_advice(advice.hash, Rotation(ADVICE_OFFSET));
            let result = vc.query_advice(advice.result, Rotation(ADVICE_OFFSET));

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
        todo!()
    }

    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advices {
        todo!()
    }
}
