use alloc::vec;

use halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{gates::Gate, AssignedCell};

/// Represents the relation: `summand_1 + summand_2 = sum`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SumGate {
    advice: Column<Advice>,
    selector: Selector,
}

#[derive(Clone, Debug)]
pub struct SumGateValues<F: Field> {
    pub summand_1: AssignedCell<F>,
    pub summand_2: AssignedCell<F>,
    pub sum: AssignedCell<F>,
}

const SELECTOR_OFFSET: usize = 0;
const SUMMAND_1_OFFSET: usize = 0;
const SUMMAND_2_OFFSET: usize = 1;
const SUM_OFFSET: usize = 2;
const GATE_NAME: &str = "Sum gate";

impl<F: Field> Gate<F> for SumGate {
    type Values = SumGateValues<F>;
    type Advices = Column<Advice>;

    fn create_gate(cs: &mut ConstraintSystem<F>, advice: Self::Advices) -> Self {
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);
            let summand_1 = vc.query_advice(advice, Rotation(SUMMAND_1_OFFSET as i32));
            let summand_2 = vc.query_advice(advice, Rotation(SUMMAND_2_OFFSET as i32));
            let sum = vc.query_advice(advice, Rotation(SUM_OFFSET as i32));
            vec![selector * (summand_1 + summand_2 - sum)]
        });
        Self { advice, selector }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<F>,
        input: Self::Values,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector.enable(&mut region, SELECTOR_OFFSET)?;

                for (cell, name, offset) in [
                    (&input.summand_1, "summand 1", SUMMAND_1_OFFSET),
                    (&input.summand_2, "summand 2", SUMMAND_2_OFFSET),
                    (&input.sum, "sum", SUM_OFFSET),
                ] {
                    cell.copy_advice(|| name, &mut region, self.advice, offset)?;
                }

                Ok(())
            },
        )
    }
}
