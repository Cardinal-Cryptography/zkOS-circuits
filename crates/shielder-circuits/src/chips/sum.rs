use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, Error},
};

use crate::{
    gates::{
        sum::{SumGate, SumGateValues},
        Gate,
    },
    AssignedCell, Field,
};

#[derive(Clone, Debug)]
pub struct SumChip {
    pub gate: SumGate,
    pub advice: Column<Advice>,
}

impl SumChip {
    /// Constrain cells to satisfy the equation `summand_1 + summand_2 = sum`.
    pub fn constrain_sum<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        summand_1: AssignedCell<F>,
        summand_2: AssignedCell<F>,
        sum: AssignedCell<F>,
    ) -> Result<(), Error> {
        let gate_input = SumGateValues {
            summand_1,
            summand_2,
            sum,
        };
        self.gate.apply_in_new_region(layouter, gate_input)
    }

    /// Constrain cells to satisfy the equation `left_sock = right_sock`.
    pub fn constrain_equal<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        left_sock: AssignedCell<F>,
        right_sock: AssignedCell<F>,
    ) -> Result<(), Error> {
        let gate_input = SumGateValues {
            summand_1: left_sock,
            summand_2: self.zero(layouter)?,
            sum: right_sock,
        };
        self.gate.apply_in_new_region(layouter, gate_input)
    }

    fn zero<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<AssignedCell<F>, Error> {
        layouter.assign_region(
            || "zero",
            |mut region| region.assign_advice_from_constant(|| "zero", self.advice, 0, F::ZERO),
        )
    }
}
