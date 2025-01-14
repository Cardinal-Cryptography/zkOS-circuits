use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, Error},
};

use crate::{
    gates::{
        sum::{SumGate, SumGateInput},
        Gate,
    },
    AssignedCell, Field, F,
};

#[derive(Clone, Debug)]
pub struct SumChip {
    pub gate: SumGate,
    pub advice: Column<Advice>,
}

impl SumChip {
    /// Constrain cells to satisfy the equation `summand_1 + summand_2 = sum`.
    pub fn constrain_sum(
        &self,
        layouter: &mut impl Layouter<F>,
        summand_1: AssignedCell,
        summand_2: AssignedCell,
        sum: AssignedCell,
    ) -> Result<(), Error> {
        let gate_input = SumGateInput {
            summand_1,
            summand_2,
            sum,
        };
        self.gate.apply_in_new_region(layouter, gate_input)
    }

    /// Constrain cells to satisfy the equation `left_sock = right_sock`.
    pub fn constrain_equal(
        &self,
        layouter: &mut impl Layouter<F>,
        left_sock: AssignedCell,
        right_sock: AssignedCell,
    ) -> Result<(), Error> {
        let gate_input = SumGateInput {
            summand_1: left_sock,
            summand_2: self.zero(layouter)?,
            sum: right_sock,
        };
        self.gate.apply_in_new_region(layouter, gate_input)
    }

    /// Constrain cell to satisfy the equation `zero = 0`.
    pub fn constrain_zero(
        &self,
        layouter: &mut impl Layouter<F>,
        zero: AssignedCell,
    ) -> Result<(), Error> {
        let true_zero = self.zero(layouter)?;
        self.constrain_equal(layouter, zero, true_zero)
    }

    fn zero(&self, layouter: &mut impl Layouter<F>) -> Result<AssignedCell, Error> {
        layouter.assign_region(
            || "zero",
            |mut region| region.assign_advice_from_constant(|| "zero", self.advice, 0, F::ZERO),
        )
    }
}
