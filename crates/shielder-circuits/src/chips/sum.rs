use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::{ColumnPool, SynthesisPhase},
    gates::{
        sum::{SumGate, SumGateInput},
        Gate,
    },
    AssignedCell, Field, F,
};

#[derive(Clone, Debug)]
pub struct SumChip(SumGate);

impl SumChip {
    pub fn new(gate: SumGate) -> Self {
        Self(gate)
    }

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
        self.0.apply_in_new_region(layouter, gate_input)
    }

    /// Constrain cells to satisfy the equation `left_sock = right_sock`.
    pub fn constrain_equal(
        &self,
        layouter: &mut impl Layouter<F>,
        column_pool: &ColumnPool<Advice, SynthesisPhase>,
        left_sock: AssignedCell,
        right_sock: AssignedCell,
    ) -> Result<(), Error> {
        let gate_input = SumGateInput {
            summand_1: left_sock,
            summand_2: self.zero(layouter, column_pool)?,
            sum: right_sock,
        };
        self.0.apply_in_new_region(layouter, gate_input)
    }

    /// Constrain cell to satisfy the equation `zero = 0`.
    pub fn constrain_zero(
        &self,
        layouter: &mut impl Layouter<F>,
        column_pool: &ColumnPool<Advice, SynthesisPhase>,
        zero: AssignedCell,
    ) -> Result<(), Error> {
        let true_zero = self.zero(layouter, column_pool)?;
        self.constrain_equal(layouter, column_pool, zero, true_zero)
    }

    fn zero(
        &self,
        layouter: &mut impl Layouter<F>,
        column_pool: &ColumnPool<Advice, SynthesisPhase>,
    ) -> Result<AssignedCell, Error> {
        layouter.assign_region(
            || "zero",
            |mut region| {
                region.assign_advice_from_constant(|| "zero", column_pool.get_any(), 0, F::ZERO)
            },
        )
    }
}
