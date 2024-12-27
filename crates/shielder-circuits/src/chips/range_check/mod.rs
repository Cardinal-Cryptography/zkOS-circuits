use gate::RangeCheckGate;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, ConstraintSystem, Error},
};

use crate::{
    chips::{range_check::running_sum::running_sum, sum::SumChip},
    column_pool::ColumnPool,
    embed::Embed,
    gates::Gate,
    AssignedCell, FieldExt,
};

mod bits;
mod gate;
mod running_sum;

#[derive(Clone, Debug)]
pub struct RangeCheckChip<const CHUNK_SIZE: usize> {
    range_gate: RangeCheckGate<CHUNK_SIZE>,
    sum_chip: SumChip,
    advice_pool: ColumnPool<Advice>,
}

impl<const CHUNK_SIZE: usize> RangeCheckChip<CHUNK_SIZE> {
    pub fn new<F: FieldExt>(
        system: &mut ConstraintSystem<F>,
        advice_pool: ColumnPool<Advice>,
        sum_chip: SumChip,
    ) -> Self {
        let range_gate = RangeCheckGate::create_gate(system, advice_pool.get_any());
        Self {
            range_gate,
            sum_chip,
            advice_pool,
        }
    }

    /// Constrains the value to be less than `2^(CHUNK_SIZE * CHUNKS)`.
    pub fn constrain_value<const CHUNKS: usize, F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        value: AssignedCell<F>,
    ) -> Result<(), Error> {
        let running_sum_off_circuit = running_sum(value.value().copied(), CHUNK_SIZE, CHUNKS);
        let running_sum_cells =
            running_sum_off_circuit.embed(layouter, &self.advice_pool, "running_sum")?;
        self.sum_chip
            .constrain_equal(layouter, value, running_sum_cells[0].clone())?;
        Ok(())
        // self.range_gate
        //     .apply_in_new_region(layouter, running_sum_cells)
    }
}
