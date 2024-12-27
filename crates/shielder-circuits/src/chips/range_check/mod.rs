use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};
use gate::RangeCheckGate;
use crate::{
    chips::{range_check::running_sum::running_sum, sum::SumChip},
    column_pool::ColumnPool,
    embed::Embed,
    gates::Gate,
    AssignedCell, FieldExt,
};

mod bits;
mod running_sum;
mod gate;

#[derive(Clone, Debug)]
pub struct RangeCheckChip<const CHUNK_SIZE: usize> {
    pub range_gate: RangeCheckGate<CHUNK_SIZE>,
    pub sum_chip: SumChip,
    pub advice_pool: ColumnPool<Advice>,
}

impl<const CHUNK_SIZE: usize> RangeCheckChip<CHUNK_SIZE> {
    /// Constrains the value to be less than `2^(CHUNK_SIZE * chunks)`.
    pub fn constrain_value<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        value: AssignedCell<F>,
        chunks: usize,
    ) -> Result<(), Error> {
        let running_sum_off_circuit = running_sum(value.value().copied(), CHUNK_SIZE, chunks);
        let running_sum_cells =
            running_sum_off_circuit.embed(layouter, &self.advice_pool, "running_sum")?;
        self.sum_chip
            .constrain_equal(layouter, value, running_sum_cells[0].clone())?;
        self.range_gate
            .apply_in_new_region(layouter, running_sum_cells)
    }
}
