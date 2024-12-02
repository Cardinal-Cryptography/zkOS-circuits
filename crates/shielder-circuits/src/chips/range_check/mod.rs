mod bits;
mod running_sum;

use alloc::{format, vec};

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    chips::range_check::running_sum::running_sum, circuits::AssignedCell, range_table::RangeTable,
    FieldExt,
};

#[derive(Clone, Debug)]
pub struct LookupRangeCheckChip<const CHUNK_SIZE: usize> {
    q_lookup: Selector,
    running_sum: Column<Advice>,
    table: RangeTable<CHUNK_SIZE>,
}

impl<const CHUNK_SIZE: usize> LookupRangeCheckChip<CHUNK_SIZE> {
    /// The `running_sum` advice column breaks the field element into `CHUNK_SIZE`-bit
    /// words. It is used to construct the input expression to the lookup
    /// argument.
    ///
    /// The `table_idx` fixed column contains values from [0..2^CHUNK_SIZE). Looking up
    /// a value in `table_idx` constrains it to be within this range. The table
    /// can be loaded outside this helper.
    pub fn configure<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
        running_sum: Column<Advice>,
        table: RangeTable<CHUNK_SIZE>,
    ) -> Self {
        let q_lookup = meta.complex_selector();

        meta.lookup("Lookup", |meta| {
            let q_lookup = meta.query_selector(q_lookup);
            let z_cur = meta.query_advice(running_sum, Rotation::cur());
            let z_next = meta.query_advice(running_sum, Rotation::next());

            // We recover the word from the difference of the running sums:
            //    z_i = 2^{CHUNK_SIZE}⋅z_{i + 1} + a_i
            // => a_i = z_i - 2^{CHUNK_SIZE}⋅z_{i + 1}
            let running_sum_lookup = z_cur.clone() - z_next * F::from(1 << CHUNK_SIZE);

            vec![(q_lookup * running_sum_lookup, table.column())]
        });

        LookupRangeCheckChip {
            q_lookup,
            running_sum,
            table,
        }
    }

    /// Range check on an existing cell that is copied into this helper.
    ///
    /// Returns an error if `element` is not in a column that was passed to
    /// [`ConstraintSystem::enable_equality`] during circuit configuration.
    pub fn copy_check<F: FieldExt>(
        &self,
        mut layouter: impl Layouter<F>,
        element: AssignedCell<F>,
        num_words: usize,
    ) -> Result<(), Error> {
        self.table.ensure_initialized(&mut layouter)?;

        layouter.assign_region(
            || format!("{:?} words range check", num_words),
            |mut region| {
                // `num_words` must fit into a single field element.
                assert!(num_words * CHUNK_SIZE <= F::CAPACITY as usize);

                let running_sum = running_sum(element.value().copied(), CHUNK_SIZE, num_words);

                for (idx, z) in running_sum.iter().enumerate() {
                    if idx < num_words {
                        self.q_lookup.enable(&mut region, idx)?;
                    }

                    let chunk = region.assign_advice(
                        || format!("z_{idx:?}"),
                        self.running_sum,
                        idx,
                        || *z,
                    )?;

                    if idx == num_words {
                        region.constrain_constant(chunk.cell(), F::ZERO)?;
                    }
                }

                Ok(())
            },
        )
    }
}
