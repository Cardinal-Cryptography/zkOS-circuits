mod bits;
mod running_sum;

use alloc::{format, vec};
use core::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    chips::range_check::running_sum::running_sum,
    circuits::{AssignedCell, FieldExt},
    range_table::RangeTable,
};

#[derive(Clone, Debug)]
pub struct LookupRangeCheckChip<F: FieldExt, const CHUNK_SIZE: usize> {
    q_lookup: Selector,
    running_sum: Column<Advice>,
    table: RangeTable<CHUNK_SIZE>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const CHUNK_SIZE: usize> LookupRangeCheckChip<F, CHUNK_SIZE> {
    /// The `running_sum` advice column breaks the field element into `CHUNK_SIZE`-bit
    /// words. It is used to construct the input expression to the lookup
    /// argument.
    ///
    /// The `table_idx` fixed column contains values from [0..2^CHUNK_SIZE). Looking up
    /// a value in `table_idx` constrains it to be within this range. The table
    /// can be loaded outside this helper.
    pub fn configure(
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
            _marker: PhantomData,
        }
    }

    /// Range check on an existing cell that is copied into this helper.
    ///
    /// Returns an error if `element` is not in a column that was passed to
    /// [`ConstraintSystem::enable_equality`] during circuit configuration.
    pub fn copy_check(
        &self,
        mut layouter: impl Layouter<F>,
        element: AssignedCell<F>,
        num_words: usize,
    ) -> Result<(), Error> {
        self.table.ensure_initialized(&mut layouter)?;

        layouter.assign_region(
            || format!("{:?} words range check", num_words),
            |mut region| {
                // Copy `element` and initialize running sum `z_0 = element` to decompose it.
                let z_0 = element.copy_advice(|| "z_0", &mut region, self.running_sum, 0)?;
                self.range_check(&mut region, z_0, num_words)
            },
        )
    }

    /// The field element must fit into
    /// `num_words * CHUNK_SIZE` bits. In other words, the the final cumulative sum `z_{num_words}`
    /// must be zero.
    ///
    /// `element` must have been assigned to `self.running_sum` at offset 0.
    fn range_check(
        &self,
        region: &mut Region<'_, F>,
        element: AssignedCell<F>,
        num_words: usize,
    ) -> Result<(), Error> {
        // `num_words` must fit into a single field element.
        assert!(num_words * CHUNK_SIZE <= F::CAPACITY as usize);

        let running_sum = running_sum(element.value().copied(), CHUNK_SIZE, num_words);

        for (idx, z) in running_sum[1..].iter().enumerate() {
            self.q_lookup.enable(region, idx)?;
            region.assign_advice(
                || format!("z_{:?}", idx + 1),
                self.running_sum,
                idx + 1,
                || *z,
            )?;
        }

        Ok(())
    }
}
