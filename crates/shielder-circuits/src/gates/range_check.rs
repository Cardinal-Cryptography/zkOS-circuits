use alloc::{format, vec, vec::Vec};

use halo2_proofs::{
    circuit::{Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use crate::{gates::Gate, range_table::RangeTable, AssignedCell, FieldExt};

/// Represents inequality: `value < 2^N`, where `N` is some multiple of `CHUNK_SIZE`. `value` must
/// be represented as a running sum of chunks of size `CHUNK_SIZE`.
#[derive(Clone, Debug)]
pub struct RangeCheckGate<const CHUNK_SIZE: usize> {
    running_sum: Column<Advice>,
    selector: Selector,
    table: RangeTable<CHUNK_SIZE>,
}

/// Represents a running sum.
pub type RangeCheckGateValues<F> = Vec<AssignedCell<F>>;

const GATE_NAME: &str = "Range check gate";

impl<const CHUNK_SIZE: usize, F: FieldExt> Gate<F> for RangeCheckGate<CHUNK_SIZE> {
    type Values = RangeCheckGateValues<F>;
    type Advices = Column<Advice>;

    /// The gate operates on a single advice column `A` and a table `T`. It enforces that:
    ///
    /// `A[x] - A[x+1] * 2^CHUNK_SIZE` belongs to `T`
    ///
    /// where:
    ///  - `x` is the row where the gate is enabled
    ///  - `T` represents set `[0, 2^CHUNK_SIZE)`
    fn create_gate(cs: &mut ConstraintSystem<F>, running_sum: Self::Advices) -> Self {
        let selector = cs.complex_selector();
        let table = RangeTable::new(cs);

        cs.lookup("Range check lookup", |meta| {
            let selector = meta.query_selector(selector);
            let curr_sum = meta.query_advice(running_sum, Rotation::cur());
            let next_sum = meta.query_advice(running_sum, Rotation::next());

            // We require that:
            //  - curr_sum = next_sum * SCALE + chunk
            //  - chunk < 2^CHUNK_SIZE
            // where SCALE = 2^CHUNK_SIZE.
            //
            // Therefore, we recover the chunk as:
            //  - chunk = curr_sum - next_sum * SCALE
            let scale = Expression::Constant(F::from(1 << CHUNK_SIZE));
            let chunk = curr_sum - next_sum * scale;

            vec![(selector * chunk, table.column())]
        });

        RangeCheckGate {
            running_sum,
            selector,
            table,
        }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<F>,
        running_sum: Self::Values,
    ) -> Result<(), Error> {
        // We assume that the running sum has length `n` and the following form:
        //  - rs[0] = X, where X is the original value to be range checked.
        //  - rs[i] = rs[i + 1] * 2^CHUNK_SIZE + a[i], for i = 0...n-2
        //  - rs[n - 1] = 0
        //  - a[i] < 2^CHUNK_SIZE, for i = 0...n-2

        let n = running_sum.len();
        assert!((n - 1) * CHUNK_SIZE <= F::CAPACITY as usize);

        self.table.ensure_initialized(layouter)?;
        layouter.assign_region(
            || GATE_NAME,
            |mut region| {
                // 1. Copy the running sum into the region.
                let running_sum = self.copy_running_sum(&mut region, &running_sum)?;
                // 2. For all consecutive pairs of sums, enable the selector.
                for i in 0..n - 1 {
                    self.selector.enable(&mut region, i)?;
                }
                // 3. Ensure that the last sum is zero.
                region.constrain_constant(running_sum[n - 1].cell(), F::ZERO)
            },
        )
    }
}

impl<const CHUNK_SIZE: usize> RangeCheckGate<CHUNK_SIZE> {
    /// Copy the cells of running sum into the region.
    fn copy_running_sum<F: FieldExt>(
        &self,
        region: &mut Region<F>,
        running_sum: &[AssignedCell<F>],
    ) -> Result<Vec<AssignedCell<F>>, Error> {
        let mut copied = Vec::with_capacity(running_sum.len());
        for (i, sum) in running_sum.iter().enumerate() {
            let ann = || format!("running sum[{i}]");
            copied.push(sum.copy_advice(ann, region, self.running_sum, i)?);
        }
        Ok(copied)
    }
}
