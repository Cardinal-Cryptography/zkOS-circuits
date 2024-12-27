use alloc::{format, vec, vec::Vec};

use halo2_proofs::{
    circuit::{Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use crate::{gates::Gate, range_table::RangeTable, AssignedCell, FieldExt};

/// Represents inequality: `base - shifted * 2^CHUNK_SIZE < 2^CHUNK_SIZE`.
#[derive(Clone, Debug)]
pub struct RangeCheckGate<const CHUNK_SIZE: usize> {
    advice: Column<Advice>,
    selector: Selector,
    table: RangeTable<CHUNK_SIZE>,
}

/// The values that are required to construct a range check gate. Pair `(base, shifted)` is expected
/// to satisfy the inequality: `base - shifted * 2^CHUNK_SIZE < 2^CHUNK_SIZE`.
pub type RangeCheckGateValues<F> = (AssignedCell<F>, AssignedCell<F>);

const GATE_NAME: &str = "Range check gate";
const BASE_OFFSET: usize = 0;
const SHIFTED_OFFSET: usize = 1;

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
    fn create_gate(cs: &mut ConstraintSystem<F>, advice: Self::Advices) -> Self {
        let selector = cs.complex_selector();
        let table = RangeTable::new(cs);

        cs.lookup("Range check lookup", |meta| {
            let selector = meta.query_selector(selector);
            let base = meta.query_advice(advice, Rotation(BASE_OFFSET as i32));
            let shifted = meta.query_advice(advice, Rotation(SHIFTED_OFFSET as i32));

            // We require that:
            //  - base = shifted * SCALE + chunk
            //  - chunk < 2^CHUNK_SIZE
            // where SCALE = 2^CHUNK_SIZE.
            //
            // Therefore, we recover the chunk as:
            //  - chunk = base - shifted * SCALE
            let scale = Expression::Constant(F::from(1 << CHUNK_SIZE));
            let chunk = base - shifted * scale;

            vec![(selector * chunk, table.column())]
        });

        RangeCheckGate {
            advice,
            selector,
            table,
        }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<F>,
        (base, shifted): (AssignedCell<F>, AssignedCell<F>),
    ) -> Result<(), Error> {
        self.table.ensure_initialized(layouter)?;
        layouter.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector.enable(&mut region, 0)?;
                base.copy_advice(|| "base", &mut region, self.advice, BASE_OFFSET)?;
                shifted.copy_advice(|| "shifted", &mut region, self.advice, SHIFTED_OFFSET)?;
                Ok(())
            },
        )
    }
}
