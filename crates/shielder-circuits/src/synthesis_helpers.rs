use alloc::vec;
use core::borrow::BorrowMut;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, Error},
};

use crate::{column_pool::ColumnPool, AssignedCell};

/// Assign all values to the advice column and return that many AssignedCells.
pub fn assign_values_to_advice<F: Field, const B: usize>(
    layouter: &mut impl Layouter<F>,
    advice_pool: &ColumnPool<Advice>,
    annotation: &str,
    values: [(Value<F>, &str); B],
) -> Result<[AssignedCell<F>; B], Error> {
    let mut assigned_cells = vec![];

    for (value, val_ann) in values {
        let assigned = layouter.assign_region(
            || annotation,
            |mut region| region.assign_advice(|| val_ann, advice_pool.get_any(), 0, || value),
        )?;
        assigned_cells.push(assigned);
    }

    Ok(assigned_cells.try_into().expect("Safe unwrap"))
}

/// Assigns a 2D array of values to a 2D array of advice columns within a region.
pub fn assign_2d_advice_array<'region, const A: usize, const B: usize, F: Field>(
    mut region: impl BorrowMut<Region<'region, F>>,
    values: [[Value<F>; B]; A],
    advice: [Column<Advice>; B],
) -> Result<[[AssignedCell<F>; B]; A], Error> {
    let mut assign_cell = |a, b| {
        region.borrow_mut().assign_advice(
            || alloc::format!("cell [{a}][{b}]"),
            advice[b],
            a,
            || values[a][b],
        )
    };

    let mut cells = vec![];
    for a in 0..A {
        let mut row = vec![];
        for b in 0..B {
            row.push(assign_cell(a, b)?);
        }
        cells.push(row.try_into().expect("Safe unwrap"));
    }
    Ok(cells.try_into().expect("Safe unwrap"))
}
