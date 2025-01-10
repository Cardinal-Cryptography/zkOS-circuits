use core::array;

use halo2_proofs::circuit::Value;

use crate::{AssignedCell, FieldExt};

pub fn values_from_cell_array<F: FieldExt, const N: usize>(
    cell_array: &[AssignedCell<F>; N],
) -> [Value<F>; N] {
    array::from_fn(|i| cell_array[i].value().copied())
}
