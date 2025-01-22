use alloc::vec::Vec;

use halo2_proofs::{
    arithmetic::CurveExt,
    circuit::{Layouter, Value},
    halo2curves::grumpkin::G1,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::ColumnPool,
    curve_operations,
    gates::{
        point_double::{PointDoubleGate, PointDoubleGateInput},
        Gate,
    },
    AssignedCell, F,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct PointDoubleChipInput<T> {
    pub p: [T; 3],
}

// #[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct PointDoubleChipOutput<T> {
    pub s: [T; 3],
}

/// Chip that doubles a point on a Grumpkin curve.
///
/// P + Q = S
#[derive(Clone, Debug)]
pub struct PointsAddChip {
    pub advice_pool: ColumnPool<Advice>,
    pub gate: PointDoubleGate,
}
