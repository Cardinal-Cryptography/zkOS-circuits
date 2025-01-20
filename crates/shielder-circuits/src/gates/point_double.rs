use alloc::vec;

use halo2_proofs::{
    arithmetic::CurveExt,
    circuit::Layouter,
    halo2curves::{bn256::Fr, grumpkin::G1},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
#[cfg(test)]
use {
    crate::{column_pool::ColumnPool, embed::Embed, F},
    macros::embeddable,
};

use crate::{
    gates::{ensure_unique_columns, Gate},
    AssignedCell,
};

/// represents the relation 2P = S
///
/// where P,S  points on the G1 of the Grumpkin curve
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PointDoubleGate {
    p: [Column<Advice>; 3],
    s: [Column<Advice>; 3],
    selector: Selector,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(
    test,
    embeddable(
        receiver = "PointDoubleGateInput<Fr>",
        impl_generics = "",
        embedded = "PointDoubleGateInput<crate::AssignedCell>"
    )
)]
pub struct PointDoubleGateInput<T> {
    p: [T; 3], // x1,y1,z1
    s: [T; 3], // x2,y2,z2
}

const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: i32 = 0;
const GATE_NAME: &str = "Point double gate";

/// Algorithm 9, https://eprint.iacr.org/2015/1060.pdf
fn double(
    p: (Expression<Fr>, Expression<Fr>, Expression<Fr>),
) -> (Expression<Fr>, Expression<Fr>, Expression<Fr>) {
    let (x, y, z) = p;

    let b3 = G1::b() + G1::b() + G1::b();
    let t0 = y.clone() * y.clone();
    let z3 = t0.clone() + t0.clone();
    let z3 = z3.clone() + z3;
    let z3 = z3.clone() + z3;
    let t1 = y.clone() * z.clone();
    let t2 = z.clone() * z;
    let t2 = t2 * b3;
    let x3 = t2.clone() * z3.clone();
    let y3 = t0.clone() + t2.clone();
    let z3 = t1 * z3;
    let t1 = t2.clone() + t2.clone();
    let t2 = t1 + t2;
    let t0 = t0 - t2;
    let y3 = t0.clone() * y3;
    let y3 = x3 + y3;
    let t1 = x * y;
    let x3 = t0 * t1;
    let x3 = x3.clone() + x3;

    (x3, y3, z3)
}
