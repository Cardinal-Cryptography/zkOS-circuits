use alloc::vec;

use halo2_proofs::{
    arithmetic::{CurveExt, Field},
    circuit::Layouter,
    halo2curves::{bn256::Fr, grumpkin::G1},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    circuits::FieldExt, column_pool::ColumnPool, instance_wrapper::InstanceWrapper, todo::Todo,
    AssignedCell,
};

/// represents the relation P + Q = S
///
/// where P,Q,S are points on the G1 of the Grumpkin curve
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PointAddGate {
    p: [Column<Advice>; 3],
    q: [Column<Advice>; 3],
    s: [Column<Advice>; 3],
    selector: Selector,
}

#[derive(Clone, Debug)]
pub struct PointGateInput {
    p: [AssignedCell<Fr>; 3],
    q: [AssignedCell<Fr>; 3],
    s: [AssignedCell<Fr>; 3],
}
