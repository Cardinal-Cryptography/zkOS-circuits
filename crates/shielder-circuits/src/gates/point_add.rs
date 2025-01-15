use alloc::vec;

use halo2_proofs::{
    arithmetic::{CurveExt, Field},
    circuit::Layouter,
    halo2curves::{bn256::Fr, grumpkin::G1},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    circuits::FieldExt,
    column_pool::ColumnPool,
    gates::{ensure_unique_columns, Gate},
    instance_wrapper::InstanceWrapper,
    todo::Todo,
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
pub struct PointAddGateInput {
    p: [AssignedCell<Fr>; 3], // x1,y1,z1
    q: [AssignedCell<Fr>; 3], // x2,y2,z2
    s: [AssignedCell<Fr>; 3], // x3,y3,z3
}

// const SELECTOR_OFFSET: usize = 0;
const ADVICE_OFFSET: usize = 0;
const GATE_NAME: &str = "Point add gate";

impl Gate<Fr> for PointAddGate {
    type Input = PointAddGateInput;

    type Advices = (
        [Column<Advice>; 3],
        [Column<Advice>; 3],
        [Column<Advice>; 3],
    );

    fn create_gate(cs: &mut ConstraintSystem<Fr>, (p, q, s): Self::Advices) -> Self {
        ensure_unique_columns(&[p.to_vec(), q.to_vec(), s.to_vec()].concat());
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);

            let x1 = vc.query_advice(p[0], Rotation(ADVICE_OFFSET as i32));
            let x2 = vc.query_advice(p[1], Rotation(ADVICE_OFFSET as i32));
            let x3 = vc.query_advice(p[2], Rotation(ADVICE_OFFSET as i32));

            let x1 = vc.query_advice(p[0], Rotation(ADVICE_OFFSET as i32));
            let x2 = vc.query_advice(p[1], Rotation(ADVICE_OFFSET as i32));
            let x3 = vc.query_advice(p[2], Rotation(ADVICE_OFFSET as i32));

            vec![selector]
        });

        Self { p, q, s, selector }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<Fr>,
        input: Self::Input,
    ) -> Result<(), Error> {
        todo!()
    }

    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advices {
        todo!()
    }
}
