use alloc::vec;

use halo2_proofs::{
    arithmetic::{CurveExt, Field},
    circuit::{Layouter, Value},
    halo2curves::{bn256::Fr, grumpkin::G1},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Expression, Selector},
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
const ADVICE_OFFSET: i32 = 0;
const GATE_NAME: &str = "Point add gate";

/// Algorithm 7 https://eprint.iacr.org/2015/1060.pdf
fn add(
    p: (Expression<Fr>, Expression<Fr>, Expression<Fr>),
    q: (Expression<Fr>, Expression<Fr>, Expression<Fr>),
) -> (Expression<Fr>, Expression<Fr>, Expression<Fr>) {
    let (x1, y1, z1) = p;
    let (x2, y2, z2) = q;

    let b3 = G1::b() + G1::b() + G1::b();
    let t0 = x1.clone() * x2.clone();
    let t1 = y1.clone() * y2.clone();
    let t2 = z1.clone() * z2.clone();
    let t3 = x1.clone() + y1.clone();
    let t4 = x2.clone() + y2.clone();
    let t3 = t3 * t4;
    let t4 = t0.clone() + t1.clone();
    let t3 = t3 - t4;
    let t4 = y1 + z1.clone();
    let x3 = y2 + z2.clone();
    let t4 = t4 * x3;
    let x3 = t1.clone() + t2.clone();
    let t4 = t4 - x3;
    let x3 = x1 + z1;
    let y3 = x2 + z2;
    let x3 = x3 * y3;
    let y3 = t0.clone() + t2.clone();
    let y3 = x3 - y3;
    let x3 = t0.clone() + t0.clone();
    let t0 = x3 + t0;
    let t2 = t2 * b3;
    let z3 = t1.clone() + t2.clone();
    let t1 = t1 - t2;
    let y3 = y3 * b3;
    let x3 = t4.clone() * y3.clone();
    let t2 = t3.clone() * t1.clone();
    let x3 = t2 - x3.clone();
    let y3 = y3 * t0.clone();
    let t1 = t1 * z3.clone();
    let y3 = t1 + y3.clone();
    let t0 = t0 * t3;
    let z3 = z3 * t4;
    let z3 = z3.clone() + t0;

    (x3, y3, z3)
}

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

            let x1 = vc.query_advice(p[0], Rotation(ADVICE_OFFSET));
            let y1 = vc.query_advice(p[1], Rotation(ADVICE_OFFSET));
            let z1 = vc.query_advice(p[2], Rotation(ADVICE_OFFSET));

            let x2 = vc.query_advice(q[0], Rotation(ADVICE_OFFSET));
            let y2 = vc.query_advice(q[1], Rotation(ADVICE_OFFSET));
            let z2 = vc.query_advice(q[2], Rotation(ADVICE_OFFSET));

            let x3 = vc.query_advice(s[0], Rotation(ADVICE_OFFSET));
            let y3 = vc.query_advice(s[1], Rotation(ADVICE_OFFSET));
            let z3 = vc.query_advice(s[2], Rotation(ADVICE_OFFSET));

            let (res_x3, res_y3, res_z3) = add((x1, y1, z1), (x2, y2, z2));

            vec![
                selector.clone() * (res_x3 - x3),
                selector.clone() * (res_y3 - y3),
                selector * (res_z3 - z3),
            ]
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
