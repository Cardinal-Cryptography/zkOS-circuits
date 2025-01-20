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

#[derive(Clone, Debug, Default)]
#[cfg_attr(
    test,
    embeddable(
        receiver = "PointAddGateInput<Fr>",
        impl_generics = "",
        embedded = "PointAddGateInput<crate::AssignedCell>"
    )
)]
pub struct PointAddGateInput<T> {
    p: [T; 3], // x1,y1,z1
    q: [T; 3], // x2,y2,z2
    s: [T; 3], // x3,y3,z3
}

const SELECTOR_OFFSET: usize = 0;
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
    let x3 = t2 - x3;
    let y3 = y3 * t0.clone();
    let t1 = t1 * z3.clone();
    let y3 = t1 + y3;
    let t0 = t0 * t3;
    let z3 = z3 * t4;
    let z3 = z3 + t0;

    (x3, y3, z3)
}

impl Gate for PointAddGate {
    type Input = PointAddGateInput<AssignedCell>;

    type Advices = (
        [Column<Advice>; 3], // p
        [Column<Advice>; 3], // q
        [Column<Advice>; 3], // s
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

            Constraints::with_selector(selector, vec![res_x3 - x3, res_y3 - y3, res_z3 - z3])
        });

        Self { p, q, s, selector }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<Fr>,
        input: Self::Input,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector.enable(&mut region, SELECTOR_OFFSET)?;

                for (i, cell) in input.p.iter().enumerate() {
                    cell.copy_advice(
                        || alloc::format!("P[{i}]"),
                        &mut region,
                        self.p[i],
                        ADVICE_OFFSET as usize,
                    )?;
                }

                for (i, cell) in input.q.iter().enumerate() {
                    cell.copy_advice(
                        || alloc::format!("Q[{i}]"),
                        &mut region,
                        self.q[i],
                        ADVICE_OFFSET as usize,
                    )?;
                }

                for (i, cell) in input.s.iter().enumerate() {
                    cell.copy_advice(
                        || alloc::format!("S[{i}]"),
                        &mut region,
                        self.s[i],
                        ADVICE_OFFSET as usize,
                    )?;
                }

                Ok(())
            },
        )
    }

    #[cfg(test)]
    fn organize_advice_columns(
        pool: &mut ColumnPool<Advice>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advices {
        pool.ensure_capacity(cs, 9);

        (
            [pool.get(0), pool.get(1), pool.get(2)],
            [pool.get(3), pool.get(4), pool.get(5)],
            [pool.get(6), pool.get(7), pool.get(8)],
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use halo2_proofs::{
        arithmetic::Field,
        dev::{MockProver, VerifyFailure},
        halo2curves::{bn256::Fr, group::Group, grumpkin::G1},
        plonk::ConstraintSystem,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use super::{PointAddGate, PointAddGateInput};
    use crate::gates::{test_utils::OneGateCircuit, Gate as _};

    fn rng() -> StdRng {
        StdRng::from_seed(*b"00000000000000000000100001011001")
    }

    fn input(p: G1, q: G1, s: G1) -> PointAddGateInput<Fr> {
        PointAddGateInput {
            p: [p.x, p.y, p.z],
            q: [q.x, q.y, q.z],
            s: [s.x, s.y, s.z],
        }
    }

    fn verify(input: PointAddGateInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = OneGateCircuit::<PointAddGate, _>::new(input);
        MockProver::run(3, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn gate_creation() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let p = [cs.advice_column(), cs.advice_column(), cs.advice_column()];
        let q = [cs.advice_column(), cs.advice_column(), cs.advice_column()];
        let s = [cs.advice_column(), cs.advice_column(), cs.advice_column()];

        PointAddGate::create_gate(&mut cs, (p, q, s));
    }

    #[test]
    fn adding_point_at_infinity() {
        let p = G1 {
            x: Fr::ZERO,
            y: Fr::ONE,
            z: Fr::ZERO,
        };
        let q = G1 {
            x: Fr::ZERO,
            y: Fr::ONE,
            z: Fr::ZERO,
        };
        let s = p + q;

        assert!(verify(input(p, q, s)).is_ok());
    }

    #[test]
    fn adding_random_points() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let s = p + q;

        assert!(verify(input(p, q, s)).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let q = G1::random(rng.clone());
        let s = G1::random(rng.clone());

        verify(input(p, q, s)).expect_err("Verification should fail");
    }
}
