use alloc::vec;

use halo2_proofs::{
    circuit::Layouter,
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
#[cfg(test)]
use {
    crate::{column_pool::ColumnPool, column_pool::ConfigPhase, embed::Embed},
    macros::embeddable,
};

use crate::{
    consts::GRUMPKIN_3B,
    curve_operations::{self, GrumpkinPoint},
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
    pub p: [T; 3], // x1,y1,z1
    pub s: [T; 3], // x2,y2,z2
}

const SELECTOR_OFFSET: i32 = 0;
const ADVICE_OFFSET: i32 = 0;
const GATE_NAME: &str = "Point double gate";

impl Gate for PointDoubleGate {
    type Input = PointDoubleGateInput<AssignedCell>;

    type Advices = (
        [Column<Advice>; 3], // p
        [Column<Advice>; 3], // s
    );

    fn create_gate(cs: &mut ConstraintSystem<Fr>, (p, s): Self::Advices) -> Self {
        ensure_unique_columns(&[p.to_vec(), s.to_vec()].concat());
        let selector = cs.selector();

        cs.create_gate(GATE_NAME, |vc| {
            let selector = vc.query_selector(selector);

            let x = vc.query_advice(p[0], Rotation(ADVICE_OFFSET));
            let y = vc.query_advice(p[1], Rotation(ADVICE_OFFSET));
            let z = vc.query_advice(p[2], Rotation(ADVICE_OFFSET));

            let x3 = vc.query_advice(s[0], Rotation(ADVICE_OFFSET));
            let y3 = vc.query_advice(s[1], Rotation(ADVICE_OFFSET));
            let z3 = vc.query_advice(s[2], Rotation(ADVICE_OFFSET));

            let GrumpkinPoint {
                x: res_x3,
                y: res_y3,
                z: res_z3,
            } = curve_operations::point_double(
                GrumpkinPoint::new(x, y, z),
                Expression::Constant(*GRUMPKIN_3B),
            );

            Constraints::with_selector(selector, vec![res_x3 - x3, res_y3 - y3, res_z3 - z3])
        });

        Self { p, s, selector }
    }

    fn apply_in_new_region(
        &self,
        layouter: &mut impl Layouter<Fr>,
        input: Self::Input,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || GATE_NAME,
            |mut region| {
                self.selector
                    .enable(&mut region, SELECTOR_OFFSET as usize)?;

                for (i, cell) in input.p.iter().enumerate() {
                    cell.copy_advice(
                        || alloc::format!("P[{i}]"),
                        &mut region,
                        self.p[i],
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
        pool: &mut ColumnPool<Advice, ConfigPhase>,
        cs: &mut ConstraintSystem<Fr>,
    ) -> Self::Advices {
        pool.ensure_capacity(cs, 6);

        (
            [pool.get(0), pool.get(1), pool.get(2)], // p
            [pool.get(3), pool.get(4), pool.get(5)], // s
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

    use super::*;
    use crate::{gates::test_utils::OneGateCircuit, rng};

    fn input(p: G1, s: G1) -> PointDoubleGateInput<Fr> {
        PointDoubleGateInput {
            p: [p.x, p.y, p.z],
            s: [s.x, s.y, s.z],
        }
    }

    fn verify(input: PointDoubleGateInput<Fr>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = OneGateCircuit::<PointDoubleGate, _>::new(input);
        MockProver::run(3, &circuit, vec![])
            .expect("Mock prover should run")
            .verify()
    }

    #[test]
    fn gate_creation() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let p = [cs.advice_column(), cs.advice_column(), cs.advice_column()];
        let s = [cs.advice_column(), cs.advice_column(), cs.advice_column()];

        PointDoubleGate::create_gate(&mut cs, (p, s));
    }

    #[test]
    #[should_panic = "Advice columns must be unique"]
    fn unique_columns() {
        let mut cs = ConstraintSystem::<Fr>::default();
        let col = cs.advice_column();
        let p = [col, cs.advice_column(), cs.advice_column()];
        let s = [cs.advice_column(), col, cs.advice_column()];

        PointDoubleGate::create_gate(&mut cs, (p, s));
    }

    #[test]
    fn doubling_point_at_infinity() {
        let zero = G1 {
            x: Fr::ZERO,
            y: Fr::ONE,
            z: Fr::ZERO,
        };

        let s = zero + zero;

        assert!(verify(input(zero, s)).is_ok());
    }

    #[test]
    fn doubling_random_point() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let s = p + p;

        assert!(verify(input(p, s)).is_ok());
    }

    #[test]
    fn incorrect_inputs() {
        let rng = rng();

        let p = G1::random(rng.clone());
        let s = G1::random(rng.clone());

        verify(input(p, s)).expect_err("Verification should fail");
    }
}
