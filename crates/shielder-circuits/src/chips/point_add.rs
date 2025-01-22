use alloc::{vec, vec::Vec};
use core::{array, borrow::Borrow};

use halo2_proofs::{
    arithmetic::CurveExt,
    circuit::{Layouter, Value},
    halo2curves::{bn256::Fr, grumpkin::G1},
    plonk::{Advice, Error, Expression},
};
use strum::IntoEnumIterator;

use crate::{
    column_pool::ColumnPool,
    gates::{
        point_add::{add, PointAddGate, PointAddGateInput},
        point_double::PointDoubleGate,
        Gate,
    },
    grumpkin::curve_operations::CurveOperations,
    instance_wrapper::InstanceWrapper,
    todo::Todo,
    AssignedCell, F,
};

pub mod off_circuit {
    use core::{
        array,
        ops::{Add, Mul},
    };

    use halo2_proofs::{
        arithmetic::CurveExt,
        circuit::Value,
        halo2curves::{bn256::Fr, grumpkin::G1},
    };

    use super::{PointAddChipInput, PointAddChipOutput};
    use crate::AssignedCell;

    pub fn add(p: [Value<Fr>; 3], q: [Value<Fr>; 3]) -> [Value<Fr>; 3] {
        let [x1, y1, z1] = p;
        let [x2, y2, z2] = q;

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
        let t2 = t2 * Value::known(b3);
        let z3 = t1.clone() + t2.clone();
        let t1 = t1 - t2;
        let y3 = y3 * Value::known(b3);
        let x3 = t4.clone() * y3.clone();
        let t2 = t3.clone() * t1.clone();
        let x3 = t2 - x3;
        let y3 = y3 * t0.clone();
        let t1 = t1 * z3.clone();
        let y3 = t1 + y3;
        let t0 = t0 * t3;
        let z3 = z3 * t4;
        let z3 = z3 + t0;

        [x3, y3, z3]
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PointAddChipInput<T> {
    pub p: [T; 3],
    pub q: [T; 3],
}

#[derive(Copy, Clone, Debug)]
pub struct PointAddChipOutput<T> {
    pub s: [T; 3],
}

/// Chip that adds two points on a Grumpkin EC.
///
/// P + Q = S
#[derive(Clone, Debug)]
pub struct PointAddChip {
    pub advice_pool: ColumnPool<Advice>,
    pub gate: PointAddGate,
}

impl PointAddChip {
    pub fn new(gate: PointAddGate, advice_pool: ColumnPool<Advice>) -> Self {
        Self { gate, advice_pool }
    }

    pub fn point_add(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &PointAddChipInput<AssignedCell>,
    ) -> Result<PointAddChipOutput<AssignedCell>, Error> {
        let b3 = Value::known(G1::b() + G1::b() + G1::b());
        let s_value = add(
            [
                input.p[0].value().copied(),
                input.p[1].value().copied(),
                input.p[2].value().copied(),
            ],
            [
                input.q[0].value().copied(),
                input.q[1].value().copied(),
                input.q[2].value().copied(),
            ],
            b3,
        );

        let s: Vec<AssignedCell> = s_value
            .into_iter()
            .map(|value| {
                layouter
                    .assign_region(
                        || "s",
                        |mut region| {
                            region.assign_advice(|| "s", self.advice_pool.get_any(), 0, || value)
                        },
                    )
                    .expect("can assign advice from a value")
            })
            .collect();

        let s: [AssignedCell; 3] = s.try_into().unwrap_or_else(|v: Vec<AssignedCell>| {
            panic!("Expected a Vec of length {} but it was {}", 3, v.len())
        });

        let gate_input = PointAddGateInput {
            p: input.p.clone(),
            q: input.q.clone(),
            s: s.clone(),
        };

        self.gate.apply_in_new_region(layouter, gate_input)?;

        Ok(PointAddChipOutput { s })
    }
}

#[cfg(test)]
mod tests {

    use std::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    use halo2_proofs::{
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use super::{PointAddChip, PointAddChipInput};
    use crate::{column_pool::ColumnPool, config_builder::ConfigsBuilder, embed::Embed};

    #[derive(Clone, Debug, Default)]
    struct PointAddCircuit(PointAddChipInput<Fr>);

    impl Circuit<Fr> for PointAddCircuit {
        type Config = (ColumnPool<Advice>, PointAddChip, Column<Instance>);

        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            // public input column
            let instance = meta.instance_column();
            meta.enable_equality(instance);

            // TODO: register point add chip
            let configs_builder = ConfigsBuilder::new(meta);

            todo!()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            todo!()
        }
    }
}
