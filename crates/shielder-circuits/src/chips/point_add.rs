use alloc::{vec, vec::Vec};
use core::{array, borrow::Borrow};

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::{bn256::Fr, grumpkin::G1},
    plonk::{Advice, Error, Expression},
};
use strum::IntoEnumIterator;

use crate::{
    column_pool::ColumnPool,
    gates::{
        point_add::{PointAddGate, PointAddGateInput},
        point_double::PointDoubleGate,
        Gate,
    },
    instance_wrapper::InstanceWrapper,
    todo::Todo,
    AssignedCell, F,
};

pub mod off_circuit {
    use core::{
        array,
        ops::{Add, Mul},
    };

    use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

    use super::{PointAddChipInput, PointAddChipOutput};
    use crate::AssignedCell;

    pub fn add(p: &[Value<Fr>; 3], q: &[Value<Fr>; 3]) -> [Value<Fr>; 3] {
        todo!()
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
        let s_value = off_circuit::add(
            &[
                input.p[0].value().copied(),
                input.p[1].value().copied(),
                input.p[2].value().copied(),
            ],
            &[
                input.q[0].value().copied(),
                input.q[1].value().copied(),
                input.q[2].value().copied(),
            ],
        );

        // let mut s: Vec<AssignedCell> = vec![];
        // // let mut s: [AssignedCell; 3] = [Default::default(), Default::default(), Default::default()];
        // for i in 0..3 {
        //     s.push(layouter.assign_region(
        //         || "s[{i}]",
        //         |mut region| {
        //             region.assign_advice(|| "s[{i}]", self.advice_pool.get_any(), 0, || s_value[i])
        //         },
        //     )?);
        // }

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
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };

    use crate::{
        chips::point_add::off_circuit, column_pool::ColumnPool, config_builder::ConfigsBuilder,
        embed::Embed, F,
    };
}
