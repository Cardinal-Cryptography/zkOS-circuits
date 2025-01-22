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
    curve_operations,
    gates::{
        point_double::PointDoubleGate,
        points_add::{PointsAddGate, PointsAddGateInput},
        Gate,
    },
    instance_wrapper::InstanceWrapper,
    todo::Todo,
    AssignedCell, F,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct PointsAddChipInput<T> {
    pub p: [T; 3],
    pub q: [T; 3],
}

#[derive(Copy, Clone, Debug)]
pub struct PointsAddChipOutput<T> {
    pub s: [T; 3],
}

/// Chip that adds two points on a Grumpkin EC.
///
/// P + Q = S
#[derive(Clone, Debug)]
pub struct PointsAddChip {
    pub advice_pool: ColumnPool<Advice>,
    pub gate: PointsAddGate,
}

impl PointsAddChip {
    pub fn new(gate: PointsAddGate, advice_pool: ColumnPool<Advice>) -> Self {
        Self { gate, advice_pool }
    }

    pub fn point_add(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &PointsAddChipInput<AssignedCell>,
    ) -> Result<PointsAddChipOutput<AssignedCell>, Error> {
        let b3 = Value::known(G1::b() + G1::b() + G1::b());
        let s_value = curve_operations::points_add(
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

        let gate_input = PointsAddGateInput {
            p: input.p.clone(),
            q: input.q.clone(),
            s: s.clone(),
        };

        self.gate.apply_in_new_region(layouter, gate_input)?;

        Ok(PointsAddChipOutput { s })
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

    use super::{PointsAddChip, PointsAddChipInput};
    use crate::{column_pool::ColumnPool, config_builder::ConfigsBuilder, embed::Embed};

    #[derive(Clone, Debug, Default)]
    struct PointAddCircuit(PointsAddChipInput<Fr>);

    impl Circuit<Fr> for PointAddCircuit {
        type Config = (ColumnPool<Advice>, PointsAddChip, Column<Instance>);

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
