use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};

use crate::{column_pool::ColumnPool, embed::Embed, gates::Gate, Field};

pub struct OneGateCircuit<const ADVICE_COUNT: usize, Gate, Input> {
    input: Value<Input>,
    _marker: PhantomData<Gate>,
}

impl<const ADVICE_COUNT: usize, F: Field, G: Gate<F>, Input: Embed<F>> Circuit<F>
    for OneGateCircuit<ADVICE_COUNT, G, Input>
{
    type Config = ColumnPool<Advice>;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            input: Value::unknown(),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let mut advice_pool = ColumnPool::<Advice>::new();
        advice_pool.ensure_capacity(meta, ADVICE_COUNT);
        let advice = G::organize_advices(&mut advice_pool, meta);
        G::create_gate(meta, advice);
        advice_pool
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        todo!()
    }
}
