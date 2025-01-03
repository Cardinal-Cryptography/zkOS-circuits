use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};

use crate::{column_pool::ColumnPool, embed::Embed, gates::Gate, Field};

pub struct OneGateCircuit<Gate, Input> {
    input: Input,
    _marker: PhantomData<Gate>,
}

impl<Gate, Input> OneGateCircuit<Gate, Input> {
    pub fn new(input: Input) -> Self {
        Self {
            input,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, G: Gate<F> + Clone, Input: Embed<F, Embedded = <G as Gate<F>>::Input> + Default>
    Circuit<F> for OneGateCircuit<G, Input>
{
    type Config = (ColumnPool<Advice>, G);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            input: Input::default(),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let mut advice_pool = ColumnPool::<Advice>::new();
        let advice = G::organize_advices(&mut advice_pool, meta);
        (advice_pool, G::create_gate(meta, advice))
    }

    fn synthesize(
        &self,
        (advice_pool, gate): (ColumnPool<Advice>, G),
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let embedded_input = self.input.embed(&mut layouter, &advice_pool, "input")?;
        gate.apply_in_new_region(&mut layouter, embedded_input)
    }
}
