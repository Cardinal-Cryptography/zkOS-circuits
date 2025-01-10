use std::{
    marker::PhantomData,
    prelude::rust_2015::Vec,
    string::{String, ToString},
    vec,
};

use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    dev::MockProver,
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};

use crate::{column_pool::ColumnPool, embed::Embed, gates::Gate, F};

/// The minimal circuit that uses a single gate. It represents a single application of the gate to
/// the input.
///
/// # Configuration phase
///
/// The constraint system will register exactly one gate (after creating required columns).
///
/// # Synthesis phase
///
/// The circuit will perform two steps:
/// 1. Embed the input into the circuit.
/// 2. Apply the gate to the embedded input.
pub struct OneGateCircuit<Gate, Input> {
    input: Input,
    _marker: PhantomData<Gate>,
}

impl<Gate, Input> OneGateCircuit<Gate, Input> {
    /// Create new circuit instance for a single gate application to `input`.
    pub fn new(input: Input) -> Self {
        Self {
            input,
            _marker: PhantomData,
        }
    }
}

impl<G: Gate<F> + Clone, Input: Embed<F, Embedded = <G as Gate<F>>::Input> + Default> Circuit<F>
    for OneGateCircuit<G, Input>
{
    type Config = (ColumnPool<Advice>, G);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            input: Input::default(),
            _marker: PhantomData,
        }
    }

    /// Our only goal is to register gate `G`. Firstly, we organize sufficient advice area and then
    /// we create the gate instance.
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let mut advice_pool = ColumnPool::<Advice>::new();
        let advice = G::organize_advice_columns(&mut advice_pool, meta);
        (advice_pool, G::create_gate(meta, advice))
    }

    /// Embed the input and apply the gate.
    fn synthesize(
        &self,
        (advice_pool, gate): (ColumnPool<Advice>, G),
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let embedded_input = self.input.embed(&mut layouter, &advice_pool, "input")?;
        gate.apply_in_new_region(&mut layouter, embedded_input)
    }
}

pub fn verify<G: Gate<F> + Clone, Input: Embed<F, Embedded = <G as Gate<F>>::Input> + Default>(
    input: Input,
) -> Result<(), Vec<String>> {
    let circuit = OneGateCircuit::<G, Input>::new(input);
    MockProver::run(4, &circuit, vec![])
        .expect("Mock prover should run")
        .verify()
        .map_err(|v| v.into_iter().map(|e| e.to_string()).collect())
}
