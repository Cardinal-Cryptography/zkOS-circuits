use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};

use crate::{
    circuits::merkle::knowledge::MerkleProverKnowledge,
    column_pool::{ColumnPool, SynthesisPhase},
    config_builder::ConfigsBuilder,
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    merkle::{chip::MerkleChip, MerkleConstraints, MerkleInstance},
    todo::Todo,
    F,
};

#[derive(Clone, Debug, Default)]
pub struct MerkleCircuit<const TREE_HEIGHT: usize>(
    pub MerkleProverKnowledge<TREE_HEIGHT, Value<F>>,
);

impl<const TREE_HEIGHT: usize> Circuit<F> for MerkleCircuit<TREE_HEIGHT> {
    type Config = (MerkleChip, ColumnPool<Advice, SynthesisPhase>);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let public_inputs = InstanceWrapper::<MerkleInstance>::new(meta);
        let configs_builder = ConfigsBuilder::new(meta).with_merkle(public_inputs);
        (configs_builder.merkle_chip(), configs_builder.finish())
    }

    fn synthesize(
        &self,
        (main_chip, column_pool): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut todo = Todo::<MerkleConstraints>::new();
        let knowledge = self
            .0
            .embed(&mut layouter, &column_pool, "MerkleProverKnowledge")?;
        main_chip.synthesize(&mut layouter, &knowledge, &mut todo)?;
        todo.assert_done()
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::halo2curves::bn256::Fr;

    use crate::{
        circuits::{merkle::knowledge::MerkleProverKnowledge, test_utils::run_full_pipeline},
        consts::merkle_constants::NOTE_TREE_HEIGHT,
    };

    #[test]
    fn positive_pipeline_for_merkle_proof_circuit() {
        run_full_pipeline::<MerkleProverKnowledge<{ NOTE_TREE_HEIGHT }, Fr>>()
    }
}
