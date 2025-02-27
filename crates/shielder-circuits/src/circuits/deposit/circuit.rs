use alloc::collections::BTreeMap;

use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};
use strum::EnumCount;

use crate::{
    circuits::deposit::{chip::DepositChip, knowledge::DepositProverKnowledge},
    column_pool::{ColumnPool, PreSynthesisPhase},
    config_builder::ConfigsBuilder,
    deposit::{DepositFullInstance, DepositInstance, DepositInstance::Commitment},
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::hash,
    synthesizer::create_synthesizer,
    AssignedCell, Fr, Value,
};

#[derive(Clone, Debug, Default)]
pub struct DepositCircuit(pub DepositProverKnowledge<Value>);

impl Circuit<Fr> for DepositCircuit {
    type Config = (DepositChip, ColumnPool<Advice, PreSynthesisPhase>);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let public_inputs = InstanceWrapper::<DepositInstance>::new(meta);

        let configs_builder = ConfigsBuilder::new(meta)
            .with_poseidon()
            .with_merkle()
            .with_range_check()
            .with_note();

        (
            DepositChip {
                public_inputs,
                poseidon: configs_builder.poseidon_chip(),
                merkle: configs_builder.merkle_chip(),
                range_check: configs_builder.range_check_chip(),
                note: configs_builder.note_chip(),
            },
            configs_builder.finish(),
        )
    }

    fn synthesize(
        &self,
        (main_chip, column_pool): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let pool = column_pool.start_synthesis();
        let mut synthesizer = create_synthesizer(&mut layouter, &pool);
        let knowledge = self.0.embed(&mut synthesizer, "DepositProverKnowledge")?;

        let mut instance = BTreeMap::<DepositFullInstance, AssignedCell>::default();

        main_chip.check_old_note(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_old_nullifier(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_new_note(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_id_hiding(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_mac(&mut synthesizer, &knowledge, &mut instance)?;

        use crate::synthesizer::Synthesizer;
        let zero = synthesizer.assign_constant("zero", Fr::zero())?;
        assert_eq!(instance.len(), DepositFullInstance::COUNT);
        let inner_hash = hash(
            &mut synthesizer,
            main_chip.poseidon.clone(),
            [
                instance[&DepositFullInstance::MacSalt].clone(),
                instance[&DepositFullInstance::MacCommitment].clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
            ],
        )?;

        let commitment = hash(
            &mut synthesizer,
            main_chip.poseidon.clone(),
            [
                instance[&DepositFullInstance::IdHiding].clone(),
                instance[&DepositFullInstance::MerkleRoot].clone(),
                instance[&DepositFullInstance::HashedOldNullifier].clone(),
                instance[&DepositFullInstance::HashedNewNote].clone(),
                instance[&DepositFullInstance::DepositValue].clone(),
                instance[&DepositFullInstance::TokenAddress].clone(),
                inner_hash,
            ],
        )?;

        main_chip
            .public_inputs
            .constrain_cells(&mut synthesizer, [(commitment, Commitment)])
    }
}
