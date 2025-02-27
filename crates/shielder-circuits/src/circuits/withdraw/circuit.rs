use alloc::collections::BTreeMap;

use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};
use strum::EnumCount;

use crate::{
    circuits::withdraw::chip::WithdrawChip,
    column_pool::{ColumnPool, PreSynthesisPhase},
    config_builder::ConfigsBuilder,
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::hash,
    synthesizer::create_synthesizer,
    withdraw::{WithdrawFullInstance, WithdrawInstance, WithdrawProverKnowledge},
    AssignedCell, Fr, Value,
};

#[derive(Clone, Debug, Default)]
pub struct WithdrawCircuit(pub WithdrawProverKnowledge<Value>);

impl Circuit<Fr> for WithdrawCircuit {
    type Config = (WithdrawChip, ColumnPool<Advice, PreSynthesisPhase>);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Default::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let public_inputs = InstanceWrapper::<WithdrawInstance>::new(meta);

        let configs_builder = ConfigsBuilder::new(meta)
            .with_merkle()
            .with_range_check()
            .with_note();

        (
            WithdrawChip {
                public_inputs,
                poseidon: configs_builder.poseidon_chip(),
                merkle: configs_builder.merkle_chip(),
                range_check: configs_builder.range_check_chip(),
                sum_chip: configs_builder.sum_chip(),
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
        let knowledge = self.0.embed(&mut synthesizer, "WithdrawProverKnowledge")?;

        let mut instance = BTreeMap::<WithdrawFullInstance, AssignedCell>::default();

        main_chip.check_old_note(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_old_nullifier(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_new_note(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_commitment(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_id_hiding(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.check_mac(&mut synthesizer, &knowledge, &mut instance)?;

        use crate::synthesizer::Synthesizer;
        let zero = synthesizer.assign_constant("zero", Fr::zero())?;
        assert_eq!(instance.len(), WithdrawFullInstance::COUNT);
        let inner_hash = hash(
            &mut synthesizer,
            main_chip.poseidon.clone(),
            [
                instance[&WithdrawFullInstance::Commitment].clone(),
                instance[&WithdrawFullInstance::MacSalt].clone(),
                instance[&WithdrawFullInstance::MacCommitment].clone(),
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
                instance[&WithdrawFullInstance::IdHiding].clone(),
                instance[&WithdrawFullInstance::MerkleRoot].clone(),
                instance[&WithdrawFullInstance::HashedOldNullifier].clone(),
                instance[&WithdrawFullInstance::HashedNewNote].clone(),
                instance[&WithdrawFullInstance::WithdrawalValue].clone(),
                instance[&WithdrawFullInstance::TokenAddress].clone(),
                inner_hash,
            ],
        )?;

        main_chip.public_inputs.constrain_cells(
            &mut synthesizer,
            [(commitment, WithdrawInstance::Commitment)],
        )
    }
}
