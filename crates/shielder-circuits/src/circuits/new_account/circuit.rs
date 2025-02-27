use alloc::collections::BTreeMap;

use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter},
    plonk::{Advice, Circuit, ConstraintSystem, Error},
};
use strum::EnumCount;

use crate::{
    circuits::new_account::{chip::NewAccountChip, knowledge::NewAccountProverKnowledge},
    column_pool::{ColumnPool, PreSynthesisPhase},
    config_builder::ConfigsBuilder,
    embed::Embed,
    instance_wrapper::InstanceWrapper,
    new_account::{NewAccountFullInstance, NewAccountInstance, NewAccountInstance::Commitment},
    poseidon::circuit::hash,
    synthesizer::create_synthesizer,
    AssignedCell, Fr, Value,
};

#[derive(Clone, Debug, Default)]
pub struct NewAccountCircuit(pub NewAccountProverKnowledge<Value>);

impl Circuit<Fr> for NewAccountCircuit {
    type Config = (NewAccountChip, ColumnPool<Advice, PreSynthesisPhase>);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let public_inputs = InstanceWrapper::<NewAccountInstance>::new(meta);
        let configs_builder = ConfigsBuilder::new(meta)
            .with_poseidon()
            .with_note()
            .with_is_point_on_curve_affine()
            .with_to_projective_chip()
            .with_to_affine_chip()
            .with_el_gamal_encryption_chip();

        (
            NewAccountChip {
                public_inputs,
                poseidon: configs_builder.poseidon_chip(),
                note: configs_builder.note_chip(),
                is_point_on_curve: configs_builder.is_point_on_curve_affine_gate(),
                el_gamal_encryption: configs_builder.el_gamal_encryption_chip(),
                to_projective: configs_builder.to_projective_chip(),
                to_affine: configs_builder.to_affine_chip(),
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
        let knowledge = self
            .0
            .embed(&mut synthesizer, "NewAccountProverKnowledge")?;

        let mut instance = BTreeMap::<NewAccountFullInstance, AssignedCell>::default();

        main_chip.check_note(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.constrain_hashed_id(&mut synthesizer, &knowledge, &mut instance)?;
        main_chip.constrain_sym_key_encryption(&mut synthesizer, &knowledge, &mut instance)?;

        assert_eq!(instance.len(), NewAccountFullInstance::COUNT);

        use crate::synthesizer::Synthesizer;
        let zero = synthesizer.assign_constant("zero", Fr::zero())?;
        let inner_hash = hash(
            &mut synthesizer,
            main_chip.poseidon.clone(),
            [
                instance[&NewAccountFullInstance::SymKeyEncryptionCiphertext1X].clone(),
                instance[&NewAccountFullInstance::SymKeyEncryptionCiphertext1Y].clone(),
                instance[&NewAccountFullInstance::SymKeyEncryptionCiphertext2X].clone(),
                instance[&NewAccountFullInstance::SymKeyEncryptionCiphertext2Y].clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
            ],
        )?;

        let commitment = hash(
            &mut synthesizer,
            main_chip.poseidon.clone(),
            [
                instance[&NewAccountFullInstance::HashedNote].clone(),
                instance[&NewAccountFullInstance::HashedId].clone(),
                instance[&NewAccountFullInstance::InitialDeposit].clone(),
                instance[&NewAccountFullInstance::TokenAddress].clone(),
                instance[&NewAccountFullInstance::AnonymityRevokerPublicKeyX].clone(),
                instance[&NewAccountFullInstance::AnonymityRevokerPublicKeyY].clone(),
                inner_hash,
            ],
        )?;

        main_chip
            .public_inputs
            .constrain_cells(&mut synthesizer, [(commitment, Commitment)])
    }
}
