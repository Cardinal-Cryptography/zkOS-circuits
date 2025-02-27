use alloc::collections::BTreeMap;

use halo2_proofs::plonk::Error;

use crate::{
    chips::{
        id_hiding::IdHidingChip,
        mac::{MacChip, MacInput},
        note::{Note, NoteChip},
        range_check::RangeCheckChip,
        sum::SumChip,
        sym_key::SymKeyChip,
    },
    circuits::{
        merkle::{MerkleChip, MerkleProverKnowledge},
        withdraw::knowledge::WithdrawProverKnowledge,
    },
    consts::RANGE_PROOF_NUM_WORDS,
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NOTE_VERSION,
    withdraw::{
        WithdrawFullInstance,
        WithdrawFullInstance::{HashedOldNullifier, MerkleRoot},
        WithdrawInstance::{self},
    },
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct WithdrawChip {
    pub public_inputs: InstanceWrapper<WithdrawInstance>,
    pub poseidon: PoseidonChip,
    pub merkle: MerkleChip,
    pub range_check: RangeCheckChip,
    pub sum_chip: SumChip,
    pub note: NoteChip,
}

impl WithdrawChip {
    pub fn check_old_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        instance: &mut BTreeMap<WithdrawFullInstance, AssignedCell>,
    ) -> Result<(), Error> {
        let old_note = self.note.note_hash(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_old.clone(),
                trapdoor: knowledge.trapdoor_old.clone(),
                account_balance: knowledge.account_old_balance.clone(),
                token_address: knowledge.token_address.clone(),
            },
        )?;

        let root = self.merkle.synthesize(
            synthesizer,
            &MerkleProverKnowledge::new(old_note, &knowledge.path),
        )?;
        assert!(instance.insert(MerkleRoot, root).is_none());

        Ok(())
    }

    pub fn check_old_nullifier(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        instance: &mut BTreeMap<WithdrawFullInstance, AssignedCell>,
    ) -> Result<(), Error> {
        let hashed_old_nullifier = hash(
            synthesizer,
            self.poseidon.clone(),
            [knowledge.nullifier_old.clone()],
        )?;

        assert!(instance
            .insert(HashedOldNullifier, hashed_old_nullifier)
            .is_none());
        Ok(())
    }

    pub fn check_id_hiding(
        &self,
        synthesizer: &mut impl Synthesizer,

        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        instance: &mut BTreeMap<WithdrawFullInstance, AssignedCell>,
    ) -> Result<(), Error> {
        let id_hiding = IdHidingChip::new(self.poseidon.clone(), self.range_check.clone())
            .id_hiding(synthesizer, knowledge.id.clone(), knowledge.nonce.clone())?;
        assert!(instance
            .insert(WithdrawFullInstance::IdHiding, id_hiding)
            .is_none());
        Ok(())
    }

    pub fn check_new_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        instance: &mut BTreeMap<WithdrawFullInstance, AssignedCell>,
    ) -> Result<(), Error> {
        let new_balance = self.note.decrease_balance(
            synthesizer,
            knowledge.account_old_balance.clone(),
            knowledge.withdrawal_value.clone(),
        )?;

        self.range_check
            .constrain_value::<RANGE_PROOF_NUM_WORDS>(synthesizer, new_balance.clone())?;

        let new_note = self.note.note_hash(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_new.clone(),
                trapdoor: knowledge.trapdoor_new.clone(),
                account_balance: new_balance,
                token_address: knowledge.token_address.clone(),
            },
        )?;

        assert!(instance
            .insert(WithdrawFullInstance::HashedNewNote, new_note)
            .is_none());
        assert!(instance
            .insert(
                WithdrawFullInstance::TokenAddress,
                knowledge.token_address.clone()
            )
            .is_none());
        assert!(instance
            .insert(
                WithdrawFullInstance::WithdrawalValue,
                knowledge.withdrawal_value.clone()
            )
            .is_none());

        Ok(())
    }

    pub fn check_commitment(
        &self,
        _synthesizer: &mut impl Synthesizer,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        instance: &mut BTreeMap<WithdrawFullInstance, AssignedCell>,
    ) -> Result<(), Error> {
        assert!(instance
            .insert(
                WithdrawFullInstance::Commitment,
                knowledge.commitment.clone()
            )
            .is_none());
        Ok(())
    }

    pub fn check_mac(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        instance: &mut BTreeMap<WithdrawFullInstance, AssignedCell>,
    ) -> Result<(), Error> {
        let sym_key =
            SymKeyChip::new(self.poseidon.clone()).derive(synthesizer, knowledge.id.clone())?;

        let mac = MacChip::new(self.poseidon.clone()).mac(
            synthesizer,
            &MacInput {
                key: sym_key,
                salt: knowledge.mac_salt.clone(),
            },
        )?;

        assert!(instance
            .insert(WithdrawFullInstance::MacCommitment, mac.commitment)
            .is_none());
        assert!(instance
            .insert(WithdrawFullInstance::MacSalt, knowledge.mac_salt.clone())
            .is_none());

        Ok(())
    }
}
