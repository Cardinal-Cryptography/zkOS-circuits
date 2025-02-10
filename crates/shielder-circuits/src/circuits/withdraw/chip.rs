use halo2_proofs::plonk::ErrorFront;

use crate::{
    chips::{
        id_hiding::IdHidingChip,
        note::{Note, NoteChip},
        range_check::RangeCheckChip,
        sum::SumChip,
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
    withdraw::WithdrawInstance::{self, *},
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
    ) -> Result<(), ErrorFront> {
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

        self.merkle.synthesize(
            synthesizer,
            &MerkleProverKnowledge::new(old_note, &knowledge.path),
        )
    }

    pub fn check_old_nullifier(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        let hashed_old_nullifier = hash(
            synthesizer,
            self.poseidon.clone(),
            [knowledge.nullifier_old.clone()],
        )?;

        self.public_inputs
            .constrain_cells(synthesizer, [(hashed_old_nullifier, HashedOldNullifier)])
    }

    pub fn check_id_hiding(
        &self,
        synthesizer: &mut impl Synthesizer,

        knowledge: &WithdrawProverKnowledge<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        let id_hiding = IdHidingChip::new(self.poseidon.clone(), self.range_check.clone())
            .id_hiding(synthesizer, knowledge.id.clone(), knowledge.nonce.clone())?;
        self.public_inputs
            .constrain_cells(synthesizer, [(id_hiding, IdHiding)])
    }

    pub fn check_new_note(
        &self,
        synthesizer: &mut impl Synthesizer,

        knowledge: &WithdrawProverKnowledge<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        let new_balance = self.note.decrease_balance(
            synthesizer,
            knowledge.account_old_balance.clone(),
            knowledge.withdrawal_value.clone(),
        )?;

        self.range_check
            .constrain_value::<RANGE_PROOF_NUM_WORDS>(synthesizer, new_balance.clone())?;

        self.public_inputs.constrain_cells(
            synthesizer,
            [(knowledge.withdrawal_value.clone(), WithdrawalValue)],
        )?;

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

        self.public_inputs
            .constrain_cells(synthesizer, [(new_note, HashedNewNote)])
    }

    pub fn check_commitment(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
    ) -> Result<(), ErrorFront> {
        self.public_inputs
            .constrain_cells(synthesizer, [(knowledge.commitment.clone(), Commitment)])
    }
}
