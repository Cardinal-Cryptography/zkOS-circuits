use halo2_proofs::plonk::Error;
use DepositInstance::DepositValue;

use crate::{
    chips::{
        id_hiding::IdHidingChip,
        note::{Note, NoteChip},
        range_check::RangeCheckChip,
        sum::SumChip,
    },
    circuits::{
        deposit::knowledge::DepositProverKnowledge,
        merkle::{MerkleChip, MerkleProverKnowledge},
    },
    deposit::{
        DepositConstraints::{self, *},
        DepositInstance::{self, HashedNewNote, HashedOldNullifier, *},
    },
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    todo::Todo,
    version::NOTE_VERSION,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct DepositChip {
    pub public_inputs: InstanceWrapper<DepositInstance>,
    pub poseidon: PoseidonChip,
    pub range_check: RangeCheckChip,
    pub sum_chip: SumChip,
    pub merkle: MerkleChip,
    pub note: NoteChip,
}

impl DepositChip {
    pub fn check_old_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
        todo: &mut Todo<DepositConstraints>,
    ) -> Result<(), Error> {
        let old_note = self.note.note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_old.clone(),
                trapdoor: knowledge.trapdoor_old.clone(),
                account_balance: knowledge.account_old_balance.clone(),
            },
        )?;
        todo.check_off(OldNullifierIsIncludedInTheOldNote)?;

        self.merkle.synthesize(
            synthesizer,
            &MerkleProverKnowledge::new(old_note, &knowledge.path),
            todo,
        )
    }

    pub fn check_old_nullifier(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
        todo: &mut Todo<DepositConstraints>,
    ) -> Result<(), Error> {
        let hashed_old_nullifier = hash(
            synthesizer,
            self.poseidon.clone(),
            [knowledge.nullifier_old.clone()],
        )?;
        todo.check_off(HashedOldNullifierIsCorrect)?;

        self.public_inputs
            .constrain_cells(synthesizer, [(hashed_old_nullifier, HashedOldNullifier)])?;
        todo.check_off(HashedOldNullifierInstanceIsConstrainedToAdvice)
    }

    pub fn check_id_hiding(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
        todo: &mut Todo<DepositConstraints>,
    ) -> Result<(), Error> {
        let id_hiding = IdHidingChip::new(self.poseidon.clone(), self.range_check.clone())
            .id_hiding(synthesizer, knowledge.id.clone(), knowledge.nonce.clone())?;

        todo.check_off(IdHidingIsCorrect)?;

        self.public_inputs
            .constrain_cells(synthesizer, [(id_hiding, IdHiding)])?;

        todo.check_off(IdHidingInstanceIsConstrainedToAdvice)
    }

    pub fn check_new_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
        todo: &mut Todo<DepositConstraints>,
    ) -> Result<(), Error> {
        self.public_inputs.constrain_cells(
            synthesizer,
            [(knowledge.deposit_value.clone(), DepositValue)],
        )?;
        todo.check_off(DepositValueInstanceIsConstrainedToAdvice)?;

        // TODO: move to another chip or `IntermediateValues`.
        let account_balance_new = synthesizer.assign_value(
            "balance new",
            knowledge.account_old_balance.value() + knowledge.deposit_value.value(),
        )?;
        self.sum_chip.constrain_sum(
            synthesizer,
            knowledge.account_old_balance.clone(),
            knowledge.deposit_value.clone(),
            account_balance_new.clone(),
        )?;
        todo.check_off(DepositValueInstanceIsIncludedInTheNewNote)?;

        let new_note = self.note.note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_new.clone(),
                trapdoor: knowledge.trapdoor_new.clone(),
                account_balance: account_balance_new,
            },
        )?;
        todo.check_off(HashedNewNoteIsCorrect)?;

        self.public_inputs
            .constrain_cells(synthesizer, [(new_note, HashedNewNote)])?;
        todo.check_off(HashedNewNoteInstanceIsConstrainedToAdvice)
    }
}
