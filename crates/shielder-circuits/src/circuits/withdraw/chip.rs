use halo2_proofs::plonk::Error;

use crate::{
    chips::{
        id_hiding::IdHidingChip,
        note::{balances_from_native_balance, Note, NoteChip},
        range_check::RangeCheckChip,
        sum::SumChip,
    },
    circuits::{
        merkle::{MerkleChip, MerkleProverKnowledge},
        withdraw::knowledge::{IntermediateValues, WithdrawProverKnowledge},
    },
    consts::RANGE_PROOF_NUM_WORDS,
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    todo::Todo,
    version::NOTE_VERSION,
    withdraw::{
        WithdrawConstraints::{self, *},
        WithdrawInstance::{self, *},
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
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let balances =
            balances_from_native_balance(knowledge.account_old_balance.clone(), synthesizer)?;

        let old_note = self.note.note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_old.clone(),
                trapdoor: knowledge.trapdoor_old.clone(),
                balances,
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
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        todo: &mut Todo<WithdrawConstraints>,
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

        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        todo: &mut Todo<WithdrawConstraints>,
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

        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        intermediate_values: &IntermediateValues<AssignedCell>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let new_balance = intermediate_values.new_account_balance.clone();

        self.range_check
            .constrain_value::<RANGE_PROOF_NUM_WORDS>(synthesizer, new_balance.clone())?;
        todo.check_off(NewBalanceIsInRange)?;

        self.sum_chip.constrain_sum(
            synthesizer,
            new_balance.clone(),
            knowledge.withdrawal_value.clone(),
            knowledge.account_old_balance.clone(),
        )?;
        todo.check_off(WithdrawalValueInstanceIsIncludedInTheNewNote)?;

        self.public_inputs.constrain_cells(
            synthesizer,
            [(knowledge.withdrawal_value.clone(), WithdrawalValue)],
        )?;
        todo.check_off(WithdrawalValueInstanceIsConstrainedToAdvice)?;

        let balances = balances_from_native_balance(new_balance, synthesizer)?;

        let new_note = self.note.note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_new.clone(),
                trapdoor: knowledge.trapdoor_new.clone(),
                balances,
            },
        )?;
        todo.check_off(HashedNewNoteIsCorrect)?;

        self.public_inputs
            .constrain_cells(synthesizer, [(new_note, HashedNewNote)])?;
        todo.check_off(HashedNewNoteInstanceIsConstrainedToAdvice)
    }

    pub fn check_commitment(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        self.public_inputs
            .constrain_cells(synthesizer, [(knowledge.commitment.clone(), Commitment)])?;
        todo.check_off(CommitmentInstanceIsConstrainedToAdvice)
    }
}
