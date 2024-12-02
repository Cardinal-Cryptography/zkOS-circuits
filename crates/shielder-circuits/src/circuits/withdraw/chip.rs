use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    chips::{
        id_hiding::IdHidingChip,
        note::{Note, NoteChip},
        range_check::LookupRangeCheckChip,
        sum::SumChip,
    },
    circuits::{
        merkle::{MerkleChip, MerkleProverKnowledge},
        withdraw::knowledge::{IntermediateValues, WithdrawProverKnowledge},
        FieldExt,
    },
    column_pool::ColumnPool,
    consts::RANGE_PROOF_NUM_WORDS,
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::{padded_hash, PoseidonChip},
    todo::Todo,
    version::NOTE_VERSION,
    withdraw::{
        WithdrawConstraints,
        WithdrawConstraints::*,
        WithdrawInstance::{self, *},
    },
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct WithdrawChip<F: FieldExt, const CHUNK_SIZE: usize> {
    pub advice_pool: ColumnPool<Advice>,
    pub public_inputs: InstanceWrapper<WithdrawInstance>,
    pub poseidon: PoseidonChip<F>,
    pub merkle: MerkleChip<F>,
    pub range_check: LookupRangeCheckChip<CHUNK_SIZE>,
    pub sum_chip: SumChip,
}

impl<F: FieldExt, const CHUNK_SIZE: usize> WithdrawChip<F, CHUNK_SIZE> {
    pub fn check_old_note(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let old_note = NoteChip::new(self.poseidon.clone(), self.advice_pool.clone()).note(
            layouter,
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
            layouter,
            &MerkleProverKnowledge::new(old_note, &knowledge.path),
            todo,
        )
    }

    pub fn check_old_nullifier(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let hashed_old_nullifier = padded_hash(
            &mut layouter.namespace(|| "Old nullifier Hash"),
            self.poseidon.clone(),
            &[&knowledge.nullifier_old],
        )?;
        todo.check_off(HashedOldNullifierIsCorrect)?;

        self.public_inputs
            .constrain_cells(layouter, [(hashed_old_nullifier, HashedOldNullifier)])?;
        todo.check_off(HashedOldNullifierInstanceIsConstrainedToAdvice)
    }

    pub fn check_id_hiding(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let id_hiding = IdHidingChip::new(self.poseidon.clone(), self.range_check.clone())
            .id_hiding(layouter, knowledge.id.clone(), knowledge.nonce.clone())?;
        todo.check_off(IdHidingIsCorrect)?;

        self.public_inputs
            .constrain_cells(layouter, [(id_hiding, IdHiding)])?;
        todo.check_off(IdHidingInstanceIsConstrainedToAdvice)
    }

    pub fn check_new_note(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        intermediate_values: &IntermediateValues<AssignedCell<F>>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let new_balance = intermediate_values.account_new_balance.clone();
        self.range_check.copy_check(
            layouter.namespace(|| "Range Check"),
            new_balance.clone(),
            RANGE_PROOF_NUM_WORDS,
        )?;
        todo.check_off(NewBalanceIsInRange)?;

        self.sum_chip.constrain_sum(
            layouter,
            new_balance.clone(),
            knowledge.withdrawal_value.clone(),
            knowledge.account_old_balance.clone(),
        )?;
        todo.check_off(WithdrawalValueInstanceIsIncludedInTheNewNote)?;

        self.public_inputs.constrain_cells(
            layouter,
            [(knowledge.withdrawal_value.clone(), WithdrawalValue)],
        )?;
        todo.check_off(WithdrawalValueInstanceIsConstrainedToAdvice)?;

        let new_note = NoteChip::new(self.poseidon.clone(), self.advice_pool.clone()).note(
            layouter,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_new.clone(),
                trapdoor: knowledge.trapdoor_new.clone(),
                account_balance: new_balance,
            },
        )?;
        todo.check_off(HashedNewNoteIsCorrect)?;

        self.public_inputs
            .constrain_cells(layouter, [(new_note, HashedNewNote)])?;
        todo.check_off(HashedNewNoteInstanceIsConstrainedToAdvice)
    }

    pub fn check_commitment(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        self.public_inputs
            .constrain_cells(layouter, [(knowledge.commitment.clone(), Commitment)])?;
        todo.check_off(CommitmentInstanceIsConstrainedToAdvice)
    }
}
