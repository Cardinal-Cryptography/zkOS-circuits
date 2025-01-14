use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

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
    column_pool::ColumnPool,
    consts::RANGE_PROOF_NUM_WORDS,
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::{hash, PoseidonChip},
    todo::Todo,
    version::NOTE_VERSION,
    withdraw::{
        WithdrawConstraints::{self, *},
        WithdrawInstance::{self, *},
    },
    AssignedCell, F,
};

#[derive(Clone, Debug)]
pub struct WithdrawChip {
    pub advice_pool: ColumnPool<Advice>,
    pub public_inputs: InstanceWrapper<WithdrawInstance>,
    pub poseidon: PoseidonChip,
    pub merkle: MerkleChip,
    pub range_check: RangeCheckChip,
    pub sum_chip: SumChip,
}

impl WithdrawChip {
    pub fn check_old_note(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let balances = balances_from_native_balance(
            knowledge.account_old_balance.clone(),
            layouter,
            &self.advice_pool,
        )?;

        let old_note = NoteChip::new(self.poseidon.clone(), self.advice_pool.clone()).note(
            layouter,
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
            layouter,
            &MerkleProverKnowledge::new(old_note, &knowledge.path),
            todo,
        )
    }

    pub fn check_old_nullifier(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let hashed_old_nullifier = hash(
            &mut layouter.namespace(|| "Old nullifier Hash"),
            self.poseidon.clone(),
            [knowledge.nullifier_old.clone()],
        )?;
        todo.check_off(HashedOldNullifierIsCorrect)?;

        self.public_inputs
            .constrain_cells(layouter, [(hashed_old_nullifier, HashedOldNullifier)])?;
        todo.check_off(HashedOldNullifierInstanceIsConstrainedToAdvice)
    }

    pub fn check_id_hiding(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
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
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        intermediate_values: &IntermediateValues<AssignedCell>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        let new_balance = intermediate_values.new_account_balance.clone();

        self.range_check.constrain_value::<RANGE_PROOF_NUM_WORDS>(
            &mut layouter.namespace(|| "Range Check"),
            new_balance.clone(),
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

        let balances = balances_from_native_balance(new_balance, layouter, &self.advice_pool)?;

        let new_note = NoteChip::new(self.poseidon.clone(), self.advice_pool.clone()).note(
            layouter,
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
            .constrain_cells(layouter, [(new_note, HashedNewNote)])?;
        todo.check_off(HashedNewNoteInstanceIsConstrainedToAdvice)
    }

    pub fn check_commitment(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &WithdrawProverKnowledge<AssignedCell>,
        todo: &mut Todo<WithdrawConstraints>,
    ) -> Result<(), Error> {
        self.public_inputs
            .constrain_cells(layouter, [(knowledge.commitment.clone(), Commitment)])?;
        todo.check_off(CommitmentInstanceIsConstrainedToAdvice)
    }
}
