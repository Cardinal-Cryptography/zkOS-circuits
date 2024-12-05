use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};
use DepositInstance::DepositValue;

use crate::{
    chips::{
        id_hiding::IdHidingChip,
        note::{Note, NoteChip},
        range_check::RangeCheckChip,
        sum::SumChip,
    },
    circuits::{
        deposit::knowledge::{DepositProverKnowledge, IntermediateValues},
        merkle::{MerkleChip, MerkleProverKnowledge},
        FieldExt,
    },
    column_pool::ColumnPool,
    deposit::{
        DepositConstraints::{self, *},
        DepositInstance::{self, HashedNewNote, HashedOldNullifier, *},
    },
    instance_wrapper::InstanceWrapper,
    poseidon::circuit::{hash, PoseidonChip},
    todo::Todo,
    version::NOTE_VERSION,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct DepositChip<F: FieldExt, const CHUNK_SIZE: usize> {
    pub advice_pool: ColumnPool<Advice>,
    pub public_inputs: InstanceWrapper<DepositInstance>,
    pub poseidon: PoseidonChip<F>,
    pub range_check: RangeCheckChip<CHUNK_SIZE>,
    pub merkle: MerkleChip<F>,
    pub sum: SumChip,
}

impl<F: FieldExt, const CHUNK_SIZE: usize> DepositChip<F, CHUNK_SIZE> {
    pub fn check_old_note(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &DepositProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        todo: &mut Todo<DepositConstraints>,
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
        knowledge: &DepositProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        todo: &mut Todo<DepositConstraints>,
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
        knowledge: &DepositProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        todo: &mut Todo<DepositConstraints>,
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
        knowledge: &DepositProverKnowledge<AssignedCell<F>, CHUNK_SIZE>,
        intermediate_values: &IntermediateValues<AssignedCell<F>>,
        todo: &mut Todo<DepositConstraints>,
    ) -> Result<(), Error> {
        self.public_inputs
            .constrain_cells(layouter, [(knowledge.deposit_value.clone(), DepositValue)])?;
        todo.check_off(DepositValueInstanceIsConstrainedToAdvice)?;

        self.sum.constrain_sum(
            layouter,
            knowledge.account_old_balance.clone(),
            knowledge.deposit_value.clone(),
            intermediate_values.account_new_balance.clone(),
        )?;
        todo.check_off(DepositValueInstanceIsIncludedInTheNewNote)?;

        let new_note = NoteChip::new(self.poseidon.clone(), self.advice_pool.clone()).note(
            layouter,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_new.clone(),
                trapdoor: knowledge.trapdoor_new.clone(),
                account_balance: intermediate_values.account_new_balance.clone(),
            },
        )?;
        todo.check_off(HashedNewNoteIsCorrect)?;

        self.public_inputs
            .constrain_cells(layouter, [(new_note, HashedNewNote)])?;
        todo.check_off(HashedNewNoteInstanceIsConstrainedToAdvice)
    }
}
