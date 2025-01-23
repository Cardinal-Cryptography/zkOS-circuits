use halo2_proofs::plonk::Error;
use DepositInstance::DepositValue;

use crate::{
    chips::{
        balances_increase::BalancesIncreaseChip,
        id_hiding::IdHidingChip,
        note::{Note, NoteChip},
        range_check::RangeCheckChip,
        token_index::TokenIndexChip,
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
    pub merkle: MerkleChip,
    pub balances_increase: BalancesIncreaseChip,
    pub token_index: TokenIndexChip,
}

impl DepositChip {
    pub fn check_old_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
        todo: &mut Todo<DepositConstraints>,
    ) -> Result<(), Error> {
        let old_note = NoteChip::new(self.poseidon.clone()).note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_old.clone(),
                trapdoor: knowledge.trapdoor_old.clone(),
                balances: knowledge.balances_old.clone(),
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

        let balances_new = self.balances_increase.increase_balances(
            synthesizer,
            &knowledge.balances_old,
            &knowledge.token_indicators,
            &knowledge.deposit_value,
        )?;
        todo.check_off(DepositValueInstanceIsIncludedInTheNewNote)?;

        let new_note = NoteChip::new(self.poseidon.clone()).note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier_new.clone(),
                trapdoor: knowledge.trapdoor_new.clone(),
                balances: balances_new,
            },
        )?;
        todo.check_off(HashedNewNoteIsCorrect)?;

        self.public_inputs
            .constrain_cells(synthesizer, [(new_note, HashedNewNote)])?;
        todo.check_off(HashedNewNoteInstanceIsConstrainedToAdvice)
    }

    pub fn check_token_indicators(
        &self,
        layouter: &mut impl Layouter<Fr>,
        knowledge: &DepositProverKnowledge<AssignedCell>,
        todo: &mut Todo<DepositConstraints>,
    ) -> Result<(), Error> {
        self.token_index
            .constrain_indicators(layouter, &knowledge.token_indicators, todo)
    }
    pub fn check_token_index(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &DepositProverKnowledge<AssignedCell>,
        todo: &mut Todo<DepositConstraints>,
    ) -> Result<(), Error> {
        self.token_index
            .constrain_index(synthesizer, column_pool, &knowledge.token_indicators, todo)
    }
}
