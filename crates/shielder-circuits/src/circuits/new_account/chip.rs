use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    chips::note::{balances_from_native_balance, Note, NoteChip},
    circuits::{new_account::knowledge::NewAccountProverKnowledge, FieldExt},
    column_pool::ColumnPool,
    instance_wrapper::InstanceWrapper,
    new_account::{
        NewAccountConstraints::{self, *},
        NewAccountInstance::{self, *},
    },
    poseidon::circuit::{hash, PoseidonChip},
    todo::Todo,
    version::NOTE_VERSION,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct NewAccountChip<F: FieldExt> {
    pub advice_pool: ColumnPool<Advice>,
    pub public_inputs: InstanceWrapper<NewAccountInstance>,
    pub poseidon: PoseidonChip<F>,
}

impl<F: FieldExt> NewAccountChip<F> {
    pub fn synthesize(
        &self,
        layouter: &mut impl Layouter<F>,
        knowledge: &NewAccountProverKnowledge<AssignedCell<F>>,
        todo: &mut Todo<NewAccountConstraints>,
    ) -> Result<(), Error> {
        let public_inputs = &self.public_inputs;

        public_inputs.constrain_cells(
            layouter,
            [(knowledge.initial_deposit.clone(), InitialDeposit)],
        )?;
        todo.check_off(InitialDepositInstanceIsConstrainedToAdvice)?;

        let h_id = hash(layouter, self.poseidon.clone(), [knowledge.id.clone()])?;
        todo.check_off(HashedIdIsCorrect)?;

        let balances = balances_from_native_balance(
            knowledge.initial_deposit.clone(),
            layouter,
            &self.advice_pool,
        )?;

        let note = NoteChip::new(self.poseidon.clone(), self.advice_pool.clone()).note(
            layouter,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier.clone(),
                trapdoor: knowledge.trapdoor.clone(),
                balances,
            },
        )?;
        todo.check_off(IdIsIncludedInTheNote)?;
        todo.check_off(InitialDepositIsIncludedInTheNewNote)?;
        todo.check_off(HashedNoteIsCorrect)?;

        public_inputs.constrain_cells(layouter, [(note, HashedNote), (h_id, HashedId)])?;
        todo.check_off(HashedNoteInstanceIsConstrainedToAdvice)?;
        todo.check_off(HashedIdInstanceIsConstrainedToAdvice)
    }
}
