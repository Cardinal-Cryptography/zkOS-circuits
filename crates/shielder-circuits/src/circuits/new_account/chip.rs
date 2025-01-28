use halo2_proofs::plonk::Error;

use crate::{
    chips::note::{balances_from_native_balance, Note, NoteChip},
    circuits::new_account::knowledge::NewAccountProverKnowledge,
    instance_wrapper::InstanceWrapper,
    new_account::{
        NewAccountConstraints::{self, *},
        NewAccountInstance::{self, *},
    },
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    todo::Todo,
    version::NOTE_VERSION,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct NewAccountChip {
    pub public_inputs: InstanceWrapper<NewAccountInstance>,
    pub poseidon: PoseidonChip,
    pub note_chip: NoteChip,
}

impl NewAccountChip {
    pub fn synthesize(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
        todo: &mut Todo<NewAccountConstraints>,
    ) -> Result<(), Error> {
        let public_inputs = &self.public_inputs;

        public_inputs.constrain_cells(
            synthesizer,
            [(knowledge.initial_deposit.clone(), InitialDeposit)],
        )?;
        todo.check_off(InitialDepositInstanceIsConstrainedToAdvice)?;

        let h_id = hash(synthesizer, self.poseidon.clone(), [knowledge.id.clone()])?;
        todo.check_off(HashedIdIsCorrect)?;

        let balances =
            balances_from_native_balance(knowledge.initial_deposit.clone(), synthesizer)?;

        let note = self.note_chip.note(
            synthesizer,
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

        public_inputs.constrain_cells(synthesizer, [(note, HashedNote), (h_id, HashedId)])?;
        todo.check_off(HashedNoteInstanceIsConstrainedToAdvice)?;
        todo.check_off(HashedIdInstanceIsConstrainedToAdvice)
    }
}
