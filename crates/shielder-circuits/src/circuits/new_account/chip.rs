use halo2_proofs::plonk::Error;

use crate::{
    chips::note::{Note, NoteChip},
    circuits::new_account::knowledge::NewAccountProverKnowledge,
    instance_wrapper::InstanceWrapper,
    new_account::NewAccountInstance::{self, *},
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NOTE_VERSION,
    AssignedCell,
};

#[derive(Clone, Debug)]
pub struct NewAccountChip {
    pub public_inputs: InstanceWrapper<NewAccountInstance>,
    pub poseidon: PoseidonChip,
    pub note: NoteChip,
}

impl NewAccountChip {
    pub fn check_note(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let note = self.note.note(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier.clone(),
                trapdoor: knowledge.trapdoor.clone(),
                account_balance: knowledge.initial_deposit.clone(),
            },
        )?;

        self.public_inputs.constrain_cells(
            synthesizer,
            [
                (note, HashedNote),
                (knowledge.initial_deposit.clone(), InitialDeposit),
            ],
        )
    }

    pub fn constrain_hashed_id(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let h_id = hash(synthesizer, self.poseidon.clone(), [knowledge.id.clone()])?;
        self.public_inputs
            .constrain_cells(synthesizer, [(h_id, HashedId)])
    }

    pub fn constrain_hashed_id(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {}
}