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
    pub fn synthesize(
        &self,
        synthesizer: &mut impl Synthesizer,
        knowledge: &NewAccountProverKnowledge<AssignedCell>,
    ) -> Result<(), Error> {
        let public_inputs = &self.public_inputs;

        public_inputs.constrain_cells(
            synthesizer,
            [(knowledge.initial_deposit.clone(), InitialDeposit)],
        )?;

        let h_id = hash(synthesizer, self.poseidon.clone(), [knowledge.id.clone()])?;

        let note = self.note.note_hash(
            synthesizer,
            &Note {
                version: NOTE_VERSION,
                id: knowledge.id.clone(),
                nullifier: knowledge.nullifier.clone(),
                trapdoor: knowledge.trapdoor.clone(),
                account_balance: knowledge.initial_deposit.clone(),
                token_address: knowledge.token_address.clone(),
            },
        )?;

        public_inputs.constrain_cells(synthesizer, [(note, HashedNote), (h_id, HashedId)])
    }
}
