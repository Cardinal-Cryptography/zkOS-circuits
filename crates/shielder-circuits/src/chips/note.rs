use core::array;

use halo2_proofs::{arithmetic::Field, plonk::Error};

use crate::{
    consts::POSEIDON_RATE,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NoteVersion,
    AssignedCell, Fr,
};

#[derive(Copy, Clone, Debug)]
pub struct Note<T> {
    pub version: NoteVersion,
    pub id: T,
    pub nullifier: T,
    pub trapdoor: T,
    pub account_balance: T,
}

pub mod off_circuit {
    use halo2_proofs::arithmetic::Field;

    use crate::{chips::note::Note, consts::POSEIDON_RATE, poseidon::off_circuit::hash, Fr};

    pub fn note_hash(note: &Note<Fr>) -> Fr {
        // TODO: move to a separate chip, which will also handle the token address.
        let balance_hash = hash::<POSEIDON_RATE>(&[
            note.account_balance,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
        ]);

        let input = [
            note.version.as_field(),
            note.id,
            note.nullifier,
            note.trapdoor,
            balance_hash,
        ];

        hash(&input)
    }
}

/// Chip that is able to calculate note hash
#[derive(Clone, Debug)]
pub struct NoteChip {
    poseidon: PoseidonChip,
}

impl NoteChip {
    pub fn new(poseidon: PoseidonChip) -> Self {
        Self { poseidon }
    }

    fn assign_note_version(
        &self,
        note: &Note<AssignedCell>,
        synthesizer: &mut impl Synthesizer,
    ) -> Result<AssignedCell, Error> {
        let note_version: Fr = note.version.as_field();
        synthesizer.assign_constant("note_version", note_version)
    }

    /// Calculate the note_hash as follows:
    /// note_hash = Hash(NOTE_VERSION, note.id, note.nullifier, note.trapdoor, hash(note.balance))
    pub fn note(
        &self,
        synthesizer: &mut impl Synthesizer,
        note: &Note<AssignedCell>,
    ) -> Result<AssignedCell, Error> {
        let note_version = self.assign_note_version(note, synthesizer)?;

        let h_balance = self.balance_hash(synthesizer, note)?;

        let input = [
            note_version,
            note.id.clone(),
            note.nullifier.clone(),
            note.trapdoor.clone(),
            h_balance,
        ];

        hash(synthesizer, self.poseidon.clone(), input)
    }

    // TODO: move to a separate chip, which will also handle the token address.
    fn balance_hash(
        &self,
        synthesizer: &mut impl Synthesizer,
        note: &Note<AssignedCell>,
    ) -> Result<AssignedCell, Error> {
        let zero_cell = synthesizer.assign_constant("Zero", Fr::ZERO)?;

        let mut input: [_; POSEIDON_RATE] = array::from_fn(|_| zero_cell.clone());
        input[0] = note.account_balance.clone();

        hash(synthesizer, self.poseidon.clone(), input)
    }
}
