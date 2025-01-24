use core::array;

use halo2_proofs::{arithmetic::Field, plonk::Error};

use super::shortlist_hash::Shortlist;
use crate::{
    chips::shortlist_hash::chip::ShortlistHashChip,
    consts::NUM_TOKENS,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    version::NoteVersion,
    AssignedCell, Fr,
};

/// Chip that is able to calculate note hash
#[derive(Clone, Debug)]
pub struct NoteChip {
    poseidon: PoseidonChip,
}

#[derive(Copy, Clone, Debug)]
pub struct Note<T> {
    pub version: NoteVersion,
    pub id: T,
    pub nullifier: T,
    pub trapdoor: T,
    pub balances: Shortlist<T, NUM_TOKENS>,
}

pub mod off_circuit {
    use halo2_proofs::arithmetic::Field;

    use crate::{
        chips::{
            note::Note,
            shortlist_hash::{off_circuit::shortlist_hash, Shortlist},
        },
        consts::NUM_TOKENS,
        poseidon::off_circuit::hash,
        Fr,
    };

    pub fn note_hash(note: &Note<Fr>) -> Fr {
        let input = [
            note.version.as_field(),
            note.id,
            note.nullifier,
            note.trapdoor,
            shortlist_hash(&note.balances),
        ];

        hash(&input)
    }

    /// TODO: Remove this temporary helper once NewAccount and Withdraw support balance tuples.
    /// Produces the balance shortlist tuple from a single native balance.
    pub fn balances_from_native_balance(native_balance: Fr) -> Shortlist<Fr, NUM_TOKENS> {
        let mut balances = [Fr::ZERO; NUM_TOKENS];
        balances[0] = native_balance;
        Shortlist::new(balances)
    }
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

        let h_balance = ShortlistHashChip::new(self.poseidon.clone())
            .shortlist_hash(synthesizer, &note.balances)?;

        let input = [
            note_version,
            note.id.clone(),
            note.nullifier.clone(),
            note.trapdoor.clone(),
            h_balance,
        ];

        hash(synthesizer, self.poseidon.clone(), input)
    }
}

/// TODO: Remove this temporary helper once NewAccount and Withdraw support balance tuples.
/// Converts a single native balance to a balance tuple with the remaining balances
/// constrained to 0.
pub fn balances_from_native_balance(
    native_balance: AssignedCell,
    synthesizer: &mut impl Synthesizer,
) -> Result<Shortlist<AssignedCell, NUM_TOKENS>, Error> {
    let zero_cell = synthesizer.assign_constant("Balance placeholder (zero)", Fr::ZERO)?;
    Ok(Shortlist::new(array::from_fn(|i| {
        if i == 0 {
            native_balance.clone()
        } else {
            zero_cell.clone()
        }
    })))
}
