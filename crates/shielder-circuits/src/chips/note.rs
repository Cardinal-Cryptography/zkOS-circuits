use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    chips::balances::BalancesChip,
    column_pool::ColumnPool,
    poseidon::circuit::{hash, PoseidonChip},
    version::NoteVersion,
    AssignedCell, FieldExt,
};

/// Chip that is able to calculate note hash
#[derive(Clone, Debug)]
pub struct NoteChip<F: FieldExt> {
    poseidon: PoseidonChip<F>,
    advice_pool: ColumnPool<Advice>,
}

#[derive(Copy, Clone, Debug)]
pub struct Note<T> {
    pub version: NoteVersion,
    pub id: T,
    pub nullifier: T,
    pub trapdoor: T,
    pub account_balance: T,
}

pub mod off_circuit {
    use crate::{chips::note::Note, poseidon::off_circuit::hash, FieldExt};

    pub fn note_hash<F: FieldExt>(note: &Note<F>) -> F {
        let input = [
            note.version.as_field(),
            note.id,
            note.nullifier,
            note.trapdoor,
            hash(&[note.account_balance]),
        ];

        hash(&input)
    }
}

impl<F: FieldExt> NoteChip<F> {
    pub fn new(poseidon: PoseidonChip<F>, advice_pool: ColumnPool<Advice>) -> Self {
        Self {
            poseidon,
            advice_pool,
        }
    }

    fn assign_note_version(
        &self,
        note: &Note<AssignedCell<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<AssignedCell<F>, Error> {
        let note_version: F = note.version.as_field();

        layouter.assign_region(
            || "note_version",
            |mut region| {
                region.assign_advice_from_constant(
                    || "note_version",
                    self.advice_pool.get_any(),
                    0,
                    note_version,
                )
            },
        )
    }

    /// Calculate the note_hash as follows:
    /// note_hash = Hash(NOTE_VERSION, note.id, note.nullifier, note.trapdoor, hash(note.balance))
    pub fn note(
        &self,
        layouter: &mut impl Layouter<F>,
        note: &Note<AssignedCell<F>>,
    ) -> Result<AssignedCell<F>, Error> {
        let note_version = self.assign_note_version(note, layouter)?;

        let h_balance = BalancesChip::new(self.poseidon.clone(), self.advice_pool.clone())
            .hash_balances(layouter, &note.account_balance)?;

        let input = [
            note_version,
            note.id.clone(),
            note.nullifier.clone(),
            note.trapdoor.clone(),
            h_balance,
        ];

        hash(
            &mut layouter.namespace(|| "Note Hash"),
            self.poseidon.clone(),
            input,
        )
    }
}
