use core::array;

use halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    plonk::{Advice, Error},
};

use super::shortlist_hash::Shortlist;
use crate::{
    chips::shortlist_hash::ShortlistHashChip,
    column_pool::{ColumnPool, SynthesisPhase},
    consts::NUM_TOKENS,
    poseidon::circuit::{hash, PoseidonChip},
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
        layouter: &mut impl Layouter<Fr>,
        column_pool: &ColumnPool<Advice, SynthesisPhase>,
    ) -> Result<AssignedCell, Error> {
        let note_version: Fr = note.version.as_field();

        layouter.assign_region(
            || "note_version",
            |mut region| {
                region.assign_advice_from_constant(
                    || "note_version",
                    column_pool.get_any(),
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
        layouter: &mut impl Layouter<Fr>,
        column_pool: &ColumnPool<Advice, SynthesisPhase>,
        note: &Note<AssignedCell>,
    ) -> Result<AssignedCell, Error> {
        let note_version = self.assign_note_version(note, layouter, column_pool)?;

        let h_balance = ShortlistHashChip::new(self.poseidon.clone()).shortlist_hash(
            layouter,
            column_pool,
            &note.balances,
        )?;

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

/// TODO: Remove this temporary helper once NewAccount and Withdraw support balance tuples.
/// Converts a single native balance to a balance tuple with the remaining balances
/// constrained to 0.
pub fn balances_from_native_balance(
    native_balance: AssignedCell,
    layouter: &mut impl Layouter<Fr>,
    advice_pool: &ColumnPool<Advice, SynthesisPhase>,
) -> Result<Shortlist<AssignedCell, NUM_TOKENS>, Error> {
    let zero_cell = layouter.assign_region(
        || "Balance placeholder (zero)",
        |mut region| {
            region.assign_advice_from_constant(
                || "Balance placeholder (zero)",
                advice_pool.get_any(),
                0,
                Fr::ZERO,
            )
        },
    )?;

    Ok(Shortlist::new(array::from_fn(|i| {
        if i == 0 {
            native_balance.clone()
        } else {
            zero_cell.clone()
        }
    })))
}
