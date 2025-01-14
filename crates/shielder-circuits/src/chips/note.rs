use core::array;

use halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    chips::balances::BalancesChip,
    column_pool::ColumnPool,
    consts::NUM_TOKENS,
    poseidon::circuit::{hash, PoseidonChip},
    version::NoteVersion,
    AssignedCell, F,
};
/// Chip that is able to calculate note hash
#[derive(Clone, Debug)]
pub struct NoteChip {
    poseidon: PoseidonChip,
    advice_pool: ColumnPool<Advice>,
}

#[derive(Copy, Clone, Debug)]
pub struct Note<T> {
    pub version: NoteVersion,
    pub id: T,
    pub nullifier: T,
    pub trapdoor: T,
    pub balances: [T; NUM_TOKENS],
}

pub mod off_circuit {

    use halo2_proofs::arithmetic::Field;

    use crate::{
        chips::{balances::off_circuit::balances_hash, note::Note},
        consts::NUM_TOKENS,
        poseidon::off_circuit::hash,
        F,
    };

    pub fn note_hash(note: &Note<F>) -> F {
        let input = [
            note.version.as_field(),
            note.id,
            note.nullifier,
            note.trapdoor,
            balances_hash(note.balances),
        ];

        hash(&input)
    }

    /// TODO: Remove this temporary helper once NewAccount and Withdraw support balance tuples.
    /// Produces the balance shortlist tuple from a single native balance.
    pub fn balances_from_native_balance(native_balance: F) -> [F; NUM_TOKENS] {
        let mut balances = [F::ZERO; NUM_TOKENS];
        balances[0] = native_balance;
        balances
    }
}

impl NoteChip {
    pub fn new(poseidon: PoseidonChip, advice_pool: ColumnPool<Advice>) -> Self {
        Self {
            poseidon,
            advice_pool,
        }
    }

    fn assign_note_version(
        &self,
        note: &Note<AssignedCell>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<AssignedCell, Error> {
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
        note: &Note<AssignedCell>,
    ) -> Result<AssignedCell, Error> {
        let note_version = self.assign_note_version(note, layouter)?;

        let h_balance = BalancesChip::new(self.poseidon.clone(), self.advice_pool.clone())
            .hash_balances(layouter, &note.balances)?;

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
    layouter: &mut impl Layouter<F>,
    advice_pool: &ColumnPool<Advice>,
) -> Result<[AssignedCell; NUM_TOKENS], Error> {
    let zero_cell = layouter.assign_region(
        || "Balance placeholder (zero)",
        |mut region| {
            region.assign_advice_from_constant(
                || "Balance placeholder (zero)",
                advice_pool.get_any(),
                0,
                F::ZERO,
            )
        },
    )?;

    Ok(array::from_fn(|i| {
        if i == 0 {
            native_balance.clone()
        } else {
            zero_cell.clone()
        }
    }))
}
