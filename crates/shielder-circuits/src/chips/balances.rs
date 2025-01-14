use core::array;

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::ColumnPool,
    consts::{NUM_TOKENS, POSEIDON_RATE},
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, FieldExt,
};

pub mod off_circuit {
    use super::{FieldExt, POSEIDON_RATE};
    use crate::{consts::NUM_TOKENS, poseidon::off_circuit::hash};

    /// Hashes balances together with placeholders for future token balances
    pub fn balances_hash<F: FieldExt>(balances: [F; NUM_TOKENS]) -> F {
        let mut hash_input = [F::ZERO; POSEIDON_RATE];
        hash_input[..NUM_TOKENS].copy_from_slice(&balances[..NUM_TOKENS]);

        hash(&hash_input)
    }
}

/// Chip used to hash balances
#[derive(Clone, Debug)]
pub struct BalancesChip<F: FieldExt> {
    poseidon: PoseidonChip<F>,
    advice_pool: ColumnPool<Advice>,
}

impl<F: FieldExt> BalancesChip<F> {
    pub fn new(poseidon: PoseidonChip<F>, advice_pool: ColumnPool<Advice>) -> Self {
        Self {
            poseidon,
            advice_pool,
        }
    }

    /// Returns a single cell constrained to be the hash of the given balances
    /// together with placeholders for future token balances (zeros are appended to hash input)
    pub fn hash_balances(
        &self,
        layouter: &mut impl Layouter<F>,
        balances: &[AssignedCell<F>; NUM_TOKENS],
    ) -> Result<AssignedCell<F>, Error> {
        let zero_cell = layouter.assign_region(
            || "Balance placeholder (zero)",
            |mut region| {
                region.assign_advice_from_constant(
                    || "Balance placeholder (zero)",
                    self.advice_pool.get_any(),
                    0,
                    F::ZERO,
                )
            },
        )?;

        static_assertions::const_assert!(NUM_TOKENS <= POSEIDON_RATE);
        let hash_input: [AssignedCell<F>; POSEIDON_RATE] = array::from_fn(|i| {
            if i < NUM_TOKENS {
                balances[i].clone()
            } else {
                zero_cell.clone()
            }
        });

        hash(
            &mut layouter.namespace(|| "Balances Hash"),
            self.poseidon.clone(),
            hash_input,
        )
    }
}
