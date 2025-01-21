use core::array;

use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::{ColumnPool, SynthesisPhase},
    consts::{NUM_TOKENS, POSEIDON_RATE},
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, Field, F,
};

pub mod off_circuit {
    use super::POSEIDON_RATE;
    use crate::{consts::NUM_TOKENS, poseidon::off_circuit::hash, Field, F};

    /// Hashes balances together with placeholders for future token balances
    pub fn balances_hash(balances: [F; NUM_TOKENS]) -> F {
        let mut hash_input = [F::ZERO; POSEIDON_RATE];
        hash_input[..NUM_TOKENS].copy_from_slice(&balances[..NUM_TOKENS]);

        hash(&hash_input)
    }
}

/// Chip used to hash balances
#[derive(Clone, Debug)]
pub struct BalancesChip {
    poseidon: PoseidonChip,
}

impl BalancesChip {
    pub fn new(poseidon: PoseidonChip) -> Self {
        Self { poseidon }
    }

    /// Returns a single cell constrained to be the hash of the given balances
    /// together with placeholders for future token balances (zeros are appended to hash input)
    pub fn hash_balances(
        &self,
        layouter: &mut impl Layouter<F>,
        column_pool: &ColumnPool<Advice, SynthesisPhase>,
        balances: &[AssignedCell; NUM_TOKENS],
    ) -> Result<AssignedCell, Error> {
        let zero_cell = layouter.assign_region(
            || "Balance placeholder (zero)",
            |mut region| {
                region.assign_advice_from_constant(
                    || "Balance placeholder (zero)",
                    column_pool.get_any(),
                    0,
                    F::ZERO,
                )
            },
        )?;

        static_assertions::const_assert!(NUM_TOKENS <= POSEIDON_RATE);
        let hash_input: [AssignedCell; POSEIDON_RATE] = array::from_fn(|i| {
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
