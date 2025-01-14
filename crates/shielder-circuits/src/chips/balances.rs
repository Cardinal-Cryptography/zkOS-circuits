use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::ColumnPool,
    consts::POSEIDON_RATE,
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, Field, F,
};

pub mod off_circuit {
    use super::POSEIDON_RATE;
    use crate::{poseidon::off_circuit::hash, Field, F};

    /// Hashes native balance together with placeholders for future token balances
    pub fn balances_hash(native_balance: F) -> F {
        hash::<POSEIDON_RATE>(&[
            native_balance,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }
}

/// Chip used to hash balances
#[derive(Clone, Debug)]
pub struct BalancesChip {
    poseidon: PoseidonChip,
    advice_pool: ColumnPool<Advice>,
}

impl BalancesChip {
    pub fn new(poseidon: PoseidonChip, advice_pool: ColumnPool<Advice>) -> Self {
        Self {
            poseidon,
            advice_pool,
        }
    }

    /// Returns a single cell constrained to be the hash of the given native balance
    /// together with placeholders for future token balances (zeros are appended to hash input)
    pub fn hash_balances(
        &self,
        layouter: &mut impl Layouter<F>,
        native_balance: &AssignedCell,
    ) -> Result<AssignedCell, Error> {
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

        // We currently support only the native token, however, we hash it with placeholders for future token balances
        let hash_input: [AssignedCell; POSEIDON_RATE] = [
            native_balance.clone(),
            zero_cell.clone(),
            zero_cell.clone(),
            zero_cell.clone(),
            zero_cell.clone(),
            zero_cell.clone(),
            zero_cell,
        ];

        hash(
            &mut layouter.namespace(|| "Balances Hash"),
            self.poseidon.clone(),
            hash_input,
        )
    }
}
