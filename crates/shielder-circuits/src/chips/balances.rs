use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Error},
};

use crate::{
    column_pool::ColumnPool,
    consts::TOKEN_BALANCE_PLACEHOLDERS,
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, FieldExt,
};

/// Chip that is able to calculate note hash
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

    pub fn hash_balances(
        &self,
        layouter: &mut impl Layouter<F>,
        native_balance: &AssignedCell<F>,
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

        // We currently support only the native token, however, we hash it with placeholders for future token balances
        let hash_input: [AssignedCell<F>; 1 + TOKEN_BALANCE_PLACEHOLDERS] = [
            native_balance.clone(),
            zero_cell.clone(),
            zero_cell.clone(),
            zero_cell.clone(),
            zero_cell.clone(),
            zero_cell.clone(),
            zero_cell,
        ];

        hash(
            &mut layouter.namespace(|| "Note Hash"),
            self.poseidon.clone(),
            hash_input,
        )
    }
}
