use halo2_proofs::{circuit::Layouter, plonk::Error};

use crate::{
    chips::range_check::RangeCheckChip,
    consts::NONCE_RANGE_PROOF_NUM_WORDS,
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, F,
};

#[derive(Clone, Debug)]
pub struct IdHidingChip {
    pub poseidon: PoseidonChip,
    pub range_check: RangeCheckChip,
}

impl IdHidingChip {
    pub fn new(poseidon: PoseidonChip, range_check: RangeCheckChip) -> Self {
        Self {
            poseidon,
            range_check,
        }
    }

    /// Constrains `nonce` to be < 2^MAX_NONCE_BIT_LENGTH
    /// Returns new cell as:
    /// id_hiding = Hash(Hash(id), nonce)
    pub fn id_hiding(
        &self,
        layouter: &mut impl Layouter<F>,
        id: AssignedCell,
        nonce: AssignedCell,
    ) -> Result<AssignedCell, Error> {
        // Constrain `nonce` to be smaller than `2^{CHUNK_SIZE * NONCE_RANGE_PROOF_NUM_WORDS}`.
        self.range_check
            .constrain_value::<NONCE_RANGE_PROOF_NUM_WORDS>(
                &mut layouter.namespace(|| "Range Check for nonce"),
                nonce.clone(),
            )?;

        let h_id = hash(layouter, self.poseidon.clone(), [id])?;
        hash(layouter, self.poseidon.clone(), [h_id, nonce])
    }
}
