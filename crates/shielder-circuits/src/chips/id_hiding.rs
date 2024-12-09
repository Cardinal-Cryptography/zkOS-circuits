use halo2_proofs::{circuit::Layouter, plonk::Error};

use crate::{
    chips::range_check::RangeCheckChip,
    consts::NONCE_RANGE_PROOF_NUM_WORDS,
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, FieldExt,
};

#[derive(Clone, Debug)]
pub struct IdHidingChip<F: FieldExt, const CHUNK_SIZE: usize> {
    pub poseidon: PoseidonChip<F>,
    pub range_check: RangeCheckChip<CHUNK_SIZE>,
}

impl<F: FieldExt, const CHUNK_SIZE: usize> IdHidingChip<F, CHUNK_SIZE> {
    pub fn new(poseidon: PoseidonChip<F>, range_check: RangeCheckChip<CHUNK_SIZE>) -> Self {
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
        id: AssignedCell<F>,
        nonce: AssignedCell<F>,
    ) -> Result<AssignedCell<F>, Error> {
        // Constrain `nonce` to be smaller than `2^{CHUNK_SIZE * NONCE_RANGE_PROOF_NUM_WORDS}`.
        self.range_check.constrain_value(
            &mut layouter.namespace(|| "Range Check for nonce"),
            nonce.clone(),
            NONCE_RANGE_PROOF_NUM_WORDS,
        )?;

        let h_id = hash(layouter, self.poseidon.clone(), [id])?;
        hash(layouter, self.poseidon.clone(), [h_id, nonce])
    }
}
