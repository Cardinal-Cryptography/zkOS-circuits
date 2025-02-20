use halo2_proofs::plonk::Error;

use crate::{
    chips::range_check::RangeCheckChip,
    consts::NONCE_RANGE_PROOF_NUM_WORDS,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    AssignedCell,
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
        synthesizer: &mut impl Synthesizer,
        id: AssignedCell,
        nonce: AssignedCell,
    ) -> Result<AssignedCell, Error> {
        // Constrain `nonce` to be smaller than `2^{CHUNK_SIZE * NONCE_RANGE_PROOF_NUM_WORDS}`.
        self.range_check
            .constrain_value::<NONCE_RANGE_PROOF_NUM_WORDS>(synthesizer, nonce.clone())?;

        let h_id = hash(synthesizer, self.poseidon.clone(), [id])?;
        hash(synthesizer, self.poseidon.clone(), [h_id, nonce])
    }
}
