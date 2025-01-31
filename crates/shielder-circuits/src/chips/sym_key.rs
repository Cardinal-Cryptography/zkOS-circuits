use halo2_proofs::plonk::Error;

use crate::{
    consts::SYM_KEY_SALT,
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    AssignedCell,
};

pub mod off_circuit {
    use crate::{consts::SYM_KEY_SALT, poseidon::off_circuit::hash, Fr};

    pub fn derive(id: Fr) -> Fr {
        hash(&[id, *SYM_KEY_SALT])
    }
}

#[derive(Clone, Debug)]
pub struct SymKeyChip {
    poseidon: PoseidonChip,
}

impl SymKeyChip {
    pub fn new(poseidon: PoseidonChip) -> Self {
        Self { poseidon }
    }

    pub fn derive(
        &self,
        synthesizer: &mut impl Synthesizer,
        id: AssignedCell,
    ) -> Result<AssignedCell, Error> {
        let salt = synthesizer.assign_constant("SymKey salt", *SYM_KEY_SALT)?;
        hash(synthesizer, self.poseidon.clone(), [id, salt])
    }
}
