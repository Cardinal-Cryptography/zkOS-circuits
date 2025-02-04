use halo2_proofs::plonk::Error;

use crate::{synthesizer::Synthesizer, AssignedCell};

pub mod off_circuit {
    use crate::Fr;

    pub fn encrypt(_key: Fr, message: Fr) -> Fr {
        message
    }
}

#[derive(Clone, Debug)]
pub struct ElGamalEncryptionChip;

impl ElGamalEncryptionChip {
    pub fn encrypt(
        &self,
        _synthesizer: &mut impl Synthesizer,
        _key: AssignedCell,
        message: AssignedCell,
    ) -> Result<AssignedCell, Error> {
        Ok(message)
    }
}
