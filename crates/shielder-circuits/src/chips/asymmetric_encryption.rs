use halo2_proofs::plonk::ErrorFront;
use macros::embeddable;

use crate::{embed::Embed, synthesizer::Synthesizer, AssignedCell};

#[derive(Copy, Clone, Debug, Default)]
#[embeddable(
    receiver = "AsymPublicKey<crate::Value>",
    embedded = "AsymPublicKey<crate::AssignedCell>"
)]
pub struct AsymPublicKey<T> {
    pub x: T,
    pub y: T,
}

pub mod off_circuit {
    use crate::{chips::asymmetric_encryption::AsymPublicKey, Fr};

    pub fn encrypt(_key: AsymPublicKey<Fr>, message: Fr) -> Fr {
        message
    }
}

#[derive(Clone, Debug)]
pub struct ElGamalEncryptionChip;

impl ElGamalEncryptionChip {
    pub fn encrypt(
        &self,
        _synthesizer: &mut impl Synthesizer,
        _key: AsymPublicKey<AssignedCell>,
        message: AssignedCell,
    ) -> Result<AssignedCell, ErrorFront> {
        Ok(message)
    }
}
