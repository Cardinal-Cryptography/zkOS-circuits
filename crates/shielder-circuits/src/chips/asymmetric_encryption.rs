use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};
use macros::embeddable;

use crate::{
    curve_arithmetic::{GrumpkinPoint, GrumpkinPointAffine},
    embed::Embed,
    synthesizer::Synthesizer,
    AssignedCell,
};

// #[derive(Copy, Clone, Debug, Default)]
// #[embeddable(
//     receiver = "AsymPublicKey<crate::Value>",
//     embedded = "AsymPublicKey<crate::AssignedCell>"
// )]
// pub struct AsymPublicKey<T> {
//     pub x: T,
//     pub y: T,
// }

pub type AsymPublicKey<T> = GrumpkinPointAffine<T>;

pub mod off_circuit {
    use super::ElGamalEncryptionInput;
    use crate::{
        chips::asymmetric_encryption::AsymPublicKey,
        curve_arithmetic::{self, GrumpkinPoint},
        Fr,
    };

    pub fn encrypt(
        ElGamalEncryptionInput {
            message,
            public_key,
            trapdoor_le_bits,
        }: ElGamalEncryptionInput<Fr>,
    ) -> (GrumpkinPoint<Fr>, GrumpkinPoint<Fr>) {
        let generator = GrumpkinPoint::generator();

        let public_key_projective = public_key.into();

        let shared_secret =
            curve_arithmetic::scalar_multiply(public_key_projective, trapdoor_le_bits);

        let ciphertext1 = curve_arithmetic::scalar_multiply(generator, trapdoor_le_bits);

        let ciphertext2 = curve_arithmetic::points_add(message, shared_secret);

        (ciphertext1, ciphertext2)
    }

    pub fn decrypt(
        ciphertext1: GrumpkinPoint<Fr>,
        ciphertext2: GrumpkinPoint<Fr>,
        private_key_le_bits: [Fr; 254],
    ) -> GrumpkinPoint<Fr> {
        let shared_secret = curve_arithmetic::scalar_multiply(ciphertext1, private_key_le_bits);
        ciphertext2 - shared_secret
    }
}

#[derive(Clone, Debug)]
#[embeddable(
    receiver = "ElGamalEncryptionInput<crate::Value>",
    embedded = "ElGamalEncryptionInput<AssignedCell>"
)]
pub struct ElGamalEncryptionInput<T> {
    pub message: GrumpkinPoint<T>,
    pub public_key: AsymPublicKey<T>,
    pub trapdoor_le_bits: [T; 254],
}

#[derive(Clone, Debug)]
pub struct ElGamalEncryptionChip;

impl ElGamalEncryptionChip {
    pub fn encrypt(
        &self,
        _synthesizer: &mut impl Synthesizer,
        _key: AsymPublicKey<AssignedCell>,
        message: AssignedCell,
    ) -> Result<AssignedCell, Error> {
        Ok(message)
    }
}
