use halo2_proofs::plonk::Error;

use crate::{
    poseidon::circuit::{hash, PoseidonChip},
    synthesizer::Synthesizer,
    AssignedCell,
};

/// Input for MAC calculation.
#[derive(Copy, Clone, Debug, Default)]
pub struct MacInput<T> {
    pub key: T,
    pub salt: T,
}

/// MAC (commitment to a key accompanied by salt).
#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub struct Mac<T> {
    pub salt: T,
    pub commitment: T,
}

#[allow(dead_code)]
pub mod off_circuit {
    use crate::{
        chips::mac::{Mac, MacInput},
        poseidon::off_circuit::hash,
        Fr,
    };

    pub fn mac(input: &MacInput<Fr>) -> Mac<Fr> {
        Mac {
            salt: input.salt,
            commitment: hash(&[input.salt, input.key]),
        }
    }
}

/// Chip that is able to calculate MAC.
///
/// Given a key `key` and a random value `r`, MAC is calculated as `(r, H(r, key))`.
#[derive(Clone, Debug)]
pub struct MacChip {
    poseidon: PoseidonChip,
}

impl MacChip {
    /// Create a new `MacChip`.
    pub fn new(poseidon: PoseidonChip) -> Self {
        Self { poseidon }
    }

    /// Calculate the MAC as `(r, H(r, key))`.
    pub fn mac(
        &self,
        synthesizer: &mut impl Synthesizer,
        input: &MacInput<AssignedCell>,
    ) -> Result<Mac<AssignedCell>, Error> {
        let commitment = hash(
            synthesizer,
            self.poseidon.clone(),
            [input.salt.clone(), input.key.clone()],
        )?;

        Ok(Mac {
            salt: input.salt.clone(),
            commitment,
        })
    }
}
