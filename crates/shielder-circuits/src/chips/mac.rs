use halo2_proofs::{circuit::Layouter, plonk::Error};

use crate::{
    poseidon::circuit::{hash, PoseidonChip},
    AssignedCell, FieldExt,
};

/// Input for MAC calculation.
#[derive(Copy, Clone, Debug)]
pub struct MacInput<T> {
    pub key: T,
    pub r: T,
}

/// MAC (commitment to a key accompanied by salt).
#[derive(Copy, Clone, Debug)]
pub struct Mac<T> {
    pub r: T,
    pub commitment: T,
}

pub mod off_circuit {
    use crate::{
        chips::mac::{Mac, MacInput},
        poseidon::off_circuit::hash,
        FieldExt,
    };

    pub fn mac<F: FieldExt>(input: &MacInput<F>) -> Mac<F> {
        Mac {
            r: input.r,
            commitment: hash(&[input.r, input.key]),
        }
    }
}

/// Chip that is able to calculate MAC.
///
/// Given a key `key` and a random value `r`, MAC is calculated as `(r, H(r, key))`.
#[derive(Clone, Debug)]
pub struct MacChip<F: FieldExt> {
    poseidon: PoseidonChip<F>,
}

impl<F: FieldExt> MacChip<F> {
    /// Create a new `MacChip`.
    pub fn new(poseidon: PoseidonChip<F>) -> Self {
        Self { poseidon }
    }

    /// Calculate the MAC as `(r, H(r, key))`.
    pub fn note(
        &self,
        layouter: &mut impl Layouter<F>,
        input: &MacInput<AssignedCell<F>>,
    ) -> Result<Mac<AssignedCell<F>>, Error> {
        let commitment = hash(
            &mut layouter.namespace(|| "MAC"),
            self.poseidon.clone(),
            [input.r.clone(), input.key.clone()],
        )?;

        Ok(Mac {
            r: input.r.clone(),
            commitment,
        })
    }
}
