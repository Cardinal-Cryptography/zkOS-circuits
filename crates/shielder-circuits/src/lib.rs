#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

mod chips;
pub mod circuits;
mod column_pool;
mod config_builder;
pub mod consts;
mod embed;
mod gates;
mod instance_wrapper;
pub mod poseidon;
mod range_table;
mod todo;
mod version;

use alloc::{fmt::Debug, vec::Vec};

pub use chips::note::{off_circuit::note_hash, Note};
pub use circuits::*;
pub use consts::MAX_K;
pub use halo2_proofs::{
    arithmetic::Field,
    dev::CircuitCost,
    halo2curves::bn256::{Bn256, G1Affine, G1},
    plonk::{Circuit, ProvingKey, VerifyingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use rand_core::RngCore;
pub use strum::{EnumCount, IntoEnumIterator};
pub use version::NoteVersion;

// We decided to use Raw because otherwise the smart contract would have to perform decompression,
// which we expect to be more expensive than the difference in call data size.
// For our benchmarks, the sizes were 5447 and 3367 for Raw and Processed, respectively.
pub const SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

pub trait ProverKnowledge<F: Field>: Clone + PublicInputProvider<Self::PublicInput, F> {
    /// Associated type for the circuit.
    type Circuit: Circuit<F> + Clone + Debug + Default;

    /// Associated type for the public inputs. Expected to be iterable enumeration.
    type PublicInput: IntoEnumIterator + EnumCount;

    /// Creates a new instance of the circuit values with correct, randomized values. The circuit
    /// MUST be satisfied. Implementation might require more effort to generate such values. Useful
    /// for testing validity of the circuit constraints.
    fn random_correct_example(rng: &mut impl RngCore) -> Self;

    /// Creates a new instance of the circuit based on the prover's knowledge.
    fn create_circuit(&self) -> Self::Circuit;
}

pub trait PublicInputProvider<Id: IntoEnumIterator + EnumCount, F> {
    /// Computes specific public input value.
    fn compute_public_input(&self, input: Id) -> F;

    /// Return full public input as a vector of field elements.
    fn serialize_public_input(&self) -> Vec<F> {
        Id::iter()
            .map(|instance_id| self.compute_public_input(instance_id))
            .collect()
    }
}

impl<Id: IntoEnumIterator + EnumCount, F, Comp: Fn(Id) -> F> PublicInputProvider<Id, F> for Comp {
    fn compute_public_input(&self, instance_id: Id) -> F {
        self(instance_id)
    }
}
