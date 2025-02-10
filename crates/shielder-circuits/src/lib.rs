#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod chips;
pub mod circuits;
mod column_pool;
mod config_builder;
pub mod consts;
mod curve_operations;
mod embed;
mod gates;
mod instance_wrapper;
pub mod poseidon;
mod range_table;
mod synthesizer;
mod version;

use alloc::{fmt::Debug, vec::Vec};

pub use chips::note::{off_circuit::note_hash, Note};
pub use circuits::*;
pub use consts::MAX_K;
pub use halo2_frontend::dev::CircuitCost;
pub use halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Bn256, Fr, G1Affine, G1},
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

pub type AssignedCell = halo2_proofs::circuit::AssignedCell<Fr, Fr>;
pub type Value = halo2_proofs::circuit::Value<Fr>;

pub trait ProverKnowledge: Clone + PublicInputProvider<Self::PublicInput> {
    /// Associated type for the circuit.
    type Circuit: Circuit<Fr> + Clone + Debug + Default;

    /// Associated type for the public inputs. Expected to be iterable enumeration.
    type PublicInput: IntoEnumIterator + EnumCount;

    /// Creates a new instance of the circuit values with correct, randomized values. The circuit
    /// MUST be satisfied. Implementation might require more effort to generate such values. Useful
    /// for testing validity of the circuit constraints.
    fn random_correct_example(rng: &mut impl RngCore) -> Self;

    /// Creates a new instance of the circuit based on the prover's knowledge.
    fn create_circuit(&self) -> Self::Circuit;
}

pub trait PublicInputProvider<Id: IntoEnumIterator + EnumCount> {
    /// Computes specific public input value.
    fn compute_public_input(&self, input: Id) -> Fr;

    /// Return full public input as a vector of field elements.
    fn serialize_public_input(&self) -> Vec<Fr> {
        Id::iter()
            .map(|instance_id| self.compute_public_input(instance_id))
            .collect()
    }
}

impl<Id: IntoEnumIterator + EnumCount, Comp: Fn(Id) -> Fr> PublicInputProvider<Id> for Comp {
    fn compute_public_input(&self, instance_id: Id) -> Fr {
        self(instance_id)
    }
}

#[cfg(test)]
mod hehe {
    use halo2_frontend::{
        circuit::{floor_planner::V1, Layouter},
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use rand::rngs::OsRng;

    use crate::config_builder::ConfigsBuilder;
    use crate::{generate_keys_with_min_k, generate_proof, generate_setup_params, Fr};

    struct T;
    impl Circuit<Fr> for T {
        type Config = ();
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            meta.instance_column();
            ConfigsBuilder::new(meta).with_poseidon();
        }

        fn synthesize(
            &self,
            _config: Self::Config,
            _layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn hoho() {
        let params = generate_setup_params(6, &mut OsRng);
        let (params, _, pk, _) = generate_keys_with_min_k(T, params).unwrap();
        generate_proof(&params, &pk, T, &[], &mut OsRng);
    }
}
