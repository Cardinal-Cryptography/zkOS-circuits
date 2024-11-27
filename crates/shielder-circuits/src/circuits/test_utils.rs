//! Helpers to be used in unit tests. These helpers are adjusted
//! not for efficiency but for ease of use.

use alloc::vec::Vec;

use halo2_proofs::plonk::{Circuit, Error};
use rand_core::OsRng;
use strum::{EnumCount, IntoEnumIterator};

use crate::{
    circuits::{self, generate_keys_with_min_k, generate_setup_params, verify, F},
    consts::MAX_K,
    generate_proof, ProverKnowledge, PublicInputProvider,
};

pub trait PublicInputProviderExt<Id: IntoEnumIterator + EnumCount + PartialEq, F: Clone>:
    PublicInputProvider<Id, F>
{
    fn with_substitution(&self, id: Id, change: impl Fn(F) -> F) -> Vec<F> {
        Id::iter()
            .map(|instance_id| {
                if instance_id == id {
                    change(self.compute_public_input(instance_id))
                } else {
                    self.compute_public_input(instance_id)
                }
            })
            .collect()
    }
}

impl<Id: IntoEnumIterator + EnumCount + PartialEq, F: Clone, PIP: PublicInputProvider<Id, F>>
    PublicInputProviderExt<Id, F> for PIP
{
}

/// Runs a full pipeline for a circuit that should succeed. This includes:
///  - creating circuit from a correct example,
///  - running a mock prover,
///  - generating keys and proof,
///  - verifying the proof.
pub fn run_full_pipeline<PK: ProverKnowledge<F>>() {
    let mut rng = OsRng;

    let prover_knowledge = PK::random_correct_example(&mut rng);
    let circuit = prover_knowledge.create_circuit();
    let pub_input = prover_knowledge.serialize_public_input();

    // In case of failure, this will fail promptly and output useful debug info.
    run_mock_prover(&circuit, &pub_input);
    // Run full heavy pipeline.
    expect_prover_success_and_run_verification(circuit, &pub_input)
        .expect("Proving-verifying pipeline should succeed");
}

// Runs key generation, proof production on prove_pub_input, and proof verification on verify_pub_input.
// Returns just the verification result, panics if there's a failure earlier.
pub fn expect_prover_success_and_run_verification_on_separate_pub_input<C: Circuit<F> + Default>(
    test_circuit: C,
    prove_pub_input: &[F],
    verify_pub_input: &[F],
) -> Result<(), Error> {
    let mut rng = OsRng;

    let params = generate_setup_params(MAX_K, &mut rng);

    let (params, _k, pk, vk) =
        generate_keys_with_min_k::<C>(params).expect("key generation should succeed");

    let proof = generate_proof(&params, &pk, test_circuit, prove_pub_input, &mut rng);

    verify(&params, &vk, &proof, verify_pub_input)
}

// Runs key generation, proof production, and proof verification.
// Returns just the verification result, panics if there's a failure earlier.
pub fn expect_prover_success_and_run_verification<C>(
    test_circuit: C,
    pub_input: &[F],
) -> Result<(), Error>
where
    C: Circuit<F> + Default,
{
    expect_prover_success_and_run_verification_on_separate_pub_input(
        test_circuit,
        pub_input,
        pub_input,
    )
}

// A prover that outputs useful debug info in case of failing constraints.
pub fn run_mock_prover<C>(test_circuit: &C, pub_input: &[F])
where
    C: Circuit<F> + Default,
{
    let params = generate_setup_params(MAX_K, &mut OsRng);

    let (_, k, _, _) = generate_keys_with_min_k::<C>(params).expect("key generation must succeed");

    circuits::run_mock_prover(k, test_circuit, pub_input.to_vec())
}
