use once_cell::sync::Lazy;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use shielder_circuits::circuits::Params;
use shielder_circuits::merkle::{MerkleCircuit, MerkleProverKnowledge};
use shielder_circuits::{
    generate_keys_with_min_k, generate_proof, generate_setup_params, verify, ProverKnowledge,
    PublicInputProvider, MAX_K,
};
use std::time::Instant;

static PARAMS: Lazy<Params> =
    Lazy::new(|| generate_setup_params(MAX_K, &mut StdRng::from_seed(Default::default())));

const NOTE_TREE_HEIGHT: usize = 13;

fn main() {
    let mut rng = StdRng::from_seed([41; 32]);

    let values = MerkleProverKnowledge::<NOTE_TREE_HEIGHT, _>::random_correct_example(&mut rng);
    let circuit = values.create_circuit();

    let (reduced_params, _, pk, vk) =
        generate_keys_with_min_k(MerkleCircuit::<NOTE_TREE_HEIGHT>::default(), PARAMS.clone())
            .unwrap();

    let public_input = values.serialize_public_input();

    println!("proving...");
    let proving_start = Instant::now();

    let proof = generate_proof(&reduced_params, &pk, circuit, &public_input, &mut rng);

    println!("proving duration: {:?}", proving_start.elapsed());
    println!("proof length: {}", proof.len());

    println!("verifying...");
    let verifying_start = Instant::now();
    verify(&reduced_params, &vk, &proof, &public_input).expect("verification should not fail");
    println!("verifying duration: {:?}", verifying_start.elapsed());
}
