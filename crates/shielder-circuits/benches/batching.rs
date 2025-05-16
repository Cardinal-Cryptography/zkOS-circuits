use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::{create_proof, verify_proof};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_proofs::transcript::TranscriptWriterBuffer;
use rand::prelude::StdRng;
use rand::Rng;
use rand_core::SeedableRng;
use shielder_circuits::circuits::{Params, ProvingKey};
use shielder_circuits::merkle::MerkleCircuit;
use shielder_circuits::{
    circuits::merkle::MerkleProverKnowledge,
    consts::merkle_constants::{ARITY, NOTE_TREE_HEIGHT},
    generate_keys_with_min_k, generate_setup_params, CommitmentScheme, Prover, ProverKnowledge,
    PublicInputProvider, Verifier, MAX_K,
};
use transcript::Keccak256Transcript;

criterion_main! {
    batching
}

criterion_group! {
    name = batching;
    config = Criterion::default().sample_size(10);
    targets = bench_batching
}

type Circuit = MerkleCircuit<NOTE_TREE_HEIGHT>;
type PK = MerkleProverKnowledge<NOTE_TREE_HEIGHT, Fr>;
const BATCH_SIZE: usize = 100;

pub fn bench_batching(c: &mut Criterion) {
    // ==================================== SETUP PHASE ==================================== //
    let mut rng = StdRng::from_seed([41; 32]);

    let full_params = generate_setup_params(MAX_K, &mut rng);
    let (reduced_params, k, pk, vk) =
        generate_keys_with_min_k(Circuit::default(), full_params).unwrap();

    // ==================================== DATA PHASE ==================================== //
    let (mut circuits, mut instances_owned) = (vec![], vec![]);
    for _ in 0..BATCH_SIZE {
        let prover_knowledge = PK::random_correct_example(&mut rng);
        circuits.push(prover_knowledge.create_circuit());
        instances_owned.push(vec![prover_knowledge.serialize_public_input()]);
    }
    let instances_less_owned = instances_owned
        .iter()
        .map(|instance_column| {
            instance_column
                .iter()
                .map(|i| i.as_slice())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let instances = instances_less_owned
        .iter()
        .map(|instance_column| instance_column.as_slice())
        .collect::<Vec<_>>();

    // ==================================== PROVING PHASE ==================================== //
    let mut group = c.benchmark_group("Batch proving / verifying");

    // Actually generate a proof, for future verification bench.
    group.bench_function(
        BenchmarkId::new(
            "Batch proving",
            format!("batch size = {BATCH_SIZE}, k={k}, arity={ARITY}, height={NOTE_TREE_HEIGHT}"),
        ),
        |b| {
            b.iter(|| {
                black_box(generate_batched_proof(
                    &reduced_params,
                    &pk,
                    &circuits,
                    &instances,
                    &mut rng,
                ))
            })
        },
    );

    // Actually generate a proof, for future verification bench.
    let proof = generate_batched_proof(&reduced_params, &pk, &circuits, &instances, &mut rng);

    // ==================================== VERIFYING PHASE ==================================== //
    group.bench_function(
        BenchmarkId::new(
            "Batch verifying",
            format!("batch size = {BATCH_SIZE}, k={k}, arity={ARITY}, height={NOTE_TREE_HEIGHT}"),
        ),
        |b| {
            b.iter(|| {
                let mut transcript = Keccak256Transcript::new(proof.as_slice());
                black_box(verify_proof::<CommitmentScheme, Verifier, _, _, _>(
                    reduced_params.verifier_params(),
                    &vk,
                    AccumulatorStrategy::new(reduced_params.verifier_params()),
                    &instances,
                    &mut transcript,
                ))
            })
        },
    );
}

fn generate_batched_proof(
    params: &Params,
    pk: &ProvingKey,
    circuits: &[Circuit],
    instances: &[&[&[Fr]]],
    rng: &mut impl Rng,
) -> Vec<u8> {
    let mut transcript = Keccak256Transcript::new(Vec::new());
    create_proof::<CommitmentScheme, Prover, _, _, _, Circuit>(
        params,
        pk,
        circuits,
        instances,
        rng,
        &mut transcript,
    )
    .unwrap();
    transcript.finalize().to_vec()
}
