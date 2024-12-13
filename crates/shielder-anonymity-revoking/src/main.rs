use anyhow::{anyhow, Result};
use clap::Parser;
use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use rayon::prelude::*;
use shielder_circuits::poseidon::off_circuit::hash as poseidon_hash;

use crate::cli::{Cli, DataSource};

mod chain;
mod cli;
mod csv;
mod db;

const MAX_NONCE: usize = 65536;
const CHUNK_SIZE: usize = 1000;

/// Generate all id hidings that are seeded with `id_hash`, i.e., `hash(id_hash, nonce)`, for all
/// permissible values of `nonce`.
fn id_hidings(id_hash: Fr) -> Vec<Fr> {
    let start = std::time::Instant::now();

    let results: Vec<Fr> = (0..MAX_NONCE)
        .into_par_iter()
        .map(|i| {
            let nonce = Fr::from(i as u64);
            poseidon_hash(&[id_hash, nonce])
        })
        .collect();

    // You could print statistics after completion:
    let duration = start.elapsed();
    println!(
        "Completed hashing {} nonces in {:?} (~{:.2} hashes/sec)",
        MAX_NONCE,
        duration,
        MAX_NONCE as f64 / duration.as_secs_f64()
    );

    results
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let id_hash = Fr::from_str_vartime(&cli.id_hash).ok_or(anyhow!("Invalid id_hash"))?;

    println!("Computing possible id_hiding for {:?}...", id_hash);
    let id_hidings = id_hidings(id_hash);

    match cli.source {
        DataSource::DB(db_config) => db::run(&id_hidings, db_config),
        DataSource::Chain(chain_config) => chain::run(&id_hidings, chain_config).await,
    }
}
