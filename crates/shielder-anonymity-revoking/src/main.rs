use anyhow::{anyhow, Result};
use clap::Parser;
use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
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
    let mut nonce = Fr::zero();
    let mut result = Vec::new();
    let start = std::time::Instant::now();

    for i in 0..MAX_NONCE {
        if i % 1000 == 0 && i > 0 {
            println!(
                "hashes: {i}/{MAX_NONCE}, time: {:?}, hashes per second: {:?}",
                start.elapsed(),
                ((i * 1000) as f64) / start.elapsed().as_millis() as f64
            );
        }

        let hash = poseidon_hash(&[id_hash, nonce]);
        result.push(hash);
        nonce += Fr::one();
    }

    result
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
