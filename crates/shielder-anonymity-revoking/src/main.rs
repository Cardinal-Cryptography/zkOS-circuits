use std::{env, fs::File};

use anyhow::Error;
use clap::Parser;
use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use postgres::{Client, NoTls, SimpleQueryMessage};
use prettytable::{Cell, Table};
use secrecy::{ExposeSecret, SecretBox};
use shielder_circuits::poseidon::off_circuit::hash as poseidon_hash;
use crate::cli::CLI;

mod cli;
mod db;

const MAX_NONCE: usize = 65536;
const CHUNK_SIZE: usize = 1000;

fn id_hidings(id_hash: Fr) -> Vec<Fr> {
    let mut nonce = Fr::zero();
    let mut result = Vec::new();
    let start = std::time::Instant::now();

    for i in 0..MAX_NONCE {
        if i % 1000 == 0 && i > 0 {
            println!(
                "hashes: {:?}/{:?}, time: {:?}, hashes per second: {:?}",
                i,
                MAX_NONCE,
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

fn main() -> Result<(), Error> {
    let options = CLI::parse();
    let connection_string = SecretBox::init_with(|| {
        let password = options.password.unwrap_or_else(|| {
            env::var("POSTGRES_PASSWORD")
                .expect("Provide password by -p or POSTGRES_PASSWORD environment variable")
        });

        format!(
            "host={} port={} user={} dbname={} password={}",
            options.host, options.port, options.user, options.database, password
        )
    });

    let mut conn = Client::connect(connection_string.expose_secret(), NoTls)?;
    let id_hash =
        Fr::from_str_vartime(&options.id_hash).ok_or(anyhow::anyhow!("Invalid id_hash"))?;

    println!("Computing possible id_hiding for {:?}...", id_hash);
    let id_hidings = id_hidings(id_hash);

    let mut deposit_native = Table::new();
    let fields_deposit_native = "id_hiding, amount, new_note, new_note_index";
    deposit_native.add_row(fields_deposit_native.split(", ").map(Cell::new).collect());

    let mut withdraw_native = Table::new();
    let fields_withdraw_native =
        "id_hiding, amount, \"to\", new_note, new_note_index, relayer_address, fee";
    withdraw_native.add_row(fields_withdraw_native.split(", ").map(Cell::new).collect());
    println!("Fetching data from database...");

    for chunk in id_hidings.chunks(CHUNK_SIZE) {
        let chunk = chunk
            .iter()
            .map(|id| format!("{:?}", id))
            .collect::<Vec<_>>();

        let chunk = chunk.join(", ");

        let query = format!(
            "SELECT {fields_deposit_native} FROM deposit_native WHERE id_hiding IN ({chunk})"
        );
        let res = conn.simple_query(&query)?;
        for msg in res {
            if let SimpleQueryMessage::Row(row) = msg {
                deposit_native.add_row(
                    (0..row.len())
                        .map(|f| Cell::new(row.get(f).unwrap()))
                        .collect(),
                );
            }
        }

        let query = format!(
            "SELECT {fields_withdraw_native} FROM withdraw_native WHERE id_hiding IN ({chunk})"
        );
        let res = conn.simple_query(&query)?;
        for msg in res {
            if let SimpleQueryMessage::Row(row) = msg {
                withdraw_native.add_row(
                    (0..row.len())
                        .map(|f| Cell::new(row.get(f).unwrap()))
                        .collect(),
                );
            }
        }
    }

    println!("\n\nDEPOSIT_NATIVE\n\n");
    deposit_native.printstd();
    let out = File::create("deposit_native.csv")?;
    deposit_native.to_csv(out)?;

    println!("\n\nWITHDRAW_NATIVE\n\n");
    withdraw_native.printstd();
    let out = File::create("withdraw_native.csv")?;
    withdraw_native.to_csv(out)?;

    Ok(())
}
