use std::env;

use anyhow::Result;
use clap::Args;
use halo2_proofs::halo2curves::bn256::Fr;
use postgres::{Client, NoTls, SimpleQueryMessage};
use prettytable::{Cell, Table};
use secrecy::{ExposeSecret, SecretBox};

use crate::{
    csv::{
        deposit_field_names, deposit_table, save_deposit_table, save_withdraw_table,
        withdraw_field_names, withdraw_table,
    },
    CHUNK_SIZE,
};

#[derive(Args, Debug)]
pub struct DbConfig {
    /// Postgres host to connect to
    #[clap(short, long)]
    host: String,

    /// Postgres port to connect to
    #[clap(short, long, default_value_t = 5432)]
    port: u16,

    /// Postgres user to connect as
    #[clap(short, long)]
    user: String,

    /// Postgres password to connect with - uses POSTGRES_PASSWORD environment variable if not provided
    #[clap(short, long, default_value = None)]
    password: Option<String>,

    /// Database to connect to (assumed to be an indexer database)
    #[clap(short, long, default_value = "zkos")]
    database: String,
}

pub fn run(id_hidings: &[Fr], config: DbConfig) -> Result<()> {
    let mut conn = create_connection(config)?;

    let mut deposit_native = deposit_table();
    let mut withdraw_native = withdraw_table();

    println!("Fetching data from database...");
    for chunk in id_hidings.chunks(CHUNK_SIZE) {
        let chunk = chunk
            .iter()
            .map(|id| format!("{:?}", id))
            .collect::<Vec<_>>()
            .join(", ");

        handle_relation(
            &mut conn,
            &mut deposit_native,
            &chunk,
            "deposit_native",
            deposit_field_names(),
        )?;
        handle_relation(
            &mut conn,
            &mut withdraw_native,
            &chunk,
            "withdraw_native",
            withdraw_field_names(),
        )?;
    }

    save_deposit_table(deposit_native);
    save_withdraw_table(withdraw_native);

    Ok(())
}

fn create_connection(config: DbConfig) -> Result<Client> {
    let connection_string = SecretBox::init_with(|| {
        let password = config.password.unwrap_or_else(|| {
            env::var("POSTGRES_PASSWORD")
                .expect("Provide password by -p or POSTGRES_PASSWORD environment variable")
        });

        format!(
            "host={} port={} user={} dbname={} password={}",
            config.host, config.port, config.user, config.database, password
        )
    });

    Ok(Client::connect(connection_string.expose_secret(), NoTls)?)
}

fn handle_relation(
    conn: &mut Client,
    aggregation: &mut Table,
    chunk: &String,
    table_name: &'static str,
    table_fields: &str,
) -> Result<()> {
    let query = format!("SELECT {table_fields} FROM {table_name} WHERE id_hiding IN ({chunk})");
    for msg in conn.simple_query(&query)? {
        if let SimpleQueryMessage::Row(row) = msg {
            aggregation.add_row(
                (0..row.len())
                    .map(|f| Cell::new(row.get(f).unwrap()))
                    .collect(),
            );
        }
    }
    Ok(())
}
