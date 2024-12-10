use clap::Parser;

/// Utility for unmasking a shielder user by id_hash for the prototype system. You will
/// need access to the postgres database for the shielder indexer
/// (this one https://github.com/Cardinal-Cryptography/zkOS-indexer). Output tables
/// are also written to deposit_native.csv and withdraw_native.csv.
///
/// Remember to run/compile with --release, otherwise hashing is very slow.
#[derive(Parser, Debug)]
pub struct CLI {
    /// Id to unmask
    #[clap(short, long)]
    pub id_hash: String,

    /// Postgres host to connect to
    #[clap(short, long)]
    pub host: String,

    /// Postgres port to connect to
    #[clap(short, long, default_value_t = 5432)]
    pub port: u16,

    /// Postgres user to connect as
    #[clap(short, long)]
    pub user: String,

    /// Postgres password to connect with - uses POSTGRES_PASSWORD environment variable if not provided
    #[clap(short, long, default_value = None)]
    pub password: Option<String>,

    /// Database to connect to (assumed to be an indexer database)
    #[clap(short, long, default_value = "zkos")]
    pub database: String,
}
