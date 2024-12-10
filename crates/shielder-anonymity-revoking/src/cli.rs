use clap::{Parser, Subcommand};
use crate::chain::ChainConfig;
use crate::db::DbConfig;

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

    /// What source of data should be used.
    #[command(subcommand)]
    pub source: DataSource,
}

#[derive(Subcommand, Debug)]
pub enum DataSource {
    DB(DbConfig),
    Chain(ChainConfig)
}
