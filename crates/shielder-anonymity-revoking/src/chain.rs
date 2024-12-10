use anyhow::Result;
use clap::Args;
use halo2_proofs::halo2curves::bn256::Fr;
use shielder_rust_sdk::contract::providers::create_simple_provider;

#[derive(Args, Debug)]
pub struct ChainConfig {
    ///RPC address of the node that we will be connecting to.
    #[clap(short, long)]
    node: String,
}

pub fn run(id_hidings: &[Fr], config: ChainConfig) -> Result<()> {
    let _provider = create_simple_provider(&config.node)?;
    todo!()
}
