use std::{cmp::min, str::FromStr};

use alloy_provider::Provider;
use alloy_rpc_types::{Filter, Log};
use alloy_sol_types::{Error, SolEvent};
use anyhow::Result;
use clap::Args;
use halo2_proofs::halo2curves::bn256::Fr;
use shielder_rust_sdk::{
    alloy_primitives::Address,
    contract::{
        providers::create_simple_provider,
        ShielderContract::{
            DepositNative, NewAccountNative, ShielderContractEvents, WithdrawNative,
        },
    },
    conversion::u256_to_field,
};

/// Eth node support querying for events only in windows of up to 10K blocks.
const SCAN_BATCH_SPAN: usize = 10_000;

#[derive(Args, Debug)]
pub struct ChainConfig {
    /// RPC address of the node that we will be connecting to.
    #[clap(short, long)]
    node: String,

    /// Address of the Shielder contract.
    #[clap(short, long)]
    contract_address: String,
}

pub async fn run(id_hidings: &[Fr], config: ChainConfig) -> Result<()> {
    let contract_address = Address::from_str(&config.contract_address)?;
    let base_filter = Filter::new().address(contract_address);

    let provider = create_simple_provider(&config.node).await?;
    let current_height = provider.get_block_number().await?;

    let mut deposits = vec![];
    let mut withdrawals = vec![];

    for block_number in (0..=current_height).step_by(SCAN_BATCH_SPAN) {
        let last_batch_block = min(block_number + SCAN_BATCH_SPAN as u64 - 1, current_height);
        let filter = base_filter
            .clone()
            .from_block(block_number)
            .to_block(last_batch_block);

        let raw_logs = provider.get_logs(&filter).await?;
        println!(
            "Found {} logs in block range {block_number}-{last_batch_block}",
            raw_logs.len()
        );

        let raw_logs_len = raw_logs.len();
        let filtered_logs = filter_logs(raw_logs);
        if filtered_logs.len() != raw_logs_len {
            println!(
                "Filtered out {} logs with unknown event signature",
                raw_logs_len - filtered_logs.len()
            );
        }

        for event in filtered_logs {
            match event {
                ShielderContractEvents::DepositNative(event) => {
                    if id_hidings.contains(&u256_to_field(event.idHiding)) {
                        deposits.push(event);
                    }
                }
                ShielderContractEvents::WithdrawNative(event) => {
                    if id_hidings.contains(&u256_to_field(event.idHiding)) {
                        withdrawals.push(event);
                    }
                }
                _ => {}
            }
        }
    }

    println!(
        "Found {} deposits and {} withdrawals",
        deposits.len(),
        withdrawals.len()
    );

    Ok(())
}

/// Look at `logs` and reject all logs that:
/// - have unknown event signature, or
/// - are not of type `NewAccount`, `Deposit`, or `Withdraw`.
///
/// Decode the rest of the logs and return them as a vector of `ShielderContractEvents`.
fn filter_logs(logs: Vec<Log>) -> Vec<ShielderContractEvents> {
    logs.into_iter()
        .filter_map(|event| {
            let shielder_event = match *event.topic0()? {
                NewAccountNative::SIGNATURE_HASH => {
                    NewAccountNative::decode_log_data(event.data(), true)
                        .map(ShielderContractEvents::NewAccountNative)
                }
                DepositNative::SIGNATURE_HASH => DepositNative::decode_log_data(event.data(), true)
                    .map(ShielderContractEvents::DepositNative),
                WithdrawNative::SIGNATURE_HASH => {
                    WithdrawNative::decode_log_data(event.data(), true)
                        .map(ShielderContractEvents::WithdrawNative)
                }
                _ => Err(Error::Overrun), // This is a placeholder error, will be ignored anyway.
            }
            .ok()?;
            Some(shielder_event)
        })
        .collect()
}
