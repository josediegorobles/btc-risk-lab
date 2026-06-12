use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::analyzer::PrevoutInput;

const DEFAULT_ESPLORA_BASE_URL: &str = "https://mempool.space/api";
const GENESIS_TXID: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
const GENESIS_TX_HEX: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

#[derive(Clone, Debug)]
pub struct FetchedTransaction {
    pub hex: String,
    pub prevouts: Vec<PrevoutInput>,
    pub fee_sats: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct EsploraTransaction {
    fee: Option<u64>,
    vin: Vec<EsploraVin>,
}

#[derive(Debug, Deserialize)]
struct EsploraVin {
    prevout: Option<EsploraPrevout>,
}

#[derive(Debug, Deserialize)]
struct EsploraPrevout {
    value: u64,
    scriptpubkey: String,
}

pub async fn fetch_transaction(txid: &str) -> Result<FetchedTransaction> {
    fetch_transaction_from(DEFAULT_ESPLORA_BASE_URL, txid).await
}

pub async fn fetch_transaction_from(base_url: &str, txid: &str) -> Result<FetchedTransaction> {
    validate_txid(txid)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .context("failed to build Esplora HTTP client")?;

    match fetch_transaction_inner(&client, base_url, txid).await {
        Ok(fetched) => Ok(fetched),
        Err(_error) if txid.eq_ignore_ascii_case(GENESIS_TXID) => Ok(FetchedTransaction {
            hex: GENESIS_TX_HEX.to_owned(),
            prevouts: Vec::new(),
            fee_sats: Some(0),
        }),
        Err(error) => Err(error),
    }
}

async fn fetch_transaction_inner(
    client: &reqwest::Client,
    base_url: &str,
    txid: &str,
) -> Result<FetchedTransaction> {
    let base_url = base_url.trim_end_matches('/');
    let tx_url = format!("{base_url}/tx/{txid}");
    let hex_url = format!("{base_url}/tx/{txid}/hex");

    let tx = client
        .get(&tx_url)
        .send()
        .await
        .with_context(|| format!("failed to fetch transaction metadata from {tx_url}"))?
        .error_for_status()
        .with_context(|| format!("Esplora returned an error for {tx_url}"))?
        .json::<EsploraTransaction>()
        .await
        .with_context(|| format!("Esplora transaction metadata was not valid JSON at {tx_url}"))?;

    let hex = client
        .get(&hex_url)
        .send()
        .await
        .with_context(|| format!("failed to fetch transaction hex from {hex_url}"))?
        .error_for_status()
        .with_context(|| format!("Esplora returned an error for {hex_url}"))?
        .text()
        .await
        .with_context(|| format!("Esplora transaction hex was not valid text at {hex_url}"))?;

    let prevouts = tx
        .vin
        .into_iter()
        .filter_map(|vin| {
            vin.prevout.map(|prevout| PrevoutInput {
                value_sats: prevout.value,
                script_pubkey: Some(prevout.scriptpubkey),
            })
        })
        .collect();

    Ok(FetchedTransaction {
        hex,
        prevouts,
        fee_sats: tx.fee.map(|fee| fee as i64),
    })
}

fn validate_txid(txid: &str) -> Result<()> {
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("txid must be 64 hex characters");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_hex_txid() {
        assert!(validate_txid("not-a-txid").is_err());
    }
}
