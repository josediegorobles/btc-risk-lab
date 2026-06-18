use std::{fs, path::Path};

use anyhow::{Context, Result};
use bitcoin::{consensus::encode::deserialize, Transaction};
use serde::{Deserialize, Serialize};

use super::{
    common_limitations, complexity, summary, warning, ArtifactType, OutputAnalysis, RiskLevel,
    RiskReport, ScriptSignals, TransactionAnalysis,
};
use crate::analyzer::script::{
    analyze_script_bytes, classify_script, contains_multisig, contains_timelock,
    dust_threshold_sats, script_address,
};

#[derive(Debug, Deserialize)]
struct TransactionInputFile {
    hex: String,
    #[serde(default)]
    prevouts: Vec<PrevoutInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrevoutInput {
    pub value_sats: u64,
    pub script_pubkey: Option<String>,
}

pub fn analyze_transaction_file(path: &Path) -> Result<RiskReport> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read transaction input {}", path.display()))?;
    let input: TransactionInputFile =
        serde_json::from_str(&raw).context("transaction input must be JSON with a `hex` field")?;
    analyze_transaction_hex_with_prevouts(&input.hex, &input.prevouts, None)
}

pub fn analyze_transaction_hex(hex: &str) -> Result<RiskReport> {
    analyze_transaction_hex_with_prevouts(hex, &[], None)
}

pub fn analyze_transaction_hex_with_prevouts(
    hex: &str,
    prevouts: &[PrevoutInput],
    known_fee_sats: Option<i64>,
) -> Result<RiskReport> {
    let tx_bytes = hex::decode(hex.trim()).context("transaction hex is not valid hex")?;
    let tx: Transaction =
        deserialize(&tx_bytes).context("transaction hex is not a valid Bitcoin transaction")?;

    Ok(analyze_transaction(&tx, prevouts, known_fee_sats))
}

fn analyze_transaction(
    tx: &Transaction,
    prevouts: &[PrevoutInput],
    known_fee_sats: Option<i64>,
) -> RiskReport {
    let outputs = tx
        .output
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let value_sats = output.value.to_sat();
            let script_type = classify_script(&output.script_pubkey);
            OutputAnalysis {
                index,
                value_sats,
                address: script_address(&output.script_pubkey),
                is_dust: value_sats > 0 && value_sats < dust_threshold_sats(&script_type),
                script_type,
            }
        })
        .collect::<Vec<_>>();

    let output_value_sats = tx.output.iter().map(|output| output.value.to_sat()).sum();
    let estimated_fee_sats = if prevouts.len() == tx.input.len() {
        let input_value: u64 = prevouts.iter().map(|prevout| prevout.value_sats).sum();
        Some(input_value as i64 - output_value_sats as i64)
    } else {
        known_fee_sats
    };

    let signals = transaction_signals(tx, &outputs, prevouts);
    let mut warnings = Vec::new();
    let mut missing_data = Vec::new();

    if prevouts.len() != tx.input.len() && estimated_fee_sats.is_none() {
        missing_data.push("prevout values for every input".to_owned());
        warnings.push(warning(
            "missing-prevouts",
            RiskLevel::Medium,
            "Cannot estimate fee",
            "A Bitcoin transaction does not carry the value of the UTXOs it spends. Provide prevout data to estimate fee and stronger economic risk signals.",
        ));
    }

    if outputs.iter().any(|output| output.is_dust) {
        warnings.push(warning(
            "dust-output",
            RiskLevel::Medium,
            "Dust-like output detected",
            "At least one non-zero output is below the heuristic dust threshold for its script type. This can indicate uneconomic outputs, spam-like construction, or operational mistakes.",
        ));
    }

    if estimated_fee_sats.is_some_and(|fee| fee < 0) {
        warnings.push(warning(
            "negative-fee",
            RiskLevel::High,
            "Prevout data implies a negative fee",
            "The provided input values are lower than the transaction outputs. This usually means the prevout data is incomplete or inconsistent.",
        ));
    }

    if signals.multisig {
        warnings.push(warning(
            "multisig-signal",
            RiskLevel::Low,
            "Multisig signal detected",
            "A script path appears to contain CHECKMULTISIG. Review signer policy, threshold, and recovery assumptions before relying on this artifact.",
        ));
    }

    if signals.timelock || signals.relative_timelock {
        warnings.push(warning(
            "timelock-signal",
            RiskLevel::Medium,
            "Timelock signal detected",
            "The transaction or script data includes absolute or relative timelock signals. Confirm the intended spending window and dependency on block height or median time.",
        ));
    }

    let complexity = complexity(
        complexity_score(tx, &signals),
        vec![
            format!("{} inputs", tx.input.len()),
            format!("{} outputs", tx.output.len()),
            format!(
                "{} serialized bytes",
                bitcoin::consensus::encode::serialize(tx).len()
            ),
        ],
    );

    let mut summary_items = vec![
        summary("inputs", tx.input.len()),
        summary("outputs", tx.output.len()),
        summary("output_value_sats", output_value_sats),
    ];
    if let Some(fee) = estimated_fee_sats {
        summary_items.push(summary("estimated_fee_sats", fee));
    }

    let risk = RiskLevel::from_warnings(&warnings, &missing_data);
    RiskReport {
        artifact_type: ArtifactType::Transaction,
        risk,
        summary: summary_items,
        warnings,
        missing_data,
        limitations: common_limitations(),
        transaction: Some(TransactionAnalysis {
            input_count: tx.input.len(),
            output_count: tx.output.len(),
            output_value_sats,
            estimated_fee_sats,
            outputs,
            signals,
            complexity,
        }),
        psbt: None,
        script: None,
    }
}

fn transaction_signals(
    tx: &Transaction,
    outputs: &[OutputAnalysis],
    prevouts: &[PrevoutInput],
) -> ScriptSignals {
    let mut signals = ScriptSignals {
        timelock: tx.lock_time.to_consensus_u32() > 0,
        relative_timelock: tx
            .input
            .iter()
            .any(|input| input.sequence.to_consensus_u32() < 0xffff_ffff),
        op_return: outputs
            .iter()
            .any(|output| output.script_type == "op_return"),
        ..ScriptSignals::default()
    };

    for input in &tx.input {
        let script_sig = input.script_sig.as_bytes();
        signals.multisig |= contains_multisig(script_sig);
        signals.timelock |= contains_timelock(script_sig).absolute;
        signals.relative_timelock |= contains_timelock(script_sig).relative;

        for witness_item in input.witness.iter() {
            signals.multisig |= contains_multisig(witness_item);
            signals.timelock |= contains_timelock(witness_item).absolute;
            signals.relative_timelock |= contains_timelock(witness_item).relative;
        }
    }

    for prevout in prevouts {
        if let Some(script_pubkey) = &prevout.script_pubkey {
            if let Ok(bytes) = hex::decode(script_pubkey) {
                let script = analyze_script_bytes(&bytes);
                signals.multisig |= script.signals.multisig;
                signals.timelock |= script.signals.timelock;
                signals.relative_timelock |= script.signals.relative_timelock;
            }
        }
    }

    signals
}

fn complexity_score(tx: &Transaction, signals: &ScriptSignals) -> u32 {
    let mut score = 0;
    score += tx.input.len().saturating_sub(1) as u32;
    score += tx.output.len().saturating_sub(1) as u32;
    score += u32::from(signals.multisig) * 2;
    score += u32::from(signals.timelock || signals.relative_timelock) * 2;
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TX_HEX: &str = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff02e80300000000000016001400000000000000000000000000000000000000006400000000000000160014111111111111111111111111111111111111111100000000";

    fn sample_tx() -> Transaction {
        deserialize(&hex::decode(SAMPLE_TX_HEX).unwrap()).unwrap()
    }

    #[test]
    fn estimates_fee_when_prevouts_are_present() {
        let input = TransactionInputFile {
            hex: SAMPLE_TX_HEX.to_owned(),
            prevouts: vec![PrevoutInput {
                value_sats: 2_000,
                script_pubkey: None,
            }],
        };
        let tx = sample_tx();

        let report = analyze_transaction(&tx, &input.prevouts, None);

        assert_eq!(report.transaction.unwrap().estimated_fee_sats, Some(900));
        assert_eq!(report.risk, RiskLevel::Medium);
    }

    #[test]
    fn direct_hex_reports_fee_unavailable_without_prevouts() {
        let report = analyze_transaction_hex(SAMPLE_TX_HEX).unwrap();

        let tx = report.transaction.unwrap();
        assert_eq!(tx.estimated_fee_sats, None);
        assert!(report
            .missing_data
            .contains(&"prevout values for every input".to_owned()));
    }

    #[test]
    fn warns_when_prevouts_imply_negative_fee() {
        let tx = sample_tx();
        let prevouts = vec![PrevoutInput {
            value_sats: 1_000,
            script_pubkey: None,
        }];

        let report = analyze_transaction(&tx, &prevouts, None);

        assert_eq!(report.transaction.unwrap().estimated_fee_sats, Some(-100));
        assert_eq!(report.risk, RiskLevel::High);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.code == "negative-fee"));
    }

    #[test]
    fn detects_multisig_and_timelock_from_prevout_script_pubkeys() {
        let tx = sample_tx();
        let prevouts = vec![PrevoutInput {
            value_sats: 2_000,
            script_pubkey: Some("52aeb2".to_owned()),
        }];

        let report = analyze_transaction(&tx, &prevouts, None);
        let analysis = report.transaction.unwrap();

        assert!(analysis.signals.multisig);
        assert!(analysis.signals.relative_timelock);
        assert_eq!(report.risk, RiskLevel::Medium);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.code == "multisig-signal"));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.code == "timelock-signal"));
    }
}
