use std::{fs, path::Path};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::{consensus::encode::serialize, psbt::Psbt};

use super::{
    common_limitations, complexity, summary, warning, ArtifactType, OutputAnalysis, PsbtAnalysis,
    RiskLevel, RiskReport, ScriptSignals,
};
use crate::analyzer::script::{
    analyze_script_bytes, classify_script, dust_threshold_sats, script_address,
};

pub fn analyze_psbt_file(path: &Path) -> Result<RiskReport> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read PSBT input {}", path.display()))?;
    let bytes = STANDARD
        .decode(raw.trim())
        .context("PSBT must be base64 encoded")?;
    let psbt = Psbt::deserialize(&bytes).context("PSBT bytes are not a valid BIP174 PSBT")?;

    Ok(analyze_psbt(&psbt))
}

fn analyze_psbt(psbt: &Psbt) -> RiskReport {
    let tx = &psbt.unsigned_tx;
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

    let inputs_with_witness_utxo = psbt
        .inputs
        .iter()
        .filter(|input| input.witness_utxo.is_some())
        .count();
    let inputs_with_non_witness_utxo = psbt
        .inputs
        .iter()
        .filter(|input| input.non_witness_utxo.is_some())
        .count();
    let output_value_sats: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();
    let estimated_fee_sats = estimate_psbt_fee(psbt, output_value_sats);
    let signals = psbt_signals(psbt);

    let mut warnings = Vec::new();
    let mut missing_data = Vec::new();

    if estimated_fee_sats.is_none() {
        missing_data.push("witness_utxo or non_witness_utxo for every PSBT input".to_owned());
        warnings.push(warning(
            "missing-utxo-data",
            RiskLevel::Medium,
            "Cannot estimate fee",
            "The PSBT does not include enough UTXO data for every input. Fee and economic risk analysis remain partial.",
        ));
    }

    if outputs.iter().any(|output| output.is_dust) {
        warnings.push(warning(
            "dust-output",
            RiskLevel::Medium,
            "Dust-like output detected",
            "At least one non-zero output is below the heuristic dust threshold for its script type.",
        ));
    }

    if estimated_fee_sats.is_some_and(|fee| fee < 0) {
        warnings.push(warning(
            "negative-fee",
            RiskLevel::High,
            "UTXO data implies a negative fee",
            "The PSBT input UTXO values are lower than the unsigned transaction outputs. Review PSBT consistency before proceeding.",
        ));
    }

    if signals.multisig {
        warnings.push(warning(
            "multisig-signal",
            RiskLevel::Low,
            "Multisig signal detected",
            "The PSBT contains script data or partial signatures consistent with multisig policy. Review threshold, signer set, and recovery paths.",
        ));
    }

    if signals.timelock || signals.relative_timelock {
        warnings.push(warning(
            "timelock-signal",
            RiskLevel::Medium,
            "Timelock signal detected",
            "The PSBT contains transaction-level or script-level timelock signals. Confirm intended settlement timing.",
        ));
    }

    let complexity = complexity(
        psbt_complexity_score(psbt, &signals),
        vec![
            format!("{} inputs", tx.input.len()),
            format!("{} outputs", tx.output.len()),
            format!("{} unsigned transaction bytes", serialize(tx).len()),
            format!("{} PSBT input maps", psbt.inputs.len()),
        ],
    );

    let mut summary_items = vec![
        summary("inputs", tx.input.len()),
        summary("outputs", tx.output.len()),
        summary("inputs_with_witness_utxo", inputs_with_witness_utxo),
        summary("inputs_with_non_witness_utxo", inputs_with_non_witness_utxo),
    ];
    if let Some(fee) = estimated_fee_sats {
        summary_items.push(summary("estimated_fee_sats", fee));
    }

    let risk = RiskLevel::from_warnings(&warnings, &missing_data);
    RiskReport {
        artifact_type: ArtifactType::Psbt,
        risk,
        summary: summary_items,
        warnings,
        missing_data,
        limitations: common_limitations(),
        transaction: None,
        psbt: Some(PsbtAnalysis {
            input_count: tx.input.len(),
            output_count: tx.output.len(),
            inputs_with_witness_utxo,
            inputs_with_non_witness_utxo,
            estimated_fee_sats,
            outputs,
            signals,
            complexity,
        }),
        script: None,
    }
}

fn estimate_psbt_fee(psbt: &Psbt, output_value_sats: u64) -> Option<i64> {
    let mut input_value = 0_u64;

    for (index, input) in psbt.inputs.iter().enumerate() {
        if let Some(witness_utxo) = &input.witness_utxo {
            input_value = input_value.saturating_add(witness_utxo.value.to_sat());
            continue;
        }

        let previous_output = psbt.unsigned_tx.input.get(index)?.previous_output;
        let non_witness_utxo = input.non_witness_utxo.as_ref()?;
        let previous_txout = non_witness_utxo.output.get(previous_output.vout as usize)?;
        input_value = input_value.saturating_add(previous_txout.value.to_sat());
    }

    Some(input_value as i64 - output_value_sats as i64)
}

fn psbt_signals(psbt: &Psbt) -> ScriptSignals {
    let tx = &psbt.unsigned_tx;
    let mut signals = ScriptSignals {
        timelock: tx.lock_time.to_consensus_u32() > 0,
        relative_timelock: tx
            .input
            .iter()
            .any(|input| input.sequence.to_consensus_u32() < 0xffff_ffff),
        op_return: tx
            .output
            .iter()
            .any(|output| classify_script(&output.script_pubkey) == "op_return"),
        ..ScriptSignals::default()
    };

    for input in &psbt.inputs {
        if input.partial_sigs.len() > 1 {
            signals.multisig = true;
        }

        for script in [&input.redeem_script, &input.witness_script]
            .into_iter()
            .flatten()
        {
            let analysis = analyze_script_bytes(script.as_bytes());
            signals.multisig |= analysis.signals.multisig;
            signals.timelock |= analysis.signals.timelock;
            signals.relative_timelock |= analysis.signals.relative_timelock;
        }
    }

    signals
}

fn psbt_complexity_score(psbt: &Psbt, signals: &ScriptSignals) -> u32 {
    let mut score = 0;
    score += psbt.unsigned_tx.input.len().saturating_sub(1) as u32;
    score += psbt.unsigned_tx.output.len().saturating_sub(1) as u32;
    score += psbt
        .inputs
        .iter()
        .filter(|input| input.redeem_script.is_some() || input.witness_script.is_some())
        .count() as u32;
    score += u32::from(signals.multisig) * 2;
    score += u32::from(signals.timelock || signals.relative_timelock) * 2;
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf, TxOut};

    fn minimal_psbt() -> Psbt {
        let bytes = STANDARD
            .decode("cHNidP8BAHECAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AugDAAAAAAAAFgAUAAAAAAAAAAAAAAAAAAAAAAAAAABkAAAAAAAAABYAFBERERERERERERERERERERERERERAAAAAAAAAAA=")
            .unwrap();

        Psbt::deserialize(&bytes).unwrap()
    }

    #[test]
    fn parses_minimal_psbt() {
        let psbt = minimal_psbt();

        let report = analyze_psbt(&psbt);

        assert_eq!(report.psbt.unwrap().input_count, 1);
        assert_eq!(report.risk, RiskLevel::Medium);
    }

    #[test]
    fn warns_when_witness_utxo_implies_negative_fee() {
        let mut psbt = minimal_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        });

        let report = analyze_psbt(&psbt);

        assert_eq!(report.psbt.unwrap().estimated_fee_sats, Some(-100));
        assert_eq!(report.risk, RiskLevel::High);
        assert!(report.missing_data.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.code == "negative-fee"));
    }
}
