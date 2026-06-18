use std::str::FromStr;

use anyhow::{bail, Context, Result};
use bitcoin::PublicKey;
use miniscript::{descriptor::DescriptorType, Descriptor};

use super::{
    common_limitations, complexity, summary, warning, ArtifactType, DescriptorAnalysis, RiskLevel,
    RiskReport, ScriptSignals,
};
use crate::analyzer::script::{analyze_script_bytes, classify_script};

pub fn analyze_descriptor_input(input: &str) -> Result<RiskReport> {
    let descriptor = input.trim();
    if descriptor.is_empty() {
        bail!("descriptor cannot be empty");
    }

    let descriptor = Descriptor::<PublicKey>::from_str(descriptor)
        .context("descriptor input is not a valid public-key output descriptor")?;

    Ok(analyze_descriptor(&descriptor))
}

fn analyze_descriptor(descriptor: &Descriptor<PublicKey>) -> RiskReport {
    let descriptor_type = descriptor_type_name(descriptor.desc_type()).to_owned();
    let script_pubkey = descriptor.script_pubkey();
    let script_type = classify_script(&script_pubkey);
    let sanity_check = descriptor.sanity_check().is_ok();
    let max_satisfaction_weight_wu = descriptor
        .max_weight_to_satisfy()
        .ok()
        .map(|weight| weight.to_wu());
    let signals = descriptor_signals(descriptor);

    let mut warnings = Vec::new();
    let missing_data = Vec::new();

    if !sanity_check {
        warnings.push(warning(
            "descriptor-sanity-check",
            RiskLevel::Medium,
            "Descriptor sanity check failed",
            "Miniscript parsed the descriptor, but its safety checks did not pass. Review spend paths, malleability, and standardness assumptions before operational use.",
        ));
    }

    if signals.multisig || signals.threshold {
        warnings.push(warning(
            "threshold-policy",
            RiskLevel::Low,
            "Threshold or multisig policy detected",
            "The descriptor includes threshold-like signing policy. Review signer count, quorum, backup paths, and key origin documentation.",
        ));
    }

    if signals.timelock || signals.relative_timelock {
        warnings.push(warning(
            "timelock-signal",
            RiskLevel::Medium,
            "Timelock signal detected",
            "The descriptor contains absolute or relative timelock policy. Confirm block height, median time, and sequence assumptions before relying on it.",
        ));
    }

    let complexity = descriptor_complexity(&descriptor_type, &signals);
    let mut summary_items = vec![
        summary("descriptor_type", &descriptor_type),
        summary("script_type", &script_type),
        summary("sanity_check", sanity_check),
    ];
    if let Some(weight) = max_satisfaction_weight_wu {
        summary_items.push(summary("max_satisfaction_weight_wu", weight));
    }

    let risk = RiskLevel::from_warnings(&warnings, &missing_data);
    RiskReport {
        schema_version: super::REPORT_SCHEMA_VERSION.to_owned(),
        artifact_type: ArtifactType::Descriptor,
        risk,
        summary: summary_items,
        warnings,
        missing_data,
        limitations: common_limitations(),
        transaction: None,
        psbt: None,
        script: None,
        descriptor: Some(DescriptorAnalysis {
            descriptor_type,
            script_type,
            sanity_check,
            max_satisfaction_weight_wu,
            signals,
            complexity,
        }),
    }
}

fn descriptor_signals(descriptor: &Descriptor<PublicKey>) -> ScriptSignals {
    let normalized = descriptor.to_string();
    let mut signals = descriptor
        .explicit_script()
        .map(|script| analyze_script_bytes(script.as_bytes()).signals)
        .unwrap_or_default();

    signals.multisig |= has_any(&normalized, &["multi(", "sortedmulti(", "multi_a("]);
    signals.threshold |= has_any(
        &normalized,
        &["thresh(", "multi(", "sortedmulti(", "multi_a("],
    );
    signals.timelock |= normalized.contains("after(");
    signals.relative_timelock |= normalized.contains("older(");
    signals
}

fn has_any(input: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| input.contains(needle))
}

fn descriptor_complexity(descriptor_type: &str, signals: &ScriptSignals) -> super::Complexity {
    let mut score = 0;
    let mut factors = vec![format!("descriptor type {descriptor_type}")];

    if descriptor_type.contains("wsh") || descriptor_type.contains("sh_") {
        score += 1;
        factors.push("wrapped or witness script descriptor".to_owned());
    }

    if signals.multisig || signals.threshold {
        score += 2;
        factors.push("threshold policy detected".to_owned());
    }

    if signals.timelock || signals.relative_timelock {
        score += 2;
        factors.push("timelock policy detected".to_owned());
    }

    complexity(score, factors)
}

fn descriptor_type_name(descriptor_type: DescriptorType) -> &'static str {
    match descriptor_type {
        DescriptorType::Bare => "bare",
        DescriptorType::Sh => "sh",
        DescriptorType::Pkh => "pkh",
        DescriptorType::Wpkh => "wpkh",
        DescriptorType::Wsh => "wsh",
        DescriptorType::ShWsh => "sh_wsh",
        DescriptorType::ShWpkh => "sh_wpkh",
        DescriptorType::ShSortedMulti => "sh_sortedmulti",
        DescriptorType::WshSortedMulti => "wsh_sortedmulti",
        DescriptorType::ShWshSortedMulti => "sh_wsh_sortedmulti",
        DescriptorType::Tr => "tr",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_simple_descriptor_fixture() {
        let report =
            analyze_descriptor_input(include_str!("../../tests/fixtures/descriptors/simple.txt"))
                .unwrap();
        let analysis = report.descriptor.unwrap();

        assert_eq!(report.schema_version, "0.3");
        assert_eq!(analysis.descriptor_type, "wpkh");
        assert_eq!(analysis.script_type, "p2wpkh");
        assert!(analysis.sanity_check);
        assert!(analysis.max_satisfaction_weight_wu.is_some());
        assert!(!analysis.signals.multisig);
        assert_eq!(report.risk, RiskLevel::Low);
    }

    #[test]
    fn analyzes_sortedmulti_descriptor_fixture() {
        let report = analyze_descriptor_input(include_str!(
            "../../tests/fixtures/descriptors/sortedmulti.txt"
        ))
        .unwrap();
        let analysis = report.descriptor.unwrap();

        assert_eq!(analysis.descriptor_type, "wsh_sortedmulti");
        assert_eq!(analysis.script_type, "p2wsh");
        assert!(analysis.signals.multisig);
        assert!(analysis.signals.threshold);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.code == "threshold-policy"));
    }

    #[test]
    fn analyzes_timelock_descriptor_fixture() {
        let report = analyze_descriptor_input(include_str!(
            "../../tests/fixtures/descriptors/timelock.txt"
        ))
        .unwrap();
        let analysis = report.descriptor.unwrap();

        assert_eq!(analysis.descriptor_type, "wsh");
        assert!(analysis.signals.relative_timelock);
        assert_eq!(report.risk, RiskLevel::Medium);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.code == "timelock-signal"));
    }

    #[test]
    fn rejects_invalid_descriptor_fixture() {
        let err =
            analyze_descriptor_input(include_str!("../../tests/fixtures/descriptors/invalid.txt"))
                .unwrap_err();

        assert!(err
            .to_string()
            .contains("descriptor input is not a valid public-key output descriptor"));
    }
}
