use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::analyzer::{
    self, DescriptorAnalysis, PsbtAnalysis, RiskLevel, RiskReport, RiskWarning, ScriptSignals,
    SummaryItem, TransactionAnalysis,
};

const REVIEW_PACK_SCHEMA_VERSION: &str = "0.4";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReviewPackReport {
    pub schema_version: String,
    pub artifacts_detected: Vec<DetectedArtifact>,
    pub per_artifact_summary: Vec<ArtifactSummary>,
    pub consolidated_risk: RiskLevel,
    pub warnings: Vec<RiskWarning>,
    pub missing_data: Vec<String>,
    pub cross_artifact_findings: Vec<CrossArtifactFinding>,
    pub review_questions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DetectedArtifact {
    pub artifact: String,
    pub file: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArtifactSummary {
    pub artifact: String,
    pub status: ArtifactStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskLevel>,
    pub summary: Vec<SummaryItem>,
    pub warnings: Vec<RiskWarning>,
    pub missing_data: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Analyzed,
    Read,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrossArtifactFinding {
    pub code: String,
    pub severity: RiskLevel,
    pub title: String,
    pub explanation: String,
}

#[derive(Default)]
struct AnalyzedArtifacts {
    transaction: Option<TransactionAnalysis>,
    psbt: Option<PsbtAnalysis>,
    descriptor: Option<DescriptorAnalysis>,
    script_signals: Option<ScriptSignals>,
}

pub fn analyze_review_pack(input_dir: &Path) -> Result<ReviewPackReport> {
    if !input_dir.is_dir() {
        bail!(
            "review pack input must be a directory: {}",
            input_dir.display()
        );
    }

    let mut artifacts_detected = Vec::new();
    let mut per_artifact_summary = Vec::new();
    let mut warnings = Vec::new();
    let mut missing_data = Vec::new();
    let mut analyzed = AnalyzedArtifacts::default();

    read_descriptor(
        input_dir,
        &mut artifacts_detected,
        &mut per_artifact_summary,
        &mut warnings,
        &mut missing_data,
        &mut analyzed,
    )?;
    read_psbt(
        input_dir,
        &mut artifacts_detected,
        &mut per_artifact_summary,
        &mut warnings,
        &mut missing_data,
        &mut analyzed,
    );
    read_transaction(
        input_dir,
        &mut artifacts_detected,
        &mut per_artifact_summary,
        &mut warnings,
        &mut missing_data,
        &mut analyzed,
    );
    read_script(
        input_dir,
        &mut artifacts_detected,
        &mut per_artifact_summary,
        &mut warnings,
        &mut missing_data,
        &mut analyzed,
    )?;
    read_policy(
        input_dir,
        &mut artifacts_detected,
        &mut per_artifact_summary,
        &mut warnings,
        &mut missing_data,
    )?;
    read_notes(
        input_dir,
        &mut artifacts_detected,
        &mut per_artifact_summary,
    )?;

    add_absent_artifact_context(input_dir, &mut missing_data);

    let cross_artifact_findings = cross_artifact_findings(&analyzed);
    for finding in &cross_artifact_findings {
        if finding.severity != RiskLevel::Low {
            warnings.push(RiskWarning {
                code: finding.code.clone(),
                severity: finding.severity.clone(),
                title: finding.title.clone(),
                explanation: finding.explanation.clone(),
            });
        }
    }

    for finding in &cross_artifact_findings {
        if finding.code.contains("cannot-verify") || finding.code.contains("threshold-unavailable")
        {
            missing_data.push(finding.explanation.clone());
        }
    }

    let review_questions = review_questions(&analyzed, &artifacts_detected, &missing_data);
    let limitations = limitations(&analyzed);
    let consolidated_risk = consolidated_risk(&warnings, &missing_data);

    Ok(ReviewPackReport {
        schema_version: REVIEW_PACK_SCHEMA_VERSION.to_owned(),
        artifacts_detected,
        per_artifact_summary,
        consolidated_risk,
        warnings,
        missing_data: dedupe(missing_data),
        cross_artifact_findings,
        review_questions,
        limitations,
    })
}

fn read_descriptor(
    input_dir: &Path,
    artifacts: &mut Vec<DetectedArtifact>,
    summaries: &mut Vec<ArtifactSummary>,
    warnings: &mut Vec<RiskWarning>,
    missing_data: &mut Vec<String>,
    analyzed: &mut AnalyzedArtifacts,
) -> Result<()> {
    let path = input_dir.join("descriptor.txt");
    if !path.exists() {
        return Ok(());
    }

    artifacts.push(detected("descriptor", &path));
    let input = fs::read_to_string(&path)
        .with_context(|| format!("failed to read descriptor input {}", path.display()))?;

    match analyzer::analyze_descriptor_input(&input) {
        Ok(report) => {
            analyzed.descriptor = report.descriptor.clone();
            push_report_summary("descriptor", report, summaries, warnings, missing_data);
        }
        Err(error) => push_error_summary(
            "descriptor",
            error.to_string(),
            "descriptor-analysis-error",
            summaries,
            warnings,
            missing_data,
        ),
    }

    Ok(())
}

fn read_psbt(
    input_dir: &Path,
    artifacts: &mut Vec<DetectedArtifact>,
    summaries: &mut Vec<ArtifactSummary>,
    warnings: &mut Vec<RiskWarning>,
    missing_data: &mut Vec<String>,
    analyzed: &mut AnalyzedArtifacts,
) {
    let path = input_dir.join("psbt.base64");
    if !path.exists() {
        return;
    }

    artifacts.push(detected("psbt", &path));
    match analyzer::analyze_psbt_file(&path) {
        Ok(report) => {
            analyzed.psbt = report.psbt.clone();
            push_report_summary("psbt", report, summaries, warnings, missing_data);
        }
        Err(error) => push_error_summary(
            "psbt",
            error.to_string(),
            "psbt-analysis-error",
            summaries,
            warnings,
            missing_data,
        ),
    }
}

fn read_transaction(
    input_dir: &Path,
    artifacts: &mut Vec<DetectedArtifact>,
    summaries: &mut Vec<ArtifactSummary>,
    warnings: &mut Vec<RiskWarning>,
    missing_data: &mut Vec<String>,
    analyzed: &mut AnalyzedArtifacts,
) {
    let path = input_dir.join("tx.json");
    if !path.exists() {
        return;
    }

    artifacts.push(detected("transaction", &path));
    match analyzer::analyze_transaction_file(&path) {
        Ok(report) => {
            analyzed.transaction = report.transaction.clone();
            push_report_summary("transaction", report, summaries, warnings, missing_data);
        }
        Err(error) => push_error_summary(
            "transaction",
            error.to_string(),
            "tx-analysis-error",
            summaries,
            warnings,
            missing_data,
        ),
    }
}

fn read_script(
    input_dir: &Path,
    artifacts: &mut Vec<DetectedArtifact>,
    summaries: &mut Vec<ArtifactSummary>,
    warnings: &mut Vec<RiskWarning>,
    missing_data: &mut Vec<String>,
    analyzed: &mut AnalyzedArtifacts,
) -> Result<()> {
    let path = input_dir.join("script.txt");
    if !path.exists() {
        return Ok(());
    }

    artifacts.push(detected("script", &path));
    let input = fs::read_to_string(&path)
        .with_context(|| format!("failed to read script input {}", path.display()))?;

    match analyzer::analyze_script_input(&input) {
        Ok(report) => {
            analyzed.script_signals = report.script.as_ref().map(|script| script.signals.clone());
            push_report_summary("script", report, summaries, warnings, missing_data);
        }
        Err(error) => push_error_summary(
            "script",
            error.to_string(),
            "script-analysis-error",
            summaries,
            warnings,
            missing_data,
        ),
    }

    Ok(())
}

fn read_policy(
    input_dir: &Path,
    artifacts: &mut Vec<DetectedArtifact>,
    summaries: &mut Vec<ArtifactSummary>,
    warnings: &mut Vec<RiskWarning>,
    missing_data: &mut Vec<String>,
) -> Result<()> {
    let path = input_dir.join("policy.json");
    if !path.exists() {
        return Ok(());
    }

    artifacts.push(detected("policy", &path));
    let input = fs::read_to_string(&path)
        .with_context(|| format!("failed to read policy notes {}", path.display()))?;

    match serde_json::from_str::<Value>(&input) {
        Ok(value) => summaries.push(ArtifactSummary {
            artifact: "policy".to_owned(),
            status: ArtifactStatus::Read,
            risk: None,
            summary: policy_summary(&value),
            warnings: Vec::new(),
            missing_data: Vec::new(),
        }),
        Err(error) => push_error_summary(
            "policy",
            error.to_string(),
            "policy-json-error",
            summaries,
            warnings,
            missing_data,
        ),
    }

    Ok(())
}

fn read_notes(
    input_dir: &Path,
    artifacts: &mut Vec<DetectedArtifact>,
    summaries: &mut Vec<ArtifactSummary>,
) -> Result<()> {
    let path = input_dir.join("notes.md");
    if !path.exists() {
        return Ok(());
    }

    artifacts.push(detected("notes", &path));
    let input = fs::read_to_string(&path)
        .with_context(|| format!("failed to read review notes {}", path.display()))?;

    summaries.push(ArtifactSummary {
        artifact: "notes".to_owned(),
        status: ArtifactStatus::Read,
        risk: None,
        summary: vec![
            SummaryItem {
                label: "bytes".to_owned(),
                value: input.len().to_string(),
            },
            SummaryItem {
                label: "lines".to_owned(),
                value: input.lines().count().to_string(),
            },
        ],
        warnings: Vec::new(),
        missing_data: Vec::new(),
    });

    Ok(())
}

fn push_report_summary(
    artifact: &str,
    report: RiskReport,
    summaries: &mut Vec<ArtifactSummary>,
    warnings: &mut Vec<RiskWarning>,
    missing_data: &mut Vec<String>,
) {
    warnings.extend(report.warnings.iter().cloned().map(|warning| {
        let mut warning = warning;
        warning.code = format!("{artifact}:{}", warning.code);
        warning.title = format!("{}: {}", title_case(artifact), warning.title);
        warning
    }));

    missing_data.extend(
        report
            .missing_data
            .iter()
            .map(|item| format!("{artifact}: {item}")),
    );

    summaries.push(ArtifactSummary {
        artifact: artifact.to_owned(),
        status: ArtifactStatus::Analyzed,
        risk: Some(report.risk),
        summary: report.summary,
        warnings: report.warnings,
        missing_data: report.missing_data,
    });
}

fn push_error_summary(
    artifact: &str,
    error: String,
    code: &str,
    summaries: &mut Vec<ArtifactSummary>,
    warnings: &mut Vec<RiskWarning>,
    missing_data: &mut Vec<String>,
) {
    let warning = RiskWarning {
        code: code.to_owned(),
        severity: RiskLevel::High,
        title: format!("{} could not be analyzed", title_case(artifact)),
        explanation: error.clone(),
    };
    warnings.push(warning.clone());
    missing_data.push(format!("{artifact}: valid parseable artifact data"));
    summaries.push(ArtifactSummary {
        artifact: artifact.to_owned(),
        status: ArtifactStatus::Error,
        risk: Some(RiskLevel::High),
        summary: Vec::new(),
        warnings: vec![warning],
        missing_data: vec![error],
    });
}

fn add_absent_artifact_context(input_dir: &Path, missing_data: &mut Vec<String>) {
    for (file, message) in [
        (
            "descriptor.txt",
            "descriptor.txt not provided; descriptor-to-PSBT policy comparison is unavailable",
        ),
        (
            "psbt.base64",
            "psbt.base64 not provided; signing-state and PSBT-to-transaction comparison are unavailable",
        ),
        (
            "tx.json",
            "tx.json not provided; final transaction count comparison is unavailable",
        ),
    ] {
        if !input_dir.join(file).exists() {
            missing_data.push(message.to_owned());
        }
    }
}

fn cross_artifact_findings(analyzed: &AnalyzedArtifacts) -> Vec<CrossArtifactFinding> {
    let mut findings = Vec::new();

    match (&analyzed.descriptor, &analyzed.psbt) {
        (Some(descriptor), Some(psbt)) => {
            compare_signal(
                "descriptor-psbt-multisig",
                "Descriptor and PSBT multisig signals",
                descriptor.signals.multisig,
                psbt.signals.multisig,
                &mut findings,
            );
            compare_signal(
                "descriptor-psbt-timelock",
                "Descriptor and PSBT timelock signals",
                descriptor.signals.timelock || descriptor.signals.relative_timelock,
                psbt.signals.timelock || psbt.signals.relative_timelock,
                &mut findings,
            );

            if descriptor.signals.threshold {
                findings.push(CrossArtifactFinding {
                    code: "descriptor-psbt-threshold-unavailable".to_owned(),
                    severity: RiskLevel::Unknown,
                    title: "Descriptor threshold cannot be fully checked against PSBT".to_owned(),
                    explanation: "The descriptor exposes threshold policy, but the current PSBT analyzer only exposes heuristic multisig/script signals, not an exact quorum or signer set. Real descriptor-to-PSBT equivalence is not verified.".to_owned(),
                });
            }

            findings.push(CrossArtifactFinding {
                code: "descriptor-psbt-equivalence-not-verified".to_owned(),
                severity: RiskLevel::Unknown,
                title: "Descriptor-to-PSBT equivalence is not proven".to_owned(),
                explanation: "The review pack compares available policy signals only. It does not derive addresses, reconstruct wallet origin data, or prove that the PSBT spends from the provided descriptor.".to_owned(),
            });
        }
        (Some(_), None) => findings.push(missing_cross_finding(
            "descriptor-psbt-cannot-verify",
            "Descriptor present without PSBT",
            "A descriptor was provided, but psbt.base64 is missing or invalid, so descriptor-to-PSBT policy comparison cannot be performed.",
        )),
        (None, Some(_)) => findings.push(missing_cross_finding(
            "descriptor-psbt-cannot-verify",
            "PSBT present without descriptor",
            "A PSBT was provided, but descriptor.txt is missing or invalid, so descriptor-to-PSBT policy comparison cannot be performed.",
        )),
        (None, None) => {}
    }

    match (&analyzed.transaction, &analyzed.psbt) {
        (Some(transaction), Some(psbt)) => {
            if transaction.input_count == psbt.input_count
                && transaction.output_count == psbt.output_count
            {
                findings.push(CrossArtifactFinding {
                    code: "tx-psbt-counts-match".to_owned(),
                    severity: RiskLevel::Low,
                    title: "Transaction and PSBT counts match".to_owned(),
                    explanation: format!(
                        "Both artifacts report {} input(s) and {} output(s). This is a count-level check only, not transaction equivalence.",
                        transaction.input_count, transaction.output_count
                    ),
                });
            } else {
                findings.push(CrossArtifactFinding {
                    code: "tx-psbt-count-mismatch".to_owned(),
                    severity: RiskLevel::High,
                    title: "Transaction and PSBT counts differ".to_owned(),
                    explanation: format!(
                        "The transaction reports {} input(s)/{} output(s), while the PSBT reports {} input(s)/{} output(s). Review whether these artifacts belong to the same package.",
                        transaction.input_count,
                        transaction.output_count,
                        psbt.input_count,
                        psbt.output_count
                    ),
                });
            }

            findings.push(CrossArtifactFinding {
                code: "tx-psbt-equivalence-not-verified".to_owned(),
                severity: RiskLevel::Unknown,
                title: "Transaction-to-PSBT equivalence is not proven".to_owned(),
                explanation: "The review pack compares input/output counts only. It does not prove that tx.json is the finalized or extracted transaction for psbt.base64.".to_owned(),
            });
        }
        (Some(_), None) => findings.push(missing_cross_finding(
            "tx-psbt-cannot-verify",
            "Transaction present without PSBT",
            "tx.json was provided, but psbt.base64 is missing or invalid, so transaction-to-PSBT count comparison cannot be performed.",
        )),
        (None, Some(_)) => findings.push(missing_cross_finding(
            "tx-psbt-cannot-verify",
            "PSBT present without transaction",
            "psbt.base64 was provided, but tx.json is missing or invalid, so transaction-to-PSBT count comparison cannot be performed.",
        )),
        (None, None) => {}
    }

    findings
}

fn compare_signal(
    code: &str,
    title: &str,
    descriptor_signal: bool,
    psbt_signal: bool,
    findings: &mut Vec<CrossArtifactFinding>,
) {
    if descriptor_signal == psbt_signal {
        findings.push(CrossArtifactFinding {
            code: format!("{code}-match"),
            severity: RiskLevel::Low,
            title: format!("{title} match"),
            explanation: format!(
                "Both descriptor and PSBT expose `{descriptor_signal}` for this signal."
            ),
        });
    } else {
        findings.push(CrossArtifactFinding {
            code: format!("{code}-mismatch"),
            severity: RiskLevel::Medium,
            title: format!("{title} differ"),
            explanation: format!(
                "Descriptor signal is `{descriptor_signal}`, while PSBT signal is `{psbt_signal}`. This may be valid for incomplete PSBT data, but it requires manual review."
            ),
        });
    }
}

fn missing_cross_finding(code: &str, title: &str, explanation: &str) -> CrossArtifactFinding {
    CrossArtifactFinding {
        code: code.to_owned(),
        severity: RiskLevel::Unknown,
        title: title.to_owned(),
        explanation: explanation.to_owned(),
    }
}

fn review_questions(
    analyzed: &AnalyzedArtifacts,
    artifacts: &[DetectedArtifact],
    missing_data: &[String],
) -> Vec<String> {
    let mut questions = Vec::new();

    if analyzed.descriptor.is_some() || analyzed.psbt.is_some() {
        questions.push(
            "Do descriptor.txt, psbt.base64, and policy.json describe the same signer policy, quorum, and recovery assumptions?".to_owned(),
        );
    }

    if analyzed.transaction.is_some() || analyzed.psbt.is_some() {
        questions.push(
            "Have reviewers independently confirmed that input/output counts, destinations, amounts, and fees match the intended transaction?".to_owned(),
        );
    }

    if artifacts
        .iter()
        .any(|artifact| artifact.artifact == "policy")
    {
        questions.push(
            "Does policy.json define the expected threshold, timelocks, change handling, and approval path for this package?".to_owned(),
        );
    }

    if artifacts
        .iter()
        .any(|artifact| artifact.artifact == "notes")
    {
        questions.push(
            "Do notes.md explain the operational intent, known exceptions, and external evidence needed before approval?".to_owned(),
        );
    }

    if !missing_data.is_empty() {
        questions.push(
            "Which missing data must be collected before treating this review pack as complete?"
                .to_owned(),
        );
    }

    if questions.is_empty() {
        questions.push(
            "Which Bitcoin artifacts should be added to this directory before a meaningful review can begin?".to_owned(),
        );
    }

    dedupe(questions)
}

fn limitations(analyzed: &AnalyzedArtifacts) -> Vec<String> {
    let mut limitations = vec![
        "This is an explainability and reporting tool, not a consensus-level Bitcoin validator."
            .to_owned(),
        "The tool does not create wallets, sign transactions, custody funds, request seed phrases, handle private keys, or broadcast transactions."
            .to_owned(),
        "The review pack command performs local file analysis only and does not make network calls."
            .to_owned(),
        "Cross-artifact checks compare only signals and counts exposed by the existing analyzers."
            .to_owned(),
        "Real descriptor, PSBT, and transaction equivalence is not proven by this report.".to_owned(),
    ];

    if analyzed.descriptor.is_some() && analyzed.psbt.is_some() {
        limitations.push(
            "Descriptor-to-PSBT comparison does not validate key origins, derived addresses, exact threshold, signer set, or wallet ownership."
                .to_owned(),
        );
    }

    if analyzed.transaction.is_some() && analyzed.psbt.is_some() {
        limitations.push(
            "Transaction-to-PSBT comparison does not prove that the transaction was extracted from the PSBT."
                .to_owned(),
        );
    }

    limitations
}

fn consolidated_risk(warnings: &[RiskWarning], missing_data: &[String]) -> RiskLevel {
    if warnings
        .iter()
        .any(|warning| warning.severity == RiskLevel::High)
    {
        RiskLevel::High
    } else if warnings
        .iter()
        .any(|warning| warning.severity == RiskLevel::Medium)
    {
        RiskLevel::Medium
    } else if !missing_data.is_empty()
        || warnings
            .iter()
            .any(|warning| warning.severity == RiskLevel::Unknown)
    {
        RiskLevel::Unknown
    } else {
        RiskLevel::Low
    }
}

fn policy_summary(value: &Value) -> Vec<SummaryItem> {
    match value {
        Value::Object(map) => vec![
            SummaryItem {
                label: "json_type".to_owned(),
                value: "object".to_owned(),
            },
            SummaryItem {
                label: "top_level_keys".to_owned(),
                value: map.len().to_string(),
            },
            SummaryItem {
                label: "keys".to_owned(),
                value: map.keys().cloned().collect::<Vec<_>>().join(", "),
            },
        ],
        Value::Array(items) => vec![
            SummaryItem {
                label: "json_type".to_owned(),
                value: "array".to_owned(),
            },
            SummaryItem {
                label: "items".to_owned(),
                value: items.len().to_string(),
            },
        ],
        other => vec![SummaryItem {
            label: "json_type".to_owned(),
            value: json_type(other).to_owned(),
        }],
    }
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn detected(artifact: &str, path: &Path) -> DetectedArtifact {
    DetectedArtifact {
        artifact: artifact.to_owned(),
        file: file_name(path),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| PathBuf::from(name).display().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn title_case(input: &str) -> String {
    let mut chars = input.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for item in items {
        if !deduped.contains(&item) {
            deduped.push(item);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_complete_fixture_pack() {
        let report =
            analyze_review_pack(Path::new("tests/fixtures/review-packs/complete")).unwrap();

        assert_eq!(report.schema_version, "0.4");
        assert!(report
            .artifacts_detected
            .iter()
            .any(|artifact| artifact.artifact == "psbt"));
        assert!(report
            .cross_artifact_findings
            .iter()
            .any(|finding| finding.code == "tx-psbt-counts-match"));
        assert!(report
            .limitations
            .iter()
            .any(|limitation| limitation.contains("Real descriptor")));
    }
}
