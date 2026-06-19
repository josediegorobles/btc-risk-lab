use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    analyzer::{RiskLevel, RiskWarning, SummaryItem},
    review_pack::{
        analyze_review_pack, ArtifactSummary, CrossArtifactFinding, DetectedArtifact,
        ReviewPackReport,
    },
};

const POLICY_PACK_SCHEMA_VERSION: &str = "0.5";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyPackReport {
    pub schema_version: String,
    pub pack_type: String,
    pub artifacts_detected: Vec<DetectedArtifact>,
    pub evidence_documents: Vec<EvidenceDocument>,
    pub per_artifact_summary: Vec<ArtifactSummary>,
    pub consolidated_risk: RiskLevel,
    pub findings: Vec<PolicyFinding>,
    pub warnings: Vec<RiskWarning>,
    pub missing_evidence: Vec<String>,
    pub review_questions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceDocument {
    pub artifact: String,
    pub file: String,
    pub format: String,
    pub summary: Vec<SummaryItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyFinding {
    pub code: String,
    pub severity: RiskLevel,
    pub title: String,
    pub explanation: String,
}

pub fn analyze_policy_pack(input_dir: &Path) -> Result<PolicyPackReport> {
    if !input_dir.is_dir() {
        bail!(
            "policy pack input must be a directory: {}",
            input_dir.display()
        );
    }

    let review_pack = analyze_review_pack(input_dir)?;
    let evidence_documents = read_evidence_documents(input_dir)?;
    let mut artifacts_detected = review_pack.artifacts_detected.clone();
    for evidence in &evidence_documents {
        push_detected_once(
            &mut artifacts_detected,
            DetectedArtifact {
                artifact: evidence.artifact.clone(),
                file: evidence.file.clone(),
            },
        );
    }

    let mut findings = policy_findings(&review_pack);
    let mut missing_evidence = review_pack.missing_data.clone();

    if !has_policy_notes(&evidence_documents) {
        missing_evidence.push(
            "policy notes were not provided as policy.md, policy.yaml, policy.yml, policy.json, or notes.md"
                .to_owned(),
        );
        findings.push(PolicyFinding {
            code: "missing-policy-notes".to_owned(),
            severity: RiskLevel::Unknown,
            title: "Policy notes are missing".to_owned(),
            explanation: "Custody or audit review needs human-written policy intent: quorum, approvers, change handling, timelocks, exceptions, and sign-off evidence.".to_owned(),
        });
    }

    if !has_metadata(&evidence_documents) {
        findings.push(PolicyFinding {
            code: "metadata-not-provided".to_owned(),
            severity: RiskLevel::Low,
            title: "Optional metadata is not present".to_owned(),
            explanation: "No metadata file was provided. This is acceptable, but a public review pack is clearer with owner, purpose, prepared_by, and review_date metadata.".to_owned(),
        });
    }

    findings = dedupe_findings(findings);
    missing_evidence = dedupe(missing_evidence);
    let consolidated_risk = consolidated_risk(&review_pack.warnings, &findings, &missing_evidence);
    let review_questions = review_questions(&review_pack, &evidence_documents, &missing_evidence);
    let limitations = limitations(&evidence_documents);

    Ok(PolicyPackReport {
        schema_version: POLICY_PACK_SCHEMA_VERSION.to_owned(),
        pack_type: "policy_pack".to_owned(),
        artifacts_detected,
        evidence_documents,
        per_artifact_summary: review_pack.per_artifact_summary,
        consolidated_risk,
        findings,
        warnings: review_pack.warnings,
        missing_evidence,
        review_questions,
        limitations,
    })
}

fn read_evidence_documents(input_dir: &Path) -> Result<Vec<EvidenceDocument>> {
    let mut documents = Vec::new();

    for spec in evidence_specs() {
        let path = input_dir.join(spec.file);
        if !path.exists() {
            continue;
        }

        let input = fs::read_to_string(&path)
            .with_context(|| format!("failed to read evidence document {}", path.display()))?;
        documents.push(EvidenceDocument {
            artifact: spec.artifact.to_owned(),
            file: file_name(&path),
            format: spec.format.to_owned(),
            summary: summarize_evidence(spec.format, &input),
        });
    }

    Ok(documents)
}

struct EvidenceSpec {
    artifact: &'static str,
    file: &'static str,
    format: &'static str,
}

fn evidence_specs() -> Vec<EvidenceSpec> {
    vec![
        EvidenceSpec {
            artifact: "policy_notes",
            file: "policy.md",
            format: "markdown",
        },
        EvidenceSpec {
            artifact: "policy_notes",
            file: "policy.yaml",
            format: "yaml",
        },
        EvidenceSpec {
            artifact: "policy_notes",
            file: "policy.yml",
            format: "yaml",
        },
        EvidenceSpec {
            artifact: "policy_notes",
            file: "policy.json",
            format: "json",
        },
        EvidenceSpec {
            artifact: "policy_notes",
            file: "notes.md",
            format: "markdown",
        },
        EvidenceSpec {
            artifact: "metadata",
            file: "metadata.json",
            format: "json",
        },
        EvidenceSpec {
            artifact: "metadata",
            file: "metadata.yaml",
            format: "yaml",
        },
        EvidenceSpec {
            artifact: "metadata",
            file: "metadata.yml",
            format: "yaml",
        },
    ]
}

fn summarize_evidence(format: &str, input: &str) -> Vec<SummaryItem> {
    let mut items = vec![
        summary("bytes", input.len()),
        summary("lines", input.lines().count()),
    ];

    match format {
        "json" => items.extend(json_summary(input)),
        "markdown" => items.push(summary(
            "headings",
            input.lines().filter(|line| line.starts_with('#')).count(),
        )),
        "yaml" => items.push(summary(
            "key_like_lines",
            input
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with('#') && trimmed.contains(':')
                })
                .count(),
        )),
        _ => {}
    }

    items
}

fn json_summary(input: &str) -> Vec<SummaryItem> {
    match serde_json::from_str::<Value>(input) {
        Ok(Value::Object(map)) => vec![
            summary("json_type", "object"),
            summary("top_level_keys", map.len()),
            summary("keys", map.keys().cloned().collect::<Vec<_>>().join(", ")),
        ],
        Ok(Value::Array(items)) => {
            vec![summary("json_type", "array"), summary("items", items.len())]
        }
        Ok(other) => vec![summary("json_type", json_type(&other))],
        Err(_) => vec![summary("json_parse", "invalid")],
    }
}

fn policy_findings(review_pack: &ReviewPackReport) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();

    for cross in &review_pack.cross_artifact_findings {
        findings.push(from_cross_finding(cross));
    }

    for warning in &review_pack.warnings {
        if warning.code.contains("threshold-policy") {
            findings.push(PolicyFinding {
                code: "threshold-policy-signal".to_owned(),
                severity: warning.severity.clone(),
                title: "Threshold policy signal detected".to_owned(),
                explanation: "At least one artifact exposes threshold or multisig policy. Review signer count, quorum, key custody, backup paths, and emergency access.".to_owned(),
            });
        } else if warning.code.contains("multisig-signal") {
            findings.push(PolicyFinding {
                code: "multisig-signal".to_owned(),
                severity: warning.severity.clone(),
                title: "Multisig signal detected".to_owned(),
                explanation: "At least one artifact exposes multisig-like script evidence. Confirm it matches the documented policy and signer responsibilities.".to_owned(),
            });
        } else if warning.code.contains("timelock-signal") {
            findings.push(PolicyFinding {
                code: "timelock-signal".to_owned(),
                severity: warning.severity.clone(),
                title: "Timelock signal detected".to_owned(),
                explanation: "At least one artifact exposes absolute or relative timelock policy. Confirm block height, median-time, sequence, and recovery semantics in policy notes.".to_owned(),
            });
        } else if warning.code.contains("missing-utxo-data")
            || warning.code.contains("missing-prevouts")
        {
            findings.push(PolicyFinding {
                code: "fee-evidence-missing".to_owned(),
                severity: warning.severity.clone(),
                title: "Fee evidence is incomplete".to_owned(),
                explanation: "Fee review depends on UTXO or prevout evidence. Without it, economic review remains partial.".to_owned(),
            });
        }
    }

    for artifact in &review_pack.per_artifact_summary {
        for item in &artifact.summary {
            if item.label == "estimated_fee_sats" {
                findings.push(PolicyFinding {
                    code: format!("{}-fee-estimated", artifact.artifact),
                    severity: RiskLevel::Low,
                    title: format!(
                        "{} fee estimate available",
                        artifact_label(&artifact.artifact)
                    ),
                    explanation: format!(
                        "{} includes an estimated fee of {} sats from available analyzer evidence.",
                        artifact_label(&artifact.artifact),
                        item.value
                    ),
                });
            }

            if artifact.artifact == "descriptor" && item.label == "max_satisfaction_weight_wu" {
                findings.push(PolicyFinding {
                    code: "descriptor-weight-available".to_owned(),
                    severity: RiskLevel::Low,
                    title: "Descriptor satisfaction weight is available".to_owned(),
                    explanation: format!(
                        "The descriptor analyzer reports a max satisfaction weight of {} WU. This is useful review evidence, not a transaction-level fee-rate proof.",
                        item.value
                    ),
                });
            }
        }
    }

    findings
}

fn from_cross_finding(finding: &CrossArtifactFinding) -> PolicyFinding {
    PolicyFinding {
        code: finding.code.clone(),
        severity: finding.severity.clone(),
        title: finding.title.clone(),
        explanation: finding.explanation.clone(),
    }
}

fn review_questions(
    review_pack: &ReviewPackReport,
    evidence_documents: &[EvidenceDocument],
    missing_evidence: &[String],
) -> Vec<String> {
    let mut questions = review_pack
        .review_questions
        .iter()
        .filter(|question| !question.contains("policy.json"))
        .cloned()
        .collect::<Vec<_>>();

    questions.extend([
        "Do descriptor.txt, PSBT data, transaction data, and policy notes describe the same intended signing and spending policy?".to_owned(),
        "Does the written policy identify each signer role, quorum, custody model, recovery path, and approval authority?".to_owned(),
        "Do descriptor, PSBT, and transaction artifacts match the documented policy intent without relying on this tool to prove formal equivalence?".to_owned(),
        "Have custodians or auditors independently confirmed destinations, amounts, fee assumptions, and change handling?".to_owned(),
        "Are absolute or relative timelocks documented with operational consequences and emergency procedures?".to_owned(),
    ]);

    if has_metadata(evidence_documents) {
        questions.push(
            "Does metadata identify owner, prepared_by, review_date, environment, and whether this pack is public-demo or production evidence?"
                .to_owned(),
        );
    }

    if !missing_evidence.is_empty() {
        questions.push(
            "Which missing evidence must be collected before approving, signing, or relying on this policy pack?"
                .to_owned(),
        );
    }

    dedupe(questions)
}

fn limitations(evidence_documents: &[EvidenceDocument]) -> Vec<String> {
    let mut limitations = vec![
        "This is an explainability and reporting tool, not a consensus-level Bitcoin validator."
            .to_owned(),
        "The policy-pack command performs local file analysis only and does not make network calls."
            .to_owned(),
        "The tool does not create wallets, sign transactions, custody funds, request seed phrases, handle private keys, or broadcast transactions."
            .to_owned(),
        "Cross-artifact findings compare available signals and counts only; formal descriptor, PSBT, transaction, or wallet equivalence is not proven."
            .to_owned(),
        "Fee and weight findings are analyzer evidence, not Bitcoin Core mempool acceptance or fee-rate validation."
            .to_owned(),
    ];

    if evidence_documents
        .iter()
        .any(|document| document.format == "markdown" || document.format == "yaml")
    {
        limitations.push(
            "Markdown and YAML policy evidence is summarized structurally; the tool does not semantically validate natural-language policy commitments."
                .to_owned(),
        );
    }

    limitations
}

fn consolidated_risk(
    warnings: &[RiskWarning],
    findings: &[PolicyFinding],
    missing_evidence: &[String],
) -> RiskLevel {
    if warnings
        .iter()
        .any(|warning| warning.severity == RiskLevel::High)
        || findings
            .iter()
            .any(|finding| finding.severity == RiskLevel::High)
    {
        RiskLevel::High
    } else if warnings
        .iter()
        .any(|warning| warning.severity == RiskLevel::Medium)
        || findings
            .iter()
            .any(|finding| finding.severity == RiskLevel::Medium)
    {
        RiskLevel::Medium
    } else if !missing_evidence.is_empty()
        || warnings
            .iter()
            .any(|warning| warning.severity == RiskLevel::Unknown)
        || findings
            .iter()
            .any(|finding| finding.severity == RiskLevel::Unknown)
    {
        RiskLevel::Unknown
    } else {
        RiskLevel::Low
    }
}

fn has_policy_notes(documents: &[EvidenceDocument]) -> bool {
    documents
        .iter()
        .any(|document| document.artifact == "policy_notes")
}

fn has_metadata(documents: &[EvidenceDocument]) -> bool {
    documents
        .iter()
        .any(|document| document.artifact == "metadata")
}

fn push_detected_once(artifacts: &mut Vec<DetectedArtifact>, artifact: DetectedArtifact) {
    if !artifacts
        .iter()
        .any(|existing| existing.artifact == artifact.artifact && existing.file == artifact.file)
    {
        artifacts.push(artifact);
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| PathBuf::from(name).display().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn artifact_label(input: &str) -> String {
    if input == "psbt" {
        return "PSBT".to_owned();
    }

    let mut chars = input.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
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

fn summary(label: &str, value: impl ToString) -> SummaryItem {
    SummaryItem {
        label: label.to_owned(),
        value: value.to_string(),
    }
}

fn dedupe_findings(findings: Vec<PolicyFinding>) -> Vec<PolicyFinding> {
    let mut deduped = Vec::new();
    for finding in findings {
        if !deduped
            .iter()
            .any(|existing: &PolicyFinding| existing.code == finding.code)
        {
            deduped.push(finding);
        }
    }
    deduped
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
    fn analyzes_policy_pack_fixture() {
        let report =
            analyze_policy_pack(Path::new("tests/fixtures/policy-packs/multisig-timelock"))
                .unwrap();

        assert_eq!(report.schema_version, "0.5");
        assert_eq!(report.pack_type, "policy_pack");
        assert!(report
            .evidence_documents
            .iter()
            .any(|document| document.file == "policy.md"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "descriptor-psbt-multisig-mismatch"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "descriptor-weight-available"));
    }

    #[test]
    fn reports_missing_policy_notes() {
        let report = analyze_policy_pack(Path::new(
            "tests/fixtures/policy-packs/missing-policy-notes",
        ))
        .unwrap();

        assert!(report
            .missing_evidence
            .iter()
            .any(|item| item.contains("policy notes were not provided")));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "missing-policy-notes"));
    }
}
