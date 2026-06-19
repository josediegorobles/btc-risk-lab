use anyhow::Result;

use crate::analyzer::{ArtifactType, RiskLevel, RiskReport};
use crate::policy_pack::PolicyPackReport;
use crate::review_pack::ReviewPackReport;

#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    Json,
    Markdown,
}

pub fn render_report(report: &RiskReport, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(report)?),
        OutputFormat::Markdown => Ok(render_markdown(report)),
    }
}

pub fn render_review_pack_report(
    report: &ReviewPackReport,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(report)?),
        OutputFormat::Markdown => Ok(render_review_pack_markdown(report)),
    }
}

pub fn render_policy_pack_report(
    report: &PolicyPackReport,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(report)?),
        OutputFormat::Markdown => Ok(render_policy_pack_markdown(report)),
    }
}

fn render_markdown(report: &RiskReport) -> String {
    let mut markdown = String::new();
    markdown.push_str("# BTC Risk Lab Report\n\n");
    markdown.push_str(&format!(
        "- Artifact: `{}`\n",
        artifact_name(&report.artifact_type)
    ));
    markdown.push_str(&format!("- Schema: `{}`\n", report.schema_version));
    let risk = format!("{:?}", report.risk).to_lowercase();
    markdown.push_str(&format!("- Risk: `{risk}`\n\n"));

    markdown.push_str("## Summary\n\n");
    markdown.push_str("| Signal | Value |\n|---|---:|\n");
    for item in &report.summary {
        markdown.push_str(&format!("| {} | {} |\n", item.label, item.value));
    }
    markdown.push('\n');

    if !report.warnings.is_empty() {
        markdown.push_str("## Warnings\n\n");
        for warning in &report.warnings {
            markdown.push_str(&format!(
                "- **{}** (`{:?}`, `{}`): {}\n",
                warning.title, warning.severity, warning.code, warning.explanation
            ));
        }
        markdown.push('\n');
    }

    if !report.missing_data.is_empty() {
        markdown.push_str("## Missing Data\n\n");
        for item in &report.missing_data {
            markdown.push_str(&format!("- {}\n", item));
        }
        markdown.push('\n');
    }

    if let Some(tx) = &report.transaction {
        markdown.push_str("## Outputs\n\n");
        push_outputs_table(&mut markdown, &tx.outputs);
        markdown.push_str(&format!(
            "\n## Complexity\n\n`{}` score `{}`. Factors: {}.\n\n",
            tx.complexity.label,
            tx.complexity.score,
            tx.complexity.factors.join(", ")
        ));
    }

    if let Some(psbt) = &report.psbt {
        markdown.push_str("## Outputs\n\n");
        push_outputs_table(&mut markdown, &psbt.outputs);
        markdown.push_str(&format!(
            "\n## Complexity\n\n`{}` score `{}`. Factors: {}.\n\n",
            psbt.complexity.label,
            psbt.complexity.score,
            psbt.complexity.factors.join(", ")
        ));
    }

    if let Some(script) = &report.script {
        markdown.push_str("## Script Detail\n\n");
        markdown.push_str(&format!(
            "- Type: `{}`\n- Bytes: `{}`\n- Opcodes: `{}`\n- Complexity: `{}` score `{}`\n\n",
            script.script_type,
            script.byte_len,
            script.opcode_count,
            script.complexity.label,
            script.complexity.score
        ));
    }

    if let Some(descriptor) = &report.descriptor {
        markdown.push_str("## Descriptor Detail\n\n");
        markdown.push_str(&format!(
            "- Descriptor type: `{}`\n- Script type: `{}`\n- Sanity check: `{}`\n",
            descriptor.descriptor_type, descriptor.script_type, descriptor.sanity_check
        ));
        if let Some(weight) = descriptor.max_satisfaction_weight_wu {
            markdown.push_str(&format!("- Max satisfaction weight: `{weight}` WU\n"));
        }
        markdown.push_str(&format!(
            "- Signals: multisig `{}`, threshold `{}`, timelock `{}`, relative timelock `{}`\n",
            descriptor.signals.multisig,
            descriptor.signals.threshold,
            descriptor.signals.timelock,
            descriptor.signals.relative_timelock
        ));
        markdown.push_str(&format!(
            "- Complexity: `{}` score `{}`\n\n",
            descriptor.complexity.label, descriptor.complexity.score
        ));
    }

    markdown.push_str("## Limitations\n\n");
    for limitation in &report.limitations {
        markdown.push_str(&format!("- {}\n", limitation));
    }

    markdown
}

fn push_outputs_table(markdown: &mut String, outputs: &[crate::analyzer::OutputAnalysis]) {
    markdown.push_str("| # | Value sats | Type | Dust | Address |\n|---:|---:|---|---|---|\n");
    for output in outputs {
        markdown.push_str(&format!(
            "| {} | {} | `{}` | {} | {} |\n",
            output.index,
            output.value_sats,
            output.script_type,
            output.is_dust,
            output.address.as_deref().unwrap_or("-")
        ));
    }
}

fn render_review_pack_markdown(report: &ReviewPackReport) -> String {
    let mut markdown = String::new();
    markdown.push_str("# BTC Risk Lab Review Pack\n\n");
    markdown.push_str(&format!("- Schema: `{}`\n", report.schema_version));
    markdown.push_str(&format!(
        "- Consolidated risk: `{}`\n\n",
        risk_name(&report.consolidated_risk)
    ));

    markdown.push_str("## Artifacts Detected\n\n");
    if report.artifacts_detected.is_empty() {
        markdown.push_str("- No known review pack artifacts were detected.\n\n");
    } else {
        markdown.push_str("| Artifact | File |\n|---|---|\n");
        for artifact in &report.artifacts_detected {
            markdown.push_str(&format!(
                "| `{}` | `{}` |\n",
                artifact.artifact, artifact.file
            ));
        }
        markdown.push('\n');
    }

    markdown.push_str("## Per-Artifact Summary\n\n");
    if report.per_artifact_summary.is_empty() {
        markdown.push_str("- No artifact summaries available.\n\n");
    } else {
        for artifact in &report.per_artifact_summary {
            markdown.push_str(&format!(
                "### `{}` ({:?})\n\n",
                artifact.artifact, artifact.status
            ));
            if let Some(risk) = &artifact.risk {
                markdown.push_str(&format!("- Risk: `{}`\n", risk_name(risk)));
            }
            for item in &artifact.summary {
                markdown.push_str(&format!("- {}: `{}`\n", item.label, item.value));
            }
            if !artifact.missing_data.is_empty() {
                markdown.push_str("- Missing data:\n");
                for item in &artifact.missing_data {
                    markdown.push_str(&format!("  - {}\n", item));
                }
            }
            if !artifact.warnings.is_empty() {
                markdown.push_str("- Warnings:\n");
                for warning in &artifact.warnings {
                    markdown.push_str(&format!(
                        "  - **{}** (`{:?}`, `{}`): {}\n",
                        warning.title, warning.severity, warning.code, warning.explanation
                    ));
                }
            }
            markdown.push('\n');
        }
    }

    if !report.warnings.is_empty() {
        markdown.push_str("## Warnings\n\n");
        for warning in &report.warnings {
            markdown.push_str(&format!(
                "- **{}** (`{:?}`, `{}`): {}\n",
                warning.title, warning.severity, warning.code, warning.explanation
            ));
        }
        markdown.push('\n');
    }

    if !report.missing_data.is_empty() {
        markdown.push_str("## Missing Data\n\n");
        for item in &report.missing_data {
            markdown.push_str(&format!("- {}\n", item));
        }
        markdown.push('\n');
    }

    if !report.cross_artifact_findings.is_empty() {
        markdown.push_str("## Cross-Artifact Findings\n\n");
        for finding in &report.cross_artifact_findings {
            markdown.push_str(&format!(
                "- **{}** (`{:?}`, `{}`): {}\n",
                finding.title, finding.severity, finding.code, finding.explanation
            ));
        }
        markdown.push('\n');
    }

    markdown.push_str("## Review Questions\n\n");
    for question in &report.review_questions {
        markdown.push_str(&format!("- {}\n", question));
    }
    markdown.push('\n');

    markdown.push_str("## Limitations\n\n");
    for limitation in &report.limitations {
        markdown.push_str(&format!("- {}\n", limitation));
    }

    markdown
}

fn render_policy_pack_markdown(report: &PolicyPackReport) -> String {
    let mut markdown = String::new();
    markdown.push_str("# BTC Risk Lab Policy Pack\n\n");
    markdown.push_str(&format!("- Schema: `{}`\n", report.schema_version));
    markdown.push_str(&format!("- Pack type: `{}`\n", report.pack_type));
    markdown.push_str(&format!(
        "- Consolidated risk: `{}`\n\n",
        risk_name(&report.consolidated_risk)
    ));

    markdown.push_str("## Artifacts Detected\n\n");
    if report.artifacts_detected.is_empty() {
        markdown.push_str("- No known policy pack artifacts were detected.\n\n");
    } else {
        markdown.push_str("| Artifact | File |\n|---|---|\n");
        for artifact in &report.artifacts_detected {
            markdown.push_str(&format!(
                "| `{}` | `{}` |\n",
                artifact.artifact, artifact.file
            ));
        }
        markdown.push('\n');
    }

    if !report.evidence_documents.is_empty() {
        markdown.push_str("## Evidence Documents\n\n");
        markdown.push_str("| Artifact | File | Format | Summary |\n|---|---|---|---|\n");
        for document in &report.evidence_documents {
            let summary = document
                .summary
                .iter()
                .map(|item| format!("{}: {}", item.label, item.value))
                .collect::<Vec<_>>()
                .join("; ");
            let summary = markdown_table_cell(&summary);
            markdown.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} |\n",
                markdown_table_cell(&document.artifact),
                markdown_table_cell(&document.file),
                markdown_table_cell(&document.format),
                summary
            ));
        }
        markdown.push('\n');
    }

    markdown.push_str("## Findings\n\n");
    for finding in &report.findings {
        markdown.push_str(&format!(
            "- **{}** (`{}`, `{}`): {}\n",
            finding.title,
            risk_name(&finding.severity),
            finding.code,
            finding.explanation
        ));
    }
    markdown.push('\n');

    if !report.warnings.is_empty() {
        markdown.push_str("## Warnings\n\n");
        for warning in &report.warnings {
            markdown.push_str(&format!(
                "- **{}** (`{}`, `{}`): {}\n",
                warning.title,
                risk_name(&warning.severity),
                warning.code,
                warning.explanation
            ));
        }
        markdown.push('\n');
    }

    if !report.missing_evidence.is_empty() {
        markdown.push_str("## Missing Evidence\n\n");
        for item in &report.missing_evidence {
            markdown.push_str(&format!("- {}\n", item));
        }
        markdown.push('\n');
    }

    markdown.push_str("## Per-Artifact Summary\n\n");
    if report.per_artifact_summary.is_empty() {
        markdown.push_str("- No artifact summaries available.\n\n");
    } else {
        for artifact in &report.per_artifact_summary {
            markdown.push_str(&format!(
                "### `{}` ({:?})\n\n",
                artifact.artifact, artifact.status
            ));
            if let Some(risk) = &artifact.risk {
                markdown.push_str(&format!("- Risk: `{}`\n", risk_name(risk)));
            }
            for item in &artifact.summary {
                markdown.push_str(&format!("- {}: `{}`\n", item.label, item.value));
            }
            if !artifact.missing_data.is_empty() {
                markdown.push_str("- Missing data:\n");
                for item in &artifact.missing_data {
                    markdown.push_str(&format!("  - {}\n", item));
                }
            }
            markdown.push('\n');
        }
    }

    markdown.push_str("## Review Questions\n\n");
    for question in &report.review_questions {
        markdown.push_str(&format!("- {}\n", question));
    }
    markdown.push('\n');

    markdown.push_str("## Limitations\n\n");
    for limitation in &report.limitations {
        markdown.push_str(&format!("- {}\n", limitation));
    }

    markdown
}

fn risk_name(risk: &RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Unknown => "unknown",
    }
}

fn markdown_table_cell(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

fn artifact_name(artifact_type: &ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::Transaction => "transaction",
        ArtifactType::Psbt => "psbt",
        ArtifactType::Script => "script",
        ArtifactType::Descriptor => "descriptor",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::analyze_script_input;

    #[test]
    fn renders_script_report_as_stable_json_shape() {
        let report = analyze_script_input("OP_CHECKMULTISIG OP_CHECKSEQUENCEVERIFY").unwrap();

        let rendered = render_report(&report, OutputFormat::Json).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["artifact_type"], "script");
        assert_eq!(json["risk"], "medium");
        assert_eq!(json["script"]["signals"]["multisig"], true);
        assert_eq!(json["script"]["signals"]["relative_timelock"], true);
    }

    #[test]
    fn renders_script_report_as_stable_markdown_sections() {
        let report = analyze_script_input("OP_CHECKMULTISIG OP_CHECKSEQUENCEVERIFY").unwrap();

        let rendered = render_report(&report, OutputFormat::Markdown).unwrap();

        assert!(rendered.starts_with("# BTC Risk Lab Report\n\n"));
        assert!(rendered.contains("- Artifact: `script`"));
        assert!(rendered.contains("- Risk: `medium`"));
        assert!(rendered.contains("## Warnings\n\n"));
        assert!(rendered.contains("## Script Detail\n\n"));
        assert!(rendered.contains("## Limitations\n\n"));
    }
}
