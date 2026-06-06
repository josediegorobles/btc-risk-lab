use anyhow::Result;

use crate::analyzer::{ArtifactType, RiskReport};

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

fn render_markdown(report: &RiskReport) -> String {
    let mut markdown = String::new();
    markdown.push_str("# BTC Risk Lab Report\n\n");
    markdown.push_str(&format!(
        "- Artifact: `{}`\n",
        artifact_name(&report.artifact_type)
    ));
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

fn artifact_name(artifact_type: &ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::Transaction => "transaction",
        ArtifactType::Psbt => "psbt",
        ArtifactType::Script => "script",
    }
}
