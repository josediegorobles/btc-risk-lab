use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::analyzer::RiskReport;

#[derive(Clone, Copy, Debug)]
pub enum Provider {
    Openai,
}

pub fn summarize_report(path: &Path, provider: Provider) -> Result<String> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read report JSON {}", path.display()))?;
    let report: RiskReport =
        serde_json::from_str(&raw).context("input must be a btc-risk-lab JSON report")?;

    let provider_name = match provider {
        Provider::Openai => "openai",
    };

    Ok(format!(
        "# Executive Summary Draft\n\nProvider selected: `{provider_name}`.\n\nRisk classification is `{risk:?}` for `{artifact:?}`. The technical report contains `{warning_count}` warning(s) and `{missing_count}` missing-data dependency note(s).\n\nThis feature is intentionally conservative in the MVP: it summarizes only the local JSON report and does not send transaction artifacts, secrets, private keys, seed phrases, or wallet data to any external service.",
        risk = report.risk,
        artifact = report.artifact_type,
        warning_count = report.warnings.len(),
        missing_count = report.missing_data.len()
    ))
}
