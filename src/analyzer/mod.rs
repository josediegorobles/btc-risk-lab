mod psbt;
mod script;
mod tx;

use serde::{Deserialize, Serialize};

pub use psbt::analyze_psbt_file;
pub use script::analyze_script_input;
pub use tx::{
    analyze_transaction_file, analyze_transaction_hex, analyze_transaction_hex_with_prevouts,
    PrevoutInput,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskReport {
    pub artifact_type: ArtifactType,
    pub risk: RiskLevel,
    pub summary: Vec<SummaryItem>,
    pub warnings: Vec<RiskWarning>,
    pub missing_data: Vec<String>,
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psbt: Option<PsbtAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptAnalysis>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Transaction,
    Psbt,
    Script,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

impl RiskLevel {
    fn from_warnings(warnings: &[RiskWarning], missing_data: &[String]) -> Self {
        if warnings
            .iter()
            .any(|warning| warning.severity == RiskLevel::High)
        {
            return RiskLevel::High;
        }

        if warnings
            .iter()
            .any(|warning| warning.severity == RiskLevel::Medium)
        {
            return RiskLevel::Medium;
        }

        if !missing_data.is_empty() && warnings.is_empty() {
            return RiskLevel::Unknown;
        }

        RiskLevel::Low
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskWarning {
    pub code: String,
    pub severity: RiskLevel,
    pub title: String,
    pub explanation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SummaryItem {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionAnalysis {
    pub input_count: usize,
    pub output_count: usize,
    pub output_value_sats: u64,
    pub estimated_fee_sats: Option<i64>,
    pub outputs: Vec<OutputAnalysis>,
    pub signals: ScriptSignals,
    pub complexity: Complexity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PsbtAnalysis {
    pub input_count: usize,
    pub output_count: usize,
    pub inputs_with_witness_utxo: usize,
    pub inputs_with_non_witness_utxo: usize,
    pub estimated_fee_sats: Option<i64>,
    pub outputs: Vec<OutputAnalysis>,
    pub signals: ScriptSignals,
    pub complexity: Complexity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScriptAnalysis {
    pub byte_len: usize,
    pub opcode_count: usize,
    pub script_type: String,
    pub signals: ScriptSignals,
    pub complexity: Complexity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutputAnalysis {
    pub index: usize,
    pub value_sats: u64,
    pub script_type: String,
    pub address: Option<String>,
    pub is_dust: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ScriptSignals {
    pub multisig: bool,
    pub timelock: bool,
    pub relative_timelock: bool,
    pub op_return: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Complexity {
    pub score: u32,
    pub label: String,
    pub factors: Vec<String>,
}

fn common_limitations() -> Vec<String> {
    vec![
        "This is an explainability and reporting tool, not a consensus-level Bitcoin validator."
            .to_owned(),
        "The tool does not create wallets, sign transactions, custody funds, request seed phrases, or handle private keys."
            .to_owned(),
        "Risk classifications are heuristics based only on data present in the analyzed artifact."
            .to_owned(),
    ]
}

fn warning(code: &str, severity: RiskLevel, title: &str, explanation: &str) -> RiskWarning {
    RiskWarning {
        code: code.to_owned(),
        severity,
        title: title.to_owned(),
        explanation: explanation.to_owned(),
    }
}

fn summary(label: &str, value: impl ToString) -> SummaryItem {
    SummaryItem {
        label: label.to_owned(),
        value: value.to_string(),
    }
}

fn complexity(score: u32, factors: Vec<String>) -> Complexity {
    let label = match score {
        0..=2 => "low",
        3..=6 => "medium",
        _ => "high",
    };

    Complexity {
        score,
        label: label.to_owned(),
        factors,
    }
}
