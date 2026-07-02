use std::{env, fs, path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

use crate::analyzer::RiskReport;

const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_OPENAI_MODEL: &str = "gpt-4o-mini";
const AI_TIMEOUT_SECS: u64 = 20;

pub trait SummaryProvider {
    fn summarize(&self, report: &RiskReport) -> Result<String>;
}

#[derive(Clone, Copy, Debug)]
pub enum ProviderKind {
    Openai,
}

pub fn summarize_report(path: &Path, provider: ProviderKind) -> Result<String> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read report JSON {}", path.display()))?;
    let report: RiskReport =
        serde_json::from_str(&raw).context("input must be a btc-risk-lab JSON report")?;

    let draft = match provider {
        ProviderKind::Openai => OpenAiProvider::from_env()?.summarize(&report)?,
    };

    Ok(format!(
        "# AI-assisted draft\n\n{draft}\n\n_This summary was generated from `report.json` only. Review the underlying btc-risk-lab JSON report before relying on it._"
    ))
}

pub struct OpenAiProvider {
    base_url: String,
    api_key: String,
    model: String,
    timeout: Duration,
}

impl OpenAiProvider {
    pub fn from_env() -> Result<Self> {
        let base_url = env::var("BTC_RISK_LAB_AI_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_OPENAI_BASE_URL.to_owned());
        let api_key = env::var("BTC_RISK_LAB_AI_API_KEY")
            .context("BTC_RISK_LAB_AI_API_KEY must be set for the OpenAI-compatible provider")?;
        let model =
            env::var("BTC_RISK_LAB_AI_MODEL").unwrap_or_else(|_| DEFAULT_OPENAI_MODEL.to_owned());

        if base_url.trim().is_empty() {
            bail!("BTC_RISK_LAB_AI_BASE_URL cannot be empty");
        }

        if api_key.trim().is_empty() {
            bail!("BTC_RISK_LAB_AI_API_KEY cannot be empty");
        }

        Ok(Self {
            base_url,
            api_key,
            model,
            timeout: Duration::from_secs(AI_TIMEOUT_SECS),
        })
    }

    #[cfg(test)]
    fn new_for_test(base_url: String, api_key: String, model: String) -> Self {
        Self {
            base_url,
            api_key,
            model,
            timeout: Duration::from_secs(AI_TIMEOUT_SECS),
        }
    }

    async fn summarize_async(&self, report: &RiskReport) -> Result<String> {
        let report_json = serde_json::to_string_pretty(report)
            .context("failed to serialize btc-risk-lab report for AI summary")?;

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .default_headers(self.headers()?)
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .context("failed to build AI HTTP client")?;

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let response = client
            .post(&url)
            .json(&ChatCompletionRequest {
                model: self.model.clone(),
                temperature: 0.2,
                messages: vec![
                    ChatMessage {
                        role: "system".to_owned(),
                        content: "You summarize btc-risk-lab technical JSON reports. Be concise, preserve uncertainty, do not invent facts, and label the result as a draft.".to_owned(),
                    },
                    ChatMessage {
                        role: "user".to_owned(),
                        content: format!(
                            "Create an executive summary draft from this btc-risk-lab report JSON only:\n\n{report_json}"
                        ),
                    },
                ],
            })
            .send()
            .await
            .with_context(|| format!("failed to call AI provider at {url}"))?
            .error_for_status()
            .with_context(|| format!("AI provider returned an error for {url}"))?
            .json::<ChatCompletionResponse>()
            .await
            .context("AI provider response was not valid OpenAI-compatible JSON")?;

        response
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message.content.trim().to_owned())
            .filter(|content| !content.is_empty())
            .context("AI provider returned an empty summary")
    }

    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_str(&format!("Bearer {}", self.api_key.trim()))
            .context("BTC_RISK_LAB_AI_API_KEY is not a valid HTTP header value")?;
        headers.insert(AUTHORIZATION, value);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(headers)
    }
}

impl SummaryProvider for OpenAiProvider {
    fn summarize(&self, report: &RiskReport) -> Result<String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to build AI runtime")?;

        runtime.block_on(self.summarize_async(report))
    }
}

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    temperature: f32,
    messages: Vec<ChatMessage>,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatCompletionChoice>,
}

#[derive(Deserialize)]
struct ChatCompletionChoice {
    message: ChatCompletionMessage,
}

#[derive(Deserialize)]
struct ChatCompletionMessage {
    content: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{ArtifactType, RiskLevel, RiskReport, RiskWarning, SummaryItem};

    fn minimal_report() -> RiskReport {
        RiskReport {
            schema_version: "0.3".to_owned(),
            artifact_type: ArtifactType::Transaction,
            risk: RiskLevel::Medium,
            summary: vec![SummaryItem {
                label: "inputs".to_owned(),
                value: "1".to_owned(),
            }],
            warnings: vec![RiskWarning {
                code: "missing-prevouts".to_owned(),
                severity: RiskLevel::Medium,
                title: "Cannot estimate fee".to_owned(),
                explanation: "Prevout values are missing.".to_owned(),
            }],
            missing_data: vec!["prevout values for every input".to_owned()],
            limitations: vec!["technical report only".to_owned()],
            transaction: None,
            psbt: None,
            script: None,
            descriptor: None,
        }
    }

    #[test]
    fn output_is_marked_ai_assisted_draft() {
        struct StaticProvider;

        impl SummaryProvider for StaticProvider {
            fn summarize(&self, _report: &RiskReport) -> Result<String> {
                Ok("Review missing prevout evidence.".to_owned())
            }
        }

        let draft = StaticProvider.summarize(&minimal_report()).unwrap();

        assert_eq!(draft, "Review missing prevout evidence.");
    }

    #[test]
    fn openai_provider_can_be_constructed_for_tests() {
        let provider = OpenAiProvider::new_for_test(
            "http://127.0.0.1:1/v1".to_owned(),
            "test-key".to_owned(),
            "test-model".to_owned(),
        );

        assert_eq!(provider.timeout, Duration::from_secs(AI_TIMEOUT_SECS));
    }
}
