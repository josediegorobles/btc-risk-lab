use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};

use btc_risk_lab::analyzer;
use btc_risk_lab::report::{render_report, OutputFormat};

#[derive(Debug, Parser)]
#[command(author, version, about)]
#[command(
    long_about = "Analyze Bitcoin transactions, PSBTs, and scripts to produce explainable technical risk reports. This tool does not create wallets, sign transactions, custody funds, or handle private keys."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Analyze a transaction hex string or a JSON file containing raw transaction hex and optional prevout data.
    AnalyzeTx {
        #[arg(
            long,
            value_name = "FILE",
            required_unless_present = "hex",
            conflicts_with = "hex"
        )]
        input: Option<PathBuf>,

        #[arg(
            long,
            value_name = "HEX",
            required_unless_present = "input",
            conflicts_with = "input"
        )]
        hex: Option<String>,

        #[arg(long, value_enum, default_value_t = CliFormat::Markdown)]
        format: CliFormat,
    },

    /// Fetch a public transaction from mempool.space Esplora and analyze it with prevouts.
    #[cfg(feature = "fetch")]
    FetchTx {
        #[arg(long)]
        txid: String,

        #[arg(long, value_enum, default_value_t = CliFormat::Markdown)]
        format: CliFormat,
    },

    /// Analyze a PSBT file encoded as base64.
    AnalyzePsbt {
        #[arg(long)]
        input: PathBuf,

        #[arg(long, value_enum, default_value_t = CliFormat::Markdown)]
        format: CliFormat,
    },

    /// Analyze a Bitcoin script provided as hex or a small ASM subset.
    AnalyzeScript {
        #[arg(long)]
        script: String,

        #[arg(long, value_enum, default_value_t = CliFormat::Markdown)]
        format: CliFormat,
    },

    /// Generate an optional executive summary from an existing technical JSON report.
    Summarize {
        #[arg(long)]
        input: PathBuf,

        #[arg(long, value_enum)]
        provider: AiProvider,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum CliFormat {
    Json,
    Markdown,
}

impl From<CliFormat> for OutputFormat {
    fn from(value: CliFormat) -> Self {
        match value {
            CliFormat::Json => OutputFormat::Json,
            CliFormat::Markdown => OutputFormat::Markdown,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum AiProvider {
    Openai,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::AnalyzeTx { input, hex, format } => {
            let report = match (input, hex) {
                (Some(input), None) => analyzer::analyze_transaction_file(&input)?,
                (None, Some(hex)) => analyzer::analyze_transaction_hex(&hex)?,
                _ => bail!("provide exactly one transaction source: --input or --hex"),
            };
            println!("{}", render_report(&report, format.into())?);
        }
        #[cfg(feature = "fetch")]
        Commands::FetchTx { txid, format } => {
            let report = fetch_tx(&txid)?;
            println!("{}", render_report(&report, format.into())?);
        }
        Commands::AnalyzePsbt { input, format } => {
            let report = analyzer::analyze_psbt_file(&input)?;
            println!("{}", render_report(&report, format.into())?);
        }
        Commands::AnalyzeScript { script, format } => {
            let report = analyzer::analyze_script_input(&script)?;
            println!("{}", render_report(&report, format.into())?);
        }
        Commands::Summarize { input, provider } => summarize(input, provider)?,
    }

    Ok(())
}

#[cfg(feature = "fetch")]
fn fetch_tx(txid: &str) -> Result<btc_risk_lab::analyzer::RiskReport> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let fetched = runtime.block_on(btc_risk_lab::network::fetch_transaction(txid))?;

    analyzer::analyze_transaction_hex_with_prevouts(
        &fetched.hex,
        &fetched.prevouts,
        fetched.fee_sats,
    )
}

#[cfg(feature = "ai")]
fn summarize(input: PathBuf, provider: AiProvider) -> Result<()> {
    let provider = match provider {
        AiProvider::Openai => btc_risk_lab::ai::Provider::Openai,
    };
    println!("{}", btc_risk_lab::ai::summarize_report(&input, provider)?);
    Ok(())
}

#[cfg(not(feature = "ai"))]
fn summarize(_input: PathBuf, _provider: AiProvider) -> Result<()> {
    bail!("AI summaries are disabled. Rebuild with `--features ai` to enable this command.")
}
