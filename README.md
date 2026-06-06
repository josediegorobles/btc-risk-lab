# btc-risk-lab

`btc-risk-lab` is an explainable Bitcoin risk analysis CLI written in Rust.

It analyzes Bitcoin artifacts such as raw transactions, PSBTs, and scripts, then produces a technical report in JSON or Markdown. The goal is not to replace wallet software or consensus validation. The goal is to make transaction structure, missing data, policy signals, and review assumptions visible.

This repository is also a public engineering artifact by **Jose Robles**, Head of Engineering / AI Architect, showing hands-on work across Rust, Bitcoin/blockchain, AI-assisted reporting, security-minded product boundaries, and technical due diligence.

## Why It Exists

Bitcoin and Web3 systems often fail at the edges: incomplete transaction context, unclear signing policy, weak operational review, or hidden assumptions around scripts and PSBTs.

`btc-risk-lab` demonstrates how a senior engineering team can turn low-level artifacts into reviewable evidence:

- deterministic Rust analysis first
- explicit missing-data dependencies
- human-readable warning explanations
- JSON output suitable for downstream automation
- optional AI summary layer that never replaces the technical report
- clear security boundaries around private keys and funds

## What It Demonstrates

This MVP is intentionally small, but it is structured like a real due diligence tool:

- Rust CLI architecture with `clap`
- Bitcoin transaction and PSBT parsing via `rust-bitcoin`
- script inspection heuristics
- structured reporting with `serde`
- Markdown and JSON output
- CI with `fmt`, `clippy`, and tests
- a security posture that avoids custody, signing, seed phrases, and private key handling

## Install

```bash
git clone https://github.com/josediegorobles/btc-risk-lab.git
cd btc-risk-lab
cargo build --release
```

Run locally during development:

```bash
cargo run -- analyze-tx --input examples/tx.json --format markdown
```

## Commands

Analyze a transaction JSON file:

```bash
btc-risk-lab analyze-tx --input examples/tx.json --format markdown
```

Analyze a base64 PSBT:

```bash
btc-risk-lab analyze-psbt --input examples/sample.psbt --format json
```

Analyze a script as hex or a small ASM subset:

```bash
btc-risk-lab analyze-script --script "OP_CHECKMULTISIG OP_CHECKSEQUENCEVERIFY" --format markdown
```

Generate an optional executive summary from an existing JSON report:

```bash
cargo run --features ai -- summarize --input report.json --provider openai
```

In the MVP, the AI feature is deliberately conservative: it summarizes only an existing local JSON report and does not send artifacts or secrets to an external provider.

## Transaction Input Format

Transactions are provided as JSON so fee analysis can explain whether the required UTXO context is present.

```json
{
  "hex": "0200000001...",
  "prevouts": [
    {
      "value_sats": 2000,
      "script_pubkey": "00140000000000000000000000000000000000000000"
    }
  ]
}
```

Bitcoin transactions do not include the value of the UTXOs they spend. If `prevouts` are missing, `btc-risk-lab` reports that fee estimation is unavailable instead of inventing a number.

## Sample Output

```markdown
# BTC Risk Lab Report

- Artifact: `transaction`
- Risk: `medium`

## Summary

| Signal | Value |
|---|---:|
| inputs | 1 |
| outputs | 2 |
| output_value_sats | 1100 |
| estimated_fee_sats | 900 |

## Warnings

- **Dust-like output detected** (`Medium`, `dust-output`): At least one non-zero output is below the heuristic dust threshold for its script type.
```

## MVP Analysis Signals

Current analysis includes:

- number of inputs
- number of outputs
- output value in sats
- output script type where detectable
- address rendering where detectable
- dust-like outputs
- fee estimation when input UTXO values are available
- multisig signals
- absolute and relative timelock signals
- script complexity score
- missing-data dependencies
- risk classification: `low`, `medium`, `high`, or `unknown`
- human-readable warning explanations

## Security Boundaries

`btc-risk-lab` does **not**:

- create wallets
- sign transactions
- custody funds
- handle private keys
- request seed phrases
- broadcast transactions
- promise consensus-level validation
- send secrets to an LLM

It is an analysis, explainability, and reporting tool.

## Privacy

The base analyzer runs locally and does not require network access.

AI support is optional and isolated behind the `ai` feature flag. The intended production architecture is to send only the already-produced technical JSON report, after redaction and policy checks, to an external summarization provider. Private keys, seed phrases, wallet files, and signing material are out of scope by design.

## Limitations

This MVP uses heuristics. It does not perform full Bitcoin Core policy validation, mempool acceptance simulation, chain lookup, script execution, descriptor wallet analysis, or consensus-level validation.

Risk classifications are only as complete as the artifact data provided. Missing UTXO data, omitted redeem scripts, absent witness scripts, and incomplete PSBT maps can all reduce confidence.

## Technical Due Diligence Connection

The same approach used here applies to technical due diligence for Bitcoin, Web3, fintech, and AI systems:

- make implicit risks explicit
- separate deterministic facts from interpretation
- expose missing evidence
- document operational assumptions
- build machine-readable reports that executives can still understand
- keep security and privacy boundaries visible in the product design

For clients, this repo is a compact example of how Jose Robles approaches engineering leadership: practical Rust implementation, domain-aware Bitcoin analysis, AI used as a reporting layer instead of a source of truth, and clear communication of risk.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## License

MIT
