# Security Policy

## Scope

`btc-risk-lab` is a local analysis and reporting tool for Bitcoin artifacts. It is not wallet software.

The project must not:

- create wallets
- sign transactions
- custody funds
- request or store private keys
- request or store seed phrases
- broadcast transactions
- represent heuristic analysis as consensus-level validation

## Reporting Security Issues

Please open a GitHub security advisory or contact the maintainer privately if you find a vulnerability that could cause unsafe handling of sensitive Bitcoin material, misleading risk output, command injection, parser crashes on untrusted input, or accidental network disclosure.

## Sensitive Data

Do not submit real private keys, seed phrases, wallet files, production PSBTs, proprietary transaction data, or confidential client artifacts in public issues.

## Network Egress

By default, installed builds have no network features enabled. The deterministic analyzer commands are local-only: `analyze-tx`, `analyze-psbt`, `analyze-script`, `analyze-descriptor`, `review-pack`, and `policy-pack`.

Network-backed commands are explicit:

- `fetch-tx --txid TXID`, when compiled with `--features fetch`, performs read-only HTTPS GET requests to mempool.space's Esplora API at `https://mempool.space/api`. The outgoing request path contains only the public transaction id. To avoid this egress, pass the transaction directly with `analyze-tx --hex HEX` or `analyze-tx --input FILE`.
- `summarize --input report.json --provider openai`, when compiled with `--features ai`, sends only the already-produced btc-risk-lab JSON report to the configured OpenAI-compatible endpoint. To avoid this egress, inspect the deterministic JSON or Markdown report directly.

The global `--offline` flag makes network-backed commands fail before an HTTP client is used.

## AI Feature Boundary

AI support is optional and behind the `ai` feature flag. The base analyzer is deterministic and local. Builds compiled without `ai` return `compiled without ai feature` for the summary command.

The OpenAI-compatible summarizer uses:

- `BTC_RISK_LAB_AI_BASE_URL` for the provider base URL, defaulting to `https://api.openai.com/v1`
- `BTC_RISK_LAB_AI_API_KEY` for authentication
- `BTC_RISK_LAB_AI_MODEL` for the model name, defaulting to `gpt-4o-mini`

The AI HTTP client has a hard 20 second timeout.

Only the already-produced btc-risk-lab JSON report passed to `summarize --input report.json` leaves the local machine. The command does not read or upload raw transaction hex files, PSBT files, descriptors, scripts, policy notes, wallet files, private keys, seed phrases, or signing material. Output is labeled `AI-assisted draft` and must not replace review of the deterministic technical report.

## Validation Boundary

This project does not claim Bitcoin consensus validation, Bitcoin Core policy equivalence, mempool acceptance, or final spend safety. Reports are heuristic and should be reviewed by qualified engineers before operational use.
