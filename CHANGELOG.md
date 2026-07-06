# Changelog

## v0.5.0 - 2026-07-06

### Added

- Added `policy-pack --input DIR --format json|markdown [--output FILE]` for local custody, audit, and technical policy evidence review.
- Added schema version `0.5` `PolicyPackReport` output with artifacts detected, evidence document summaries, per-artifact summaries, consolidated findings, warnings, missing evidence, review questions, and limitations.
- Added Markdown/YAML/JSON policy note evidence summaries and optional metadata evidence summaries.
- Added policy-pack fixtures and CLI/unit regression tests, including missing policy notes coverage.
- Added a public sample report at `docs/policy-pack-sample.md`.
- Added a real `ai` feature implementation for `summarize --input report.json --provider openai` using an OpenAI-compatible `/chat/completions` endpoint configured by `BTC_RISK_LAB_AI_BASE_URL`, `BTC_RISK_LAB_AI_API_KEY`, and optional `BTC_RISK_LAB_AI_MODEL`.
- Added a global `--offline` flag that turns network-backed commands into explanatory errors before any HTTP client is used.
- Added property tests covering transaction, PSBT, and script analysis against arbitrary bytes and mutated valid fixtures.

### Changed

- AI summary output is explicitly marked `AI-assisted draft` and the command sends only the already-produced btc-risk-lab JSON report to the configured provider.
- Builds compiled without `--features ai` now fail the summary command with `compiled without ai feature`.
- Extracted shared pack input validation, file presence checks, file reading, and metadata helpers into `pack_common`.

### Security

- The AI provider HTTP client uses a hard 20 second timeout and does not read or upload raw transaction, PSBT, descriptor, script, policy, wallet, private key, seed phrase, or signing material artifacts.
- Documented network egress boundaries: `fetch-tx` sends only the public txid to mempool.space Esplora, while AI summaries send only the already-produced btc-risk-lab JSON report to the configured AI endpoint.
- `policy-pack` performs local file analysis only. It does not sign, create wallets, handle keys, broadcast transactions, or make network calls.

## v0.4.0 - 2026-06-19

### Added

- Added `review-pack --input DIR --format json|markdown [--output FILE]` for consolidated local review of descriptor, PSBT, transaction, script, policy, and notes artifacts.
- Added schema version `0.4` `ReviewPackReport` output with detected artifacts, per-artifact summaries, consolidated risk, warnings, missing data, cross-artifact findings, review questions, and limitations.
- Added cross-artifact checks for descriptor/PSBT multisig and timelock signals, descriptor threshold limitations, and PSBT/transaction input-output counts.
- Added review-pack fixtures and CLI regression tests for JSON stdout and Markdown file output.

### Security

- `review-pack` performs local file analysis only. It does not sign, create wallets, handle keys, broadcast transactions, or make network calls.

## v0.3.0 - 2026-06-18

### Added

- Added `analyze-descriptor --descriptor <TEXT>` for output descriptor policy review.
- Added descriptor analysis using `miniscript`, including descriptor type, script type, sanity check, max satisfaction weight, threshold/multisig signals, and timelock signals.
- Added report schema version `0.3` to JSON and Markdown output.
- Added descriptor fixtures and CLI/unit regression tests for simple, sortedmulti, timelock, and invalid descriptors.

### Changed

- Extended script signals with threshold policy support.
- Extended Markdown reports with descriptor detail sections.
- Extended transaction and PSBT reports while preserving existing artifact analysis boundaries.

## v0.2.0 - 2026-06-12

### Added

- Added crates.io-ready package metadata and bumped the crate to `0.2.0`.
- Added `analyze-tx --hex <HEX>` for direct raw transaction analysis without a JSON file.
- Added optional `fetch` feature with `fetch-tx --txid <TXID>` to read public transaction data from mempool.space Esplora over HTTPS and fill prevouts when available.
- Added release automation that publishes to crates.io on `v*` tags using the `CRATES_IO_TOKEN` GitHub secret.
- Added a README demo asset at `docs/assets/demo.svg`.

### Changed

- Transaction analysis continues to report fee unavailable when prevout values are absent instead of inventing a fee.
- `fetch-tx` uses Esplora's public fee field only when prevout data is incomplete, such as the genesis coinbase fallback.

### Security

- The new network path is opt-in behind `--features fetch` and only performs public read-only HTTPS GET requests.
- No signing, key custody, wallet creation, broadcasting, seed phrase handling, or AI artifact upload paths were added.
