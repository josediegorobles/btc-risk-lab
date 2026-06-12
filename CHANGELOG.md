# Changelog

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
