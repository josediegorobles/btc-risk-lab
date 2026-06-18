# Roadmap

## MVP

- [x] CLI skeleton with `clap`
- [x] transaction analysis from raw hex JSON
- [x] PSBT analysis from base64 input
- [x] script analysis from hex or a small ASM subset
- [x] descriptor parsing and policy hints with `miniscript`
- [x] report schema versioning
- [x] JSON and Markdown reports
- [x] risk warnings with human explanations
- [x] GitHub Actions CI

## Near-Term

- stronger ASM parser and script disassembly
- richer PSBT field coverage
- fee-rate estimation when weight and prevouts are complete
- Taproot-specific output and script-path signals
- additional fixture coverage for common wallet and exchange patterns

## AI Reporting Layer

- redaction pipeline before any provider call
- prompt template based only on the technical JSON report
- provider abstraction for OpenAI-compatible APIs
- deterministic tests using mocked AI responses
- explicit audit log showing what data would be sent

## Due Diligence Use Cases

- batch analysis for transaction review packs
- policy review for multisig and timelock setups
- PSBT readiness checklist
- executive PDF or Markdown due diligence reports
- CI mode for teams that want checks on generated Bitcoin artifacts

## Non-Goals

- wallet creation
- transaction signing
- key management
- seed phrase handling
- custody
- broadcasting
- consensus-level validation claims
