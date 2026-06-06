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

## AI Feature Boundary

AI support is optional and behind a feature flag. The base analyzer is deterministic and local.

Any future external AI provider integration must:

- operate only on the already-produced technical JSON report
- include redaction and allowlist checks
- avoid private keys, seed phrases, wallet files, and signing material
- document exactly what leaves the local machine

## Validation Boundary

This project does not claim Bitcoin consensus validation, Bitcoin Core policy equivalence, mempool acceptance, or final spend safety. Reports are heuristic and should be reviewed by qualified engineers before operational use.
