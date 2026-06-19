# BTC Risk Lab Policy Pack

- Schema: `0.5`
- Pack type: `policy_pack`
- Consolidated risk: `medium`

## Artifacts Detected

| Artifact | File |
|---|---|
| `descriptor` | `descriptor.txt` |
| `psbt` | `psbt.base64` |
| `transaction` | `tx.json` |
| `script` | `script.txt` |
| `policy_notes` | `policy.md` |
| `policy_notes` | `policy.yaml` |
| `metadata` | `metadata.json` |

## Evidence Documents

| Artifact | File | Format | Summary |
|---|---|---|---|
| `policy_notes` | `policy.md` | `markdown` | bytes: 264; lines: 6; headings: 1 |
| `policy_notes` | `policy.yaml` | `yaml` | bytes: 118; lines: 5; key_like_lines: 5 |
| `metadata` | `metadata.json` | `json` | bytes: 166; lines: 7; json_type: object; top_level_keys: 5; keys: environment, owner, prepared_by, purpose, review_date |

## Findings

- **Descriptor and PSBT multisig signals differ** (`medium`, `descriptor-psbt-multisig-mismatch`): Descriptor signal is `true`, while PSBT signal is `false`. This may be valid for incomplete PSBT data, but it requires manual review.
- **Descriptor and PSBT timelock signals match** (`low`, `descriptor-psbt-timelock-match`): Both descriptor and PSBT expose `false` for this signal.
- **Descriptor threshold cannot be fully checked against PSBT** (`unknown`, `descriptor-psbt-threshold-unavailable`): The descriptor exposes threshold policy, but the current PSBT analyzer only exposes heuristic multisig/script signals, not an exact quorum or signer set. Real descriptor-to-PSBT equivalence is not verified.
- **Descriptor-to-PSBT equivalence is not proven** (`unknown`, `descriptor-psbt-equivalence-not-verified`): The review pack compares available policy signals only. It does not derive addresses, reconstruct wallet origin data, or prove that the PSBT spends from the provided descriptor.
- **Transaction and PSBT counts match** (`low`, `tx-psbt-counts-match`): Both artifacts report 1 input(s) and 2 output(s). This is a count-level check only, not transaction equivalence.
- **Transaction-to-PSBT equivalence is not proven** (`unknown`, `tx-psbt-equivalence-not-verified`): The review pack compares input/output counts only. It does not prove that tx.json is the finalized or extracted transaction for psbt.base64.
- **Threshold policy signal detected** (`low`, `threshold-policy-signal`): At least one artifact exposes threshold or multisig policy. Review signer count, quorum, key custody, backup paths, and emergency access.
- **Fee evidence is incomplete** (`medium`, `fee-evidence-missing`): Fee review depends on UTXO or prevout evidence. Without it, economic review remains partial.
- **Timelock signal detected** (`medium`, `timelock-signal`): At least one artifact exposes absolute or relative timelock policy. Confirm block height, median-time, sequence, and recovery semantics in policy notes.
- **Descriptor satisfaction weight is available** (`low`, `descriptor-weight-available`): The descriptor analyzer reports a max satisfaction weight of 253 WU. This is useful review evidence, not a transaction-level fee-rate proof.
- **Transaction fee estimate available** (`low`, `transaction-fee-estimated`): Transaction includes an estimated fee of 900 sats from available analyzer evidence.

## Warnings

- **Descriptor: Threshold or multisig policy detected** (`low`, `descriptor:threshold-policy`): The descriptor includes threshold-like signing policy. Review signer count, quorum, backup paths, and key origin documentation.
- **PSBT: Cannot estimate fee** (`medium`, `psbt:missing-utxo-data`): The PSBT does not include enough UTXO data for every input. Fee and economic risk analysis remain partial.
- **PSBT: Dust-like output detected** (`medium`, `psbt:dust-output`): At least one non-zero output is below the heuristic dust threshold for its script type.
- **Transaction: Dust-like output detected** (`medium`, `transaction:dust-output`): At least one non-zero output is below the heuristic dust threshold for its script type. This can indicate uneconomic outputs, spam-like construction, or operational mistakes.
- **Script: Timelock signal detected** (`medium`, `script:timelock-signal`): The script includes absolute or relative timelock opcodes. Confirm block height, median time, and sequence semantics before operational use.
- **Descriptor and PSBT multisig signals differ** (`medium`, `descriptor-psbt-multisig-mismatch`): Descriptor signal is `true`, while PSBT signal is `false`. This may be valid for incomplete PSBT data, but it requires manual review.
- **Descriptor threshold cannot be fully checked against PSBT** (`unknown`, `descriptor-psbt-threshold-unavailable`): The descriptor exposes threshold policy, but the current PSBT analyzer only exposes heuristic multisig/script signals, not an exact quorum or signer set. Real descriptor-to-PSBT equivalence is not verified.
- **Descriptor-to-PSBT equivalence is not proven** (`unknown`, `descriptor-psbt-equivalence-not-verified`): The review pack compares available policy signals only. It does not derive addresses, reconstruct wallet origin data, or prove that the PSBT spends from the provided descriptor.
- **Transaction-to-PSBT equivalence is not proven** (`unknown`, `tx-psbt-equivalence-not-verified`): The review pack compares input/output counts only. It does not prove that tx.json is the finalized or extracted transaction for psbt.base64.

## Missing Evidence

- psbt: witness_utxo or non_witness_utxo for every PSBT input
- The descriptor exposes threshold policy, but the current PSBT analyzer only exposes heuristic multisig/script signals, not an exact quorum or signer set. Real descriptor-to-PSBT equivalence is not verified.

## Per-Artifact Summary

### `descriptor` (Analyzed)

- Risk: `low`
- descriptor_type: `wsh_sortedmulti`
- script_type: `p2wsh`
- sanity_check: `true`
- max_satisfaction_weight_wu: `253`

### `psbt` (Analyzed)

- Risk: `medium`
- inputs: `1`
- outputs: `2`
- inputs_with_witness_utxo: `0`
- inputs_with_non_witness_utxo: `0`
- Missing data:
  - witness_utxo or non_witness_utxo for every PSBT input

### `transaction` (Analyzed)

- Risk: `medium`
- inputs: `1`
- outputs: `2`
- output_value_sats: `1100`
- estimated_fee_sats: `900`

### `script` (Analyzed)

- Risk: `medium`
- script_type: `unknown`
- byte_len: `1`
- opcode_count: `1`
- complexity: `low`

## Review Questions

- Have reviewers independently confirmed that input/output counts, destinations, amounts, and fees match the intended transaction?
- Which missing data must be collected before treating this review pack as complete?
- Do descriptor.txt, PSBT data, transaction data, and policy notes describe the same intended signing and spending policy?
- Does the written policy identify each signer role, quorum, custody model, recovery path, and approval authority?
- Do descriptor, PSBT, and transaction artifacts match the documented policy intent without relying on this tool to prove formal equivalence?
- Have custodians or auditors independently confirmed destinations, amounts, fee assumptions, and change handling?
- Are absolute or relative timelocks documented with operational consequences and emergency procedures?
- Does metadata identify owner, prepared_by, review_date, environment, and whether this pack is public-demo or production evidence?
- Which missing evidence must be collected before approving, signing, or relying on this policy pack?

## Limitations

- This is an explainability and reporting tool, not a consensus-level Bitcoin validator.
- The policy-pack command performs local file analysis only and does not make network calls.
- The tool does not create wallets, sign transactions, custody funds, request seed phrases, handle private keys, or broadcast transactions.
- Cross-artifact findings compare available signals and counts only; formal descriptor, PSBT, transaction, or wallet equivalence is not proven.
- Fee and weight findings are analyzer evidence, not Bitcoin Core mempool acceptance or fee-rate validation.
- Markdown and YAML policy evidence is summarized structurally; the tool does not semantically validate natural-language policy commitments.
