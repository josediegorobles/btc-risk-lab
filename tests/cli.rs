use assert_cmd::Command;
use predicates::str::contains;
use std::fs;

#[test]
fn analyze_tx_outputs_markdown() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "analyze-tx",
        "--input",
        "examples/tx.json",
        "--format",
        "markdown",
    ]);

    cmd.assert()
        .success()
        .stdout(contains("BTC Risk Lab Report"))
        .stdout(contains("estimated_fee_sats"));
}

#[test]
fn analyze_tx_accepts_raw_hex_without_prevouts() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "analyze-tx",
        "--hex",
        "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff02e80300000000000016001400000000000000000000000000000000000000006400000000000000160014111111111111111111111111111111111111111100000000",
        "--format",
        "markdown",
    ]);

    cmd.assert()
        .success()
        .stdout(contains("BTC Risk Lab Report"))
        .stdout(contains("Cannot estimate fee"))
        .stdout(contains("prevout values for every input"));
}

#[cfg(feature = "fetch")]
#[test]
fn fetch_tx_command_is_available_with_fetch_feature() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.arg("--help");

    cmd.assert().success().stdout(contains("fetch-tx"));
}

#[test]
fn analyze_script_outputs_json() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "analyze-script",
        "--script",
        "OP_CHECKMULTISIG OP_CHECKSEQUENCEVERIFY",
        "--format",
        "json",
    ]);

    cmd.assert()
        .success()
        .stdout(contains("\"risk\": \"medium\""))
        .stdout(contains("\"multisig\": true"));
}

#[test]
fn analyze_descriptor_outputs_json() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "analyze-descriptor",
        "--descriptor",
        include_str!("fixtures/descriptors/sortedmulti.txt").trim(),
        "--format",
        "json",
    ]);

    cmd.assert()
        .success()
        .stdout(contains("\"schema_version\": \"0.3\""))
        .stdout(contains("\"artifact_type\": \"descriptor\""))
        .stdout(contains("\"descriptor_type\": \"wsh_sortedmulti\""))
        .stdout(contains("\"threshold\": true"));
}

#[test]
fn analyze_descriptor_outputs_markdown() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "analyze-descriptor",
        "--descriptor",
        include_str!("fixtures/descriptors/timelock.txt").trim(),
        "--format",
        "markdown",
    ]);

    cmd.assert()
        .success()
        .stdout(contains("BTC Risk Lab Report"))
        .stdout(contains("Descriptor Detail"))
        .stdout(contains("Timelock signal detected"));
}

#[test]
fn analyze_descriptor_rejects_invalid_descriptor() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "analyze-descriptor",
        "--descriptor",
        include_str!("fixtures/descriptors/invalid.txt").trim(),
        "--format",
        "json",
    ]);

    cmd.assert().failure().stderr(contains(
        "descriptor input is not a valid public-key output descriptor",
    ));
}

#[test]
fn review_pack_outputs_json() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "review-pack",
        "--input",
        "tests/fixtures/review-packs/complete",
        "--format",
        "json",
    ]);

    cmd.assert()
        .success()
        .stdout(contains("\"schema_version\": \"0.4\""))
        .stdout(contains("\"artifacts_detected\""))
        .stdout(contains("\"consolidated_risk\""))
        .stdout(contains("\"cross_artifact_findings\""))
        .stdout(contains("\"tx-psbt-counts-match\""));
}

#[test]
fn review_pack_outputs_markdown_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output = temp_dir.path().join("review.md");

    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "review-pack",
        "--input",
        "tests/fixtures/review-packs/complete",
        "--format",
        "markdown",
        "--output",
        output.to_str().unwrap(),
    ]);

    cmd.assert().success().stdout("");

    let rendered = fs::read_to_string(output).unwrap();
    assert!(rendered.contains("BTC Risk Lab Review Pack"));
    assert!(rendered.contains("Cross-Artifact Findings"));
    assert!(rendered.contains("Review Questions"));
    assert!(rendered.contains("Limitations"));
}

#[test]
fn policy_pack_outputs_json() {
    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "policy-pack",
        "--input",
        "tests/fixtures/policy-packs/multisig-timelock",
        "--format",
        "json",
    ]);

    cmd.assert()
        .success()
        .stdout(contains("\"schema_version\": \"0.5\""))
        .stdout(contains("\"pack_type\": \"policy_pack\""))
        .stdout(contains("\"evidence_documents\""))
        .stdout(contains("\"missing_evidence\""))
        .stdout(contains("\"descriptor-psbt-multisig-mismatch\""));
}

#[test]
fn policy_pack_outputs_markdown_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output = temp_dir.path().join("policy-pack.md");

    let mut cmd = Command::cargo_bin("btc-risk-lab").unwrap();
    cmd.args([
        "policy-pack",
        "--input",
        "tests/fixtures/policy-packs/multisig-timelock",
        "--format",
        "markdown",
        "--output",
        output.to_str().unwrap(),
    ]);

    cmd.assert().success().stdout("");

    let rendered = fs::read_to_string(output).unwrap();
    assert!(rendered.contains("BTC Risk Lab Policy Pack"));
    assert!(rendered.contains("Evidence Documents"));
    assert!(rendered.contains("Findings"));
    assert!(rendered.contains("Missing Evidence"));
    assert!(rendered.contains("Limitations"));
}
