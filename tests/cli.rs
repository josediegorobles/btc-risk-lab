use assert_cmd::Command;
use predicates::str::contains;

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
