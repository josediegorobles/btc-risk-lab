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
