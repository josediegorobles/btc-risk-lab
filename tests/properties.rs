use std::{
    io::Write,
    panic::{catch_unwind, AssertUnwindSafe},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use btc_risk_lab::analyzer;
use proptest::prelude::*;

const SAMPLE_TX_HEX: &str = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff02e80300000000000016001400000000000000000000000000000000000000006400000000000000160014111111111111111111111111111111111111111100000000";
const SAMPLE_SCRIPT_HEX: &str = "52aeb2";

proptest! {
    #[test]
    fn transaction_analysis_never_panics_on_arbitrary_or_mutated_bytes(
        arbitrary in prop::collection::vec(any::<u8>(), 0..512),
        index in any::<usize>(),
        replacement in any::<u8>(),
    ) {
        assert_tx_analysis_does_not_panic(arbitrary);

        let fixture = hex::decode(SAMPLE_TX_HEX).expect("fixture tx hex should decode");
        assert_tx_analysis_does_not_panic(mutate(fixture, index, replacement));
    }

    #[test]
    fn psbt_analysis_never_panics_on_arbitrary_or_mutated_bytes(
        arbitrary in prop::collection::vec(any::<u8>(), 0..512),
        index in any::<usize>(),
        replacement in any::<u8>(),
    ) {
        assert_psbt_analysis_does_not_panic(arbitrary);

        let fixture = STANDARD
            .decode(include_str!("../examples/sample.psbt").trim())
            .expect("fixture PSBT should decode");
        assert_psbt_analysis_does_not_panic(mutate(fixture, index, replacement));
    }

    #[test]
    fn script_analysis_never_panics_on_arbitrary_or_mutated_bytes(
        arbitrary in prop::collection::vec(any::<u8>(), 0..512),
        index in any::<usize>(),
        replacement in any::<u8>(),
    ) {
        assert_script_analysis_does_not_panic(arbitrary);

        let fixture = hex::decode(SAMPLE_SCRIPT_HEX).expect("fixture script hex should decode");
        assert_script_analysis_does_not_panic(mutate(fixture, index, replacement));
    }
}

fn assert_tx_analysis_does_not_panic(bytes: Vec<u8>) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        analyzer::analyze_transaction_hex(&hex::encode(bytes))
    }));

    assert!(outcome.is_ok(), "transaction analysis panicked");
    if let Ok(Ok(report)) = outcome {
        assert_eq!(report.schema_version, "0.3");
        assert!(!report.limitations.is_empty());
    }
}

fn assert_psbt_analysis_does_not_panic(bytes: Vec<u8>) {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile should be available");
    write!(file, "{}", STANDARD.encode(bytes)).expect("tempfile write should succeed");

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        analyzer::analyze_psbt_file(file.path())
    }));

    assert!(outcome.is_ok(), "PSBT analysis panicked");
    if let Ok(Ok(report)) = outcome {
        assert_eq!(report.schema_version, "0.3");
        assert!(!report.limitations.is_empty());
    }
}

fn assert_script_analysis_does_not_panic(bytes: Vec<u8>) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        analyzer::analyze_script_input(&hex::encode(bytes))
    }));

    assert!(outcome.is_ok(), "script analysis panicked");
    if let Ok(Ok(report)) = outcome {
        assert_eq!(report.schema_version, "0.3");
        assert!(!report.limitations.is_empty());
    }
}

fn mutate(mut bytes: Vec<u8>, index: usize, replacement: u8) -> Vec<u8> {
    if bytes.is_empty() {
        bytes.push(replacement);
        return bytes;
    }

    let index = index % bytes.len();
    bytes[index] = replacement;
    bytes
}
