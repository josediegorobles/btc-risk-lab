use anyhow::{bail, Context, Result};
use bitcoin::{Address, Network, Script, ScriptBuf};

use super::{
    common_limitations, complexity, summary, warning, ArtifactType, Complexity, RiskLevel,
    RiskReport, ScriptAnalysis, ScriptSignals,
};

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_RETURN: u8 = 0x6a;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

#[derive(Debug)]
pub struct TimelockSignals {
    pub absolute: bool,
    pub relative: bool,
}

pub fn analyze_script_input(input: &str) -> Result<RiskReport> {
    let script = parse_script(input)?;
    let analysis = analyze_script(&script);
    let mut warnings = Vec::new();
    let missing_data = Vec::new();

    if analysis.signals.multisig {
        warnings.push(warning(
            "multisig-signal",
            RiskLevel::Low,
            "Multisig signal detected",
            "The script includes CHECKMULTISIG. Validate threshold, key origin assumptions, and recovery procedures outside this tool.",
        ));
    }

    if analysis.signals.timelock || analysis.signals.relative_timelock {
        warnings.push(warning(
            "timelock-signal",
            RiskLevel::Medium,
            "Timelock signal detected",
            "The script includes absolute or relative timelock opcodes. Confirm block height, median time, and sequence semantics before operational use.",
        ));
    }

    if analysis.complexity.label == "high" {
        warnings.push(warning(
            "script-complexity",
            RiskLevel::Medium,
            "High script complexity",
            "The script has enough branching, opcode count, or policy signals to deserve manual review.",
        ));
    }

    let risk = RiskLevel::from_warnings(&warnings, &missing_data);
    Ok(RiskReport {
        schema_version: super::REPORT_SCHEMA_VERSION.to_owned(),
        artifact_type: ArtifactType::Script,
        risk,
        summary: vec![
            summary("script_type", &analysis.script_type),
            summary("byte_len", analysis.byte_len),
            summary("opcode_count", analysis.opcode_count),
            summary("complexity", &analysis.complexity.label),
        ],
        warnings,
        missing_data,
        limitations: common_limitations(),
        transaction: None,
        psbt: None,
        script: Some(analysis),
        descriptor: None,
    })
}

pub fn analyze_script_bytes(bytes: &[u8]) -> ScriptAnalysis {
    let script = ScriptBuf::from_bytes(bytes.to_vec());
    analyze_script(&script)
}

fn analyze_script(script: &Script) -> ScriptAnalysis {
    let bytes = script.as_bytes();
    let lock_signals = contains_timelock(bytes);
    let signals = ScriptSignals {
        multisig: contains_multisig(bytes),
        threshold: false,
        timelock: lock_signals.absolute,
        relative_timelock: lock_signals.relative,
        op_return: bytes.first().is_some_and(|opcode| *opcode == OP_RETURN),
    };
    let opcode_count = opcode_count(bytes);
    let complexity = script_complexity(bytes, opcode_count, &signals);

    ScriptAnalysis {
        byte_len: bytes.len(),
        opcode_count,
        script_type: classify_script(script),
        signals,
        complexity,
    }
}

fn parse_script(input: &str) -> Result<ScriptBuf> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("script cannot be empty");
    }

    if looks_like_hex(trimmed) {
        return Ok(ScriptBuf::from_bytes(
            hex::decode(trimmed).context("script hex is invalid")?,
        ));
    }

    parse_asm_subset(trimmed)
}

fn looks_like_hex(input: &str) -> bool {
    input.len().is_multiple_of(2)
        && !input.contains(char::is_whitespace)
        && input.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn parse_asm_subset(input: &str) -> Result<ScriptBuf> {
    let mut bytes = Vec::new();

    for token in input.split_whitespace() {
        match token {
            "0" | "OP_0" => bytes.push(OP_0),
            "1" | "OP_1" | "OP_TRUE" => bytes.push(OP_1),
            "2" | "OP_2" => bytes.push(0x52),
            "3" | "OP_3" => bytes.push(0x53),
            "4" | "OP_4" => bytes.push(0x54),
            "5" | "OP_5" => bytes.push(0x55),
            "6" | "OP_6" => bytes.push(0x56),
            "7" | "OP_7" => bytes.push(0x57),
            "8" | "OP_8" => bytes.push(0x58),
            "9" | "OP_9" => bytes.push(0x59),
            "10" | "OP_10" => bytes.push(0x5a),
            "11" | "OP_11" => bytes.push(0x5b),
            "12" | "OP_12" => bytes.push(0x5c),
            "13" | "OP_13" => bytes.push(0x5d),
            "14" | "OP_14" => bytes.push(0x5e),
            "15" | "OP_15" => bytes.push(0x5f),
            "16" | "OP_16" => bytes.push(0x60),
            "OP_RETURN" => bytes.push(OP_RETURN),
            "OP_CHECKLOCKTIMEVERIFY" | "OP_CLTV" => bytes.push(OP_CHECKLOCKTIMEVERIFY),
            "OP_CHECKSEQUENCEVERIFY" | "OP_CSV" => bytes.push(OP_CHECKSEQUENCEVERIFY),
            "OP_CHECKMULTISIG" => bytes.push(OP_CHECKMULTISIG),
            "OP_CHECKMULTISIGVERIFY" => bytes.push(OP_CHECKMULTISIGVERIFY),
            hex_data if looks_like_hex(hex_data) => {
                let data = hex::decode(hex_data).context("ASM hex push is invalid")?;
                if data.len() > 75 {
                    bail!("ASM parser currently supports direct pushes up to 75 bytes");
                }
                bytes.push(data.len() as u8);
                bytes.extend(data);
            }
            unknown => bail!("unsupported ASM token `{unknown}`"),
        }
    }

    Ok(ScriptBuf::from_bytes(bytes))
}

pub fn classify_script(script: &Script) -> String {
    let bytes = script.as_bytes();
    if bytes.len() == 25
        && bytes[0] == 0x76
        && bytes[1] == 0xa9
        && bytes[2] == 0x14
        && bytes[23] == 0x88
        && bytes[24] == 0xac
    {
        "p2pkh".to_owned()
    } else if bytes.len() == 23 && bytes[0] == 0xa9 && bytes[1] == 0x14 && bytes[22] == 0x87 {
        "p2sh".to_owned()
    } else if bytes.len() == 22 && bytes[0] == OP_0 && bytes[1] == 0x14 {
        "p2wpkh".to_owned()
    } else if bytes.len() == 34 && bytes[0] == OP_0 && bytes[1] == 0x20 {
        "p2wsh".to_owned()
    } else if bytes.len() == 34 && bytes[0] == OP_1 && bytes[1] == 0x20 {
        "p2tr".to_owned()
    } else if bytes.first().is_some_and(|opcode| *opcode == OP_RETURN) {
        "op_return".to_owned()
    } else {
        "unknown".to_owned()
    }
}

pub fn script_address(script: &Script) -> Option<String> {
    Address::from_script(script, Network::Bitcoin)
        .ok()
        .map(|address| address.to_string())
}

pub fn dust_threshold_sats(script_type: &str) -> u64 {
    match script_type {
        "op_return" => 0,
        "p2wpkh" | "p2wsh" | "p2tr" => 294,
        _ => 546,
    }
}

pub fn contains_multisig(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|opcode| matches!(*opcode, OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY))
}

pub fn contains_timelock(bytes: &[u8]) -> TimelockSignals {
    TimelockSignals {
        absolute: bytes.contains(&OP_CHECKLOCKTIMEVERIFY),
        relative: bytes.contains(&OP_CHECKSEQUENCEVERIFY),
    }
}

fn opcode_count(bytes: &[u8]) -> usize {
    let mut index = 0;
    let mut count = 0;

    while index < bytes.len() {
        count += 1;
        let opcode = bytes[index] as usize;
        index += 1;

        if (1..=75).contains(&opcode) {
            index = index.saturating_add(opcode);
        }
    }

    count
}

fn script_complexity(bytes: &[u8], opcode_count: usize, signals: &ScriptSignals) -> Complexity {
    let mut score = 0;
    let mut factors = vec![
        format!("{} bytes", bytes.len()),
        format!("{opcode_count} opcodes"),
    ];

    if opcode_count > 8 {
        score += 2;
        factors.push("more than 8 opcodes".to_owned());
    }

    if contains_any(bytes, &[0x63, 0x64, 0x67, 0x68]) {
        score += 2;
        factors.push("branching opcode detected".to_owned());
    }

    if signals.multisig {
        score += 2;
        factors.push("multisig opcode detected".to_owned());
    }

    if signals.timelock || signals.relative_timelock {
        score += 2;
        factors.push("timelock opcode detected".to_owned());
    }

    complexity(score, factors)
}

fn contains_any(bytes: &[u8], opcodes: &[u8]) -> bool {
    bytes.iter().any(|byte| opcodes.contains(byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_multisig_and_timelock_from_asm() {
        let report = analyze_script_input("2 OP_CHECKMULTISIG OP_CHECKLOCKTIMEVERIFY").unwrap();
        let analysis = report.script.unwrap();

        assert!(analysis.signals.multisig);
        assert!(analysis.signals.timelock);
        assert_eq!(report.risk, RiskLevel::Medium);
    }

    #[test]
    fn classifies_p2wpkh() {
        let script = ScriptBuf::from_bytes(
            hex::decode("00140000000000000000000000000000000000000000").unwrap(),
        );

        assert_eq!(classify_script(&script), "p2wpkh");
    }
}
