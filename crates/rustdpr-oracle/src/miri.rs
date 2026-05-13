use rustdpr_core::model::{
    OracleFinding,
    OracleKind,
    OracleResult,
    OracleVerdict,
};

pub fn parse_miri_output(output: &str) -> OracleResult {
    let mut findings = Vec::new();

    let verdict = if output.contains("out-of-bounds") {
        OracleVerdict::OutOfBounds
    } else if output.contains("undefined behavior") {
        OracleVerdict::UndefinedBehavior
    } else if output.contains("dangling") {
        OracleVerdict::UseAfterFree
    } else {
        OracleVerdict::Unknown
    };

    if !matches!(verdict, OracleVerdict::Unknown) {
        findings.push(OracleFinding {
            oracle: OracleKind::Miri,
            verdict,
            raw_message: output.to_string(),
        });
    }

    OracleResult { findings }
}