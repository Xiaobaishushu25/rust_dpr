use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNREACHED_RAW_READ: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";
pub const FN_UNREACHED: &str = "crate::unreached_raw_read";

#[allow(dead_code)]
fn unreached_raw_read(input: &[u8]) -> u8 {
    let _guard = dpr_function!(FN_UNREACHED);
    unsafe {
        dpr_hit!(SITE_UNREACHED_RAW_READ);
        *input.as_ptr()
    }
}

pub fn process(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    assert!(
        input.len() >= 4,
        "contract panic without dangerous path reachability"
    );
    input.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn short_input_contract_panic() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[1, 2]);
    }

    #[test]
    fn long_input_no_dangerous_path() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[1, 2, 3, 4]), 4);
    }
}
