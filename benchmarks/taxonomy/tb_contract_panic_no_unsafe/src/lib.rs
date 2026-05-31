use rustdpr_trace::{dpr_function, install_panic_hook};

pub const FN_PARSE: &str = "crate::parse_header";

pub fn parse_header(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PARSE);

    let first = input.first().expect("header byte is required");
    assert!(*first != 0, "zero header is rejected by API contract");
    *first
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn empty_input_contract_panic() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = parse_header(&[]);
    }
}
