use rustdpr_trace::{dpr_function, install_panic_hook};

pub const FN_PARSE: &str = "crate::parse";

pub fn parse(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PARSE);
    let first = input.first().unwrap();
    *first
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panics_on_empty() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = parse(&[]);
    }

    #[test]
    fn non_empty_ok() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(parse(&[9]), 9);
    }
}
