use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_READ: &str = "S00001";
pub const FN_PARSE: &str = "crate::parse_after_length_guard";

pub fn parse_after_length_guard(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PARSE);

    if input.len() < 4 {
        panic!("length guard rejected input before unsafe parser fast path");
    }

    unsafe {
        dpr_hit!(SITE_RAW_READ);
        *input.as_ptr().add(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn short_input_panics_before_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = parse_after_length_guard(&[1, 2]);
    }

    #[test]
    fn long_input_reaches_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(parse_after_length_guard(&[1, 2, 3, 4]), 4);
    }
}
