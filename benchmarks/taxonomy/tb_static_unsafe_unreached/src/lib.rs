use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_DEAD_UNSAFE: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";
pub const FN_DEAD: &str = "crate::dead_unsafe_helper";

#[allow(dead_code)]
fn dead_unsafe_helper(input: &[u8]) -> u8 {
    let _guard = dpr_function!(FN_DEAD);
    unsafe {
        dpr_hit!(SITE_DEAD_UNSAFE);
        *input.as_ptr()
    }
}

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    input
        .first()
        .copied()
        .expect("panic-only path; dead unsafe helper is not called")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn empty_input_panic_no_dangerous_hit() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[]);
    }
}
