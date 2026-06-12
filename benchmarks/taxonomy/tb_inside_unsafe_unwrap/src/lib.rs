use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNSAFE: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

pub fn process(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    unsafe {
        dpr_hit!(SITE_UNSAFE);
        let width = input.get(0).copied().unwrap() as usize;
        let ptr = &width as *const usize;
        *ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn test_process_empty_input() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let input: Vec<u8> = vec![];
        process(&input);
    }
}
