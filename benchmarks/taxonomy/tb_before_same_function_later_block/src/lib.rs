use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_LATER_BLOCK: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);

    if input.len() < 2 {
        panic!("same function panic before later unsafe block");
    }

    let mut out = 0u8;
    unsafe {
        dpr_hit!(SITE_LATER_BLOCK);
        *(&mut out as *mut u8) = input[1];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_before_later_block() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[1]);
    }

    #[test]
    fn reaches_later_block() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[1, 6]), 6);
    }
}
