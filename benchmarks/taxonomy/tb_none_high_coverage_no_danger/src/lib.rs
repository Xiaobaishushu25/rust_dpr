use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNREACHED_UNSAFE: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";
pub const FN_DEAD: &str = "crate::dead_unsafe_helper";

fn dead_unsafe_helper(input: &[u8]) -> u8 {
    let _guard = dpr_function!(FN_DEAD);
    unsafe {
        dpr_hit!(SITE_UNREACHED_UNSAFE);
        *input.as_ptr()
    }
}

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let mut acc = 0u8;
    for b in input.iter().copied().take(8) {
        acc = acc.wrapping_add(b.rotate_left(1));
        if b == 13 {
            panic!("ordinary parser contract panic without dangerous path");
        }
    }
    if input.len() == usize::MAX {
        return dead_unsafe_helper(input);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic(expected = "ordinary parser contract panic without dangerous path")]
    fn test_process_with_trigger_byte() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let input = vec![13u8, 1, 2, 3];
        process(&input);
    }
}
