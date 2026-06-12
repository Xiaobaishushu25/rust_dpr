use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_SET_LEN: &str = "S00001";
pub const FN_PROCESS: &str = "crate::reserve_set_len_then_panic";

pub fn reserve_set_len_then_panic(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let len = input.first().copied().unwrap_or(0) as usize;
    let mut buf = Vec::<u8>::with_capacity(8);
    unsafe {
        dpr_hit!(SITE_SET_LEN);
        buf.set_len(len.min(8));
    }
    if len == 7 {
        panic!("panic after manual Vec::set_len");
    }
    buf.len()
}
// ... existing code ...

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic(expected = "panic after manual Vec::set_len")]
    fn test_panic_after_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let input = vec![7u8];
        reserve_set_len_then_panic(&input);
    }
}

