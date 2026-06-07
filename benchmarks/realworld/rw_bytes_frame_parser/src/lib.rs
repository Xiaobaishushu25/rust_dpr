use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn parse_frame(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::parse_frame");
    if input.len() < 2 {
        return 0;
    }
    let declared = input[0] as usize;
    let payload = unsafe {
        dpr_hit!("S00001");
        std::slice::from_raw_parts(input.as_ptr().add(1), input.len() - 1)
    };
    if declared > payload.len() {
        panic!("declared frame length exceeds payload");
    }
    payload[..declared].len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_payload_view() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = parse_frame(&[8, 1, 2, 3]);
    }
}
