use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn decode_packet(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::decode_packet");
    if input.len() < 2 { return 0; }
    let len = input[0] as usize;
    let mut out: Vec<u8> = Vec::with_capacity(len.min(32));
    unsafe {
        dpr_hit!("S00001");
        out.set_len(len.min(32));
    }
    if len > input.len() - 1 {
        panic!("decoded packet length exceeds input");
    }
    out.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_decoder_set_len() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = decode_packet(&[9, 1, 2, 3]);
    }
}
