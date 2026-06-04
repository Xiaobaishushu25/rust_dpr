use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_SLICE: &str = "S00001";
pub const FN_PARSE_PACKET: &str = "crate::parse_packet";

pub fn parse_packet(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_PARSE_PACKET);

    if input.len() < 2 {
       return 0;
    }

    let len = input[0] as usize;

    let view = unsafe {
        dpr_hit!(SITE_RAW_SLICE);
        std::slice::from_raw_parts(input.as_ptr().add(1), input.len() - 1)
    };

    if len > view.len() {
        panic!("declared length exceeds payload");
    }

    view[..len].len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn length_check_after_raw_slice_view() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = parse_packet(&[8, 1, 2, 3]);
    }
}