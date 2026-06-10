use rustdpr_trace::{dpr_function, init_trace, install_panic_hook};
use std::io::Cursor;

const MAX_DECODE_BUFFER: usize = 1 << 20;

pub fn run_input(data: &[u8]) -> usize {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    let _guard = dpr_function!("rw_png_decode::run_input");

    let decoder = png::Decoder::new(Cursor::new(data));
    let mut reader = match decoder.read_info() {
        Ok(reader) => reader,
        Err(_) => return 0,
    };

    let Some(size) = reader.output_buffer_size() else {
        return 0;
    };
    if size > MAX_DECODE_BUFFER {
        return 0;
    }

    let mut out = vec![0u8; size];
    match reader.next_frame(&mut out) {
        Ok(info) => info.buffer_size(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_random_bytes_do_not_panic() {
        assert_eq!(run_input(b"not a png"), 0);
    }
}
