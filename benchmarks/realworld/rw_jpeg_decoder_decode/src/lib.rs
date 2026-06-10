use jpeg_decoder::Decoder;
use rustdpr_trace::{dpr_function, init_trace, install_panic_hook};
use std::io::Cursor;

const MAX_PIXELS: usize = 1_000_000;

pub fn run_input(data: &[u8]) -> usize {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    let _guard = dpr_function!("rw_jpeg_decoder_decode::run_input");

    let mut decoder = Decoder::new(Cursor::new(data));
    if decoder.read_info().is_err() {
        return 0;
    }

    if let Some(info) = decoder.info() {
        let pixels = (info.width as usize).saturating_mul(info.height as usize);
        if pixels > MAX_PIXELS {
            return 0;
        }
    }

    match decoder.decode() {
        Ok(pixels) => pixels.len(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_random_bytes_do_not_panic() {
        assert_eq!(run_input(b"not a jpeg"), 0);
    }
}
