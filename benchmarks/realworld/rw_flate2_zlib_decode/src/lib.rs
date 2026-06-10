use flate2::read::ZlibDecoder;
use rustdpr_trace::{dpr_function, init_trace, install_panic_hook};
use std::io::{Cursor, Read};

const MAX_OUTPUT: u64 = 1 << 20;

pub fn run_input(data: &[u8]) -> usize {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    let _guard = dpr_function!("rw_flate2_zlib_decode::run_input");

    let decoder = ZlibDecoder::new(Cursor::new(data));
    let mut limited = decoder.take(MAX_OUTPUT);
    let mut out = Vec::new();
    match limited.read_to_end(&mut out) {
        Ok(_) => out.len(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_random_bytes_do_not_panic() {
        let _ = run_input(b"not zlib");
    }
}
