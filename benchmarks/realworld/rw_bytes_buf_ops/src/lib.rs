use bytes::{Buf, BufMut, BytesMut};
use rustdpr_trace::{dpr_function, init_trace, install_panic_hook};

const MAX_INPUT: usize = 4096;

pub fn run_input(data: &[u8]) -> usize {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    let _guard = dpr_function!("rw_bytes_buf_ops::run_input");

    let capped = &data[..data.len().min(MAX_INPUT)];
    let mut buf = BytesMut::with_capacity(capped.len() + 16);
    for chunk in capped.chunks(16) {
        buf.put_slice(chunk);
    }

    let mut frozen = buf.freeze();
    let mut checksum = 0usize;
    while frozen.has_remaining() {
        let first = frozen.chunk()[0];
        let take = ((first as usize) & 0x7) + 1;
        let n = take.min(frozen.remaining());
        let piece = frozen.copy_to_bytes(n);
        checksum ^= piece.len();
        checksum = checksum.wrapping_add(piece.first().copied().unwrap_or(0) as usize);
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_buffer_ops_do_not_panic() {
        let _ = run_input(b"abcdef0123456789");
    }
}
