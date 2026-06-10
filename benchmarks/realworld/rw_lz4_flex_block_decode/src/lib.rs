use rustdpr_trace::{dpr_function, init_trace, install_panic_hook};

const MAX_OUTPUT: usize = 1 << 20;

pub fn run_input(data: &[u8]) -> usize {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    let _guard = dpr_function!("rw_lz4_flex_block_decode::run_input");

    if data.len() < 4 {
        return 0;
    }
    let declared = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if declared > MAX_OUTPUT {
        return 0;
    }

    match lz4_flex::block::decompress_size_prepended(data) {
        Ok(out) => out.len(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_random_bytes_do_not_panic() {
        let _ = run_input(&[4, 0, 0, 0, 1, 2, 3, 4]);
    }
}
