use rustdpr_trace::{dpr_function, init_trace, install_panic_hook};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Packet {
    tag: u8,
    seq: u32,
    payload: Vec<u8>,
}

pub fn run_input(data: &[u8]) -> usize {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    let _guard = dpr_function!("rw_postcard_deser::run_input");

    match postcard::from_bytes::<Packet>(data) {
        Ok(packet) => packet.payload.len() ^ packet.seq as usize ^ packet.tag as usize,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_random_bytes_do_not_panic() {
        let _ = run_input(&[0, 1, 2, 3, 4, 5]);
    }
}
