
//! Regression reproducer for RUSTSEC-2021-0012 / cdr.
//!
//! This benchmark invokes the real `cdr` public API `deserialize_from` on a
//! serialized `Vec<u8>`. The vulnerable `Deserializer::read_vec` implementation
//! allocated an uninitialized vector and passed it to the user-provided `Read`
//! implementation. The custom reader below observes the destination buffer
//! before filling it, which is safe for the reader but invalid if the buffer is
//! uninitialized.

use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::cell::Cell;
use std::io::{self, Read};
use std::rc::Rc;

pub const SITE_CDR_DESERIALIZE_FROM_BOUNDARY: &str = "S00001";
pub const FN_CDR_DESERIALIZE_FROM: &str = "crate::run_public_api_poc";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadObservation {
    pub read_calls: usize,
    pub first_byte_seen_before_write: Option<u8>,
    pub deserializer_returned_ok: bool,
}

#[derive(Clone)]
struct ObservingRead {
    data: Vec<u8>,
    offset: usize,
    calls: Rc<Cell<usize>>,
    first_byte_seen_before_write: Rc<Cell<Option<u8>>>,
}

impl ObservingRead {
    fn new(data: Vec<u8>, calls: Rc<Cell<usize>>, first_byte_seen_before_write: Rc<Cell<Option<u8>>>) -> Self {
        Self { data, offset: 0, calls, first_byte_seen_before_write }
    }
}

impl Read for ObservingRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.calls.set(self.calls.get() + 1);

        // Later deserialize_from reads fill Vec payloads. In cdr <= 0.2.3,
        // Deserializer::read_vec exposed an uninitialized vector buffer here.
        if self.calls.get() >= 2 && !buf.is_empty() && self.first_byte_seen_before_write.get().is_none() {
            self.first_byte_seen_before_write.set(Some(buf[0]));
        }

        if self.offset >= self.data.len() {
            return Ok(0);
        }
        let n = (self.data.len() - self.offset).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

fn serialized_vec_fixture() -> Vec<u8> {
    let payload = vec![0x41u8, 0x42, 0x43, 0x44, 0x45, 0x46];
    cdr::serialize::<_, _, cdr::CdrBe>(&payload, cdr::Infinite)
        .expect("serialize Vec<u8> fixture for cdr regression")
}

/// Real public-API PoC for RUSTSEC-2021-0012.
pub fn run_public_api_poc() -> ReadObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_CDR_DESERIALIZE_FROM);

    let calls = Rc::new(Cell::new(0usize));
    let first = Rc::new(Cell::new(None));
    let reader = ObservingRead::new(serialized_vec_fixture(), calls.clone(), first.clone());

    dpr_hit!(SITE_CDR_DESERIALIZE_FROM_BOUNDARY);
    let deserializer_returned_ok = cdr::deserialize_from::<_, Vec<u8>, _>(reader, cdr::Infinite).is_ok();

    ReadObservation {
        read_calls: calls.get(),
        first_byte_seen_before_write: first.get(),
        deserializer_returned_ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn rustdpr_deterministic_trace_replay() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        let observation = run_public_api_poc();
        assert!(observation.read_calls >= 2, "deserialize_from should read the serialized Vec payload");
    }
}
