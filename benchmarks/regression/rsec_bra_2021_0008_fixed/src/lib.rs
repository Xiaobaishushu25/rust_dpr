
//! Regression reproducer for RUSTSEC-2021-0008 / bra.
//!
//! This benchmark invokes the real `bra` public API by constructing a
//! `GreedyAccessReader` and calling its `BufRead::fill_buf` implementation.
//! Affected versions allocated an uninitialized internal buffer and exposed it
//! to the wrapped user-provided `Read` implementation.

use bra::GreedyAccessReader;
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::cell::Cell;
use std::io::{self, BufRead, Read};
use std::rc::Rc;

pub const SITE_BRA_FILL_BUF_BOUNDARY: &str = "S00001";
pub const FN_BRA_FILL_BUF: &str = "crate::run_public_api_poc";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadObservation {
    pub read_calls: usize,
    pub first_byte_seen_before_write: Option<u8>,
    pub fill_buf_returned_ok: bool,
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

        // In bra 0.1.0, GreedyAccessReader::fill_buf passed an uninitialized
        // internal buffer into this user Read implementation.
        if !buf.is_empty() && self.first_byte_seen_before_write.get().is_none() {
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

/// Real public-API PoC for RUSTSEC-2021-0008.
pub fn run_public_api_poc() -> ReadObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_BRA_FILL_BUF);

    let calls = Rc::new(Cell::new(0usize));
    let first = Rc::new(Cell::new(None));
    let inner = ObservingRead::new(b"RustDPR bra regression fixture".to_vec(), calls.clone(), first.clone());
    let mut reader = GreedyAccessReader::with_capacity(inner, 16);

    dpr_hit!(SITE_BRA_FILL_BUF_BOUNDARY);
    let fill_buf_returned_ok = reader.fill_buf().map(|buf| !buf.is_empty()).unwrap_or(false);

    ReadObservation {
        read_calls: calls.get(),
        first_byte_seen_before_write: first.get(),
        fill_buf_returned_ok,
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
        assert!(observation.read_calls > 0, "GreedyAccessReader::fill_buf should read from the wrapped reader");
    }
}
