//! Fixed-version regression control for RUSTSEC-2021-0016 / ms3d.
//!
//! This benchmark invokes the same real public API as the vulnerable case,
//! `Model::from_reader`, but pins ms3d 0.1.3. The fixed crate zero-initializes
//! the internal buffer before passing it to user-provided `Read` code.

use ms3d::Model;
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::cell::Cell;
use std::io::{self, Read};
use std::rc::Rc;

pub const SITE_MS3D_MODEL_FROM_READER_BOUNDARY: &str = "S00001";
pub const FN_MS3D_MODEL_FROM_READER: &str = "crate::run_public_api_fixed_control";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadObservation {
    pub read_calls: usize,
    pub first_byte_seen_before_write: Option<u8>,
    pub parser_returned_ok: bool,
}

#[derive(Clone)]
struct ObservingRead {
    offset: usize,
    calls: Rc<Cell<usize>>,
    first_byte_seen_before_write: Rc<Cell<Option<u8>>>,
}

impl ObservingRead {
    fn new(calls: Rc<Cell<usize>>, first_byte_seen_before_write: Rc<Cell<Option<u8>>>) -> Self {
        Self {
            offset: 0,
            calls,
            first_byte_seen_before_write,
        }
    }
}

impl Read for ObservingRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.calls.set(self.calls.get() + 1);

        // Safe Rust according to the Read trait contract. In ms3d <= 0.1.2 this
        // observes the crate's uninitialized internal buffer before we write to it.
        if !buf.is_empty() && self.first_byte_seen_before_write.get().is_none() {
            self.first_byte_seen_before_write.set(Some(buf[0]));
        }

        let fixture = minimal_ms3d_stream();
        if self.offset >= fixture.len() {
            return Ok(0);
        }

        let n = (fixture.len() - self.offset).min(buf.len());
        buf[..n].copy_from_slice(&fixture[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

fn minimal_ms3d_stream() -> Vec<u8> {
    let mut bytes = Vec::new();

    // Header: id + version. The parser may continue beyond this point, but the
    // vulnerable evidence is already present at the first user Read call.
    bytes.extend_from_slice(b"MS3D000000");
    bytes.extend_from_slice(&4i32.to_le_bytes());

    // Empty top-level sections. These keep the stream close to a real MS3D file
    // while still being small and deterministic.
    bytes.extend_from_slice(&0u16.to_le_bytes()); // vertices
    bytes.extend_from_slice(&0u16.to_le_bytes()); // triangles
    bytes.extend_from_slice(&0u16.to_le_bytes()); // groups
    bytes.extend_from_slice(&0u16.to_le_bytes()); // materials

    // Animation metadata: fps, current_time, total_frames.
    bytes.extend_from_slice(&24.0f32.to_le_bytes());
    bytes.extend_from_slice(&0.0f32.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());

    bytes.extend_from_slice(&0u16.to_le_bytes()); // joints

    // Optional comment/subversion sections. If a given version stops earlier,
    // these bytes are harmless trailing input.
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&0.0f32.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&0.0f32.to_le_bytes());

    bytes
}

/// Real public-API fixed-version control for RUSTSEC-2021-0016.
pub fn run_public_api_poc() -> ReadObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_MS3D_MODEL_FROM_READER);

    let calls = Rc::new(Cell::new(0usize));
    let first = Rc::new(Cell::new(None));
    let reader = ObservingRead::new(calls.clone(), first.clone());

    dpr_hit!(SITE_MS3D_MODEL_FROM_READER_BOUNDARY);
    let parser_returned_ok = Model::from_reader(reader).is_ok();

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
        assert!(
            observation.read_calls > 0,
            "Model::from_reader should invoke the user-provided Read implementation"
        );
        assert_eq!(
            observation.first_byte_seen_before_write,
            Some(0),
            "fixed ms3d should zero-initialize the buffer before user Read code observes it"
        );
    }
}
