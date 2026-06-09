//! Official fixed-version control for RUSTSEC-2025-0105.
//!
//! The vulnerable release created a typed `Box<[T]>` from uninitialized
//! allocation.  Version 0.2.2 initializes the allocation with
//! `T::default()` before exposing typed slices.

use direct_ring_buffer::create_ring_buffer;
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_CREATE_RING_BUFFER_BOUNDARY: &str = "S00001";
pub const FN_DIRECT_RING_BUFFER_FIXED: &str = "crate::run_fixed_public_api_no_oracle_finding";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingBufferObservation {
    pub written: usize,
    pub observed_true_before_write: usize,
}

/// Calls the real fixed public API and verifies that its writable
/// `bool` slice is initialized to `false` before user writes.
pub fn run_fixed_public_api_no_oracle_finding() -> RingBufferObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_DIRECT_RING_BUFFER_FIXED);

    dpr_hit!(SITE_CREATE_RING_BUFFER_BOUNDARY);
    let (mut producer, _consumer) = create_ring_buffer::<bool>(8);

    let mut observed_true_before_write = 0usize;
    let written = producer.write_slices(
        |buf, _offset| {
            observed_true_before_write += buf.iter().filter(|&&b| b).count();
            for slot in buf.iter_mut() {
                *slot = false;
            }
            buf.len()
        },
        Some(8),
    );

    RingBufferObservation {
        written,
        observed_true_before_write,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn fixed_version_initializes_bool_buffer() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        let obs = run_fixed_public_api_no_oracle_finding();
        assert_eq!(obs.written, 8, "{obs:?}");
        assert_eq!(obs.observed_true_before_write, 0, "{obs:?}");
    }
}
