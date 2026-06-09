//! Regression reproducer for RUSTSEC-2025-0105 / GHSA-fp5x-7m4q-449f.
//!
//! This case intentionally invokes the real vulnerable public API from
//! `direct_ring_buffer` 0.2.1.  The advisory says `create_ring_buffer`
//! constructs a typed buffer from uninitialized allocation; creating or
//! reading a `&mut [bool]` over that buffer is Miri-confirmable UB.

use direct_ring_buffer::create_ring_buffer;
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_CREATE_RING_BUFFER_BOUNDARY: &str = "S00001";
pub const FN_DIRECT_RING_BUFFER_VULN: &str = "crate::run_public_api_miri_poc";

/// Calls the real vulnerable public API.  Under Miri this should report
/// undefined behavior because the bool slice is backed by uninitialized
/// memory.  Under a normal runtime it may appear to pass, so the oracle
/// for this regression is explicitly Miri, not process status.
pub fn run_public_api_miri_poc() -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_DIRECT_RING_BUFFER_VULN);

    dpr_hit!(SITE_CREATE_RING_BUFFER_BOUNDARY);
    let (mut producer, _consumer) = create_ring_buffer::<bool>(8);

    producer.write_slices(
        |buf, offset| {
            // The read makes the typed-validity violation explicit for
            // Miri. In the fixed release all values are initialized false.
            let observed_true = buf.iter().filter(|&&b| b).count();
            for slot in buf.iter_mut() {
                *slot = false;
            }
            let _ = observed_true ^ offset;
            buf.len()
        },
        Some(8),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn miri_confirms_public_advisory_uninitialized_bool() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        let written = run_public_api_miri_poc();
        assert_eq!(written, 8);
    }
}
