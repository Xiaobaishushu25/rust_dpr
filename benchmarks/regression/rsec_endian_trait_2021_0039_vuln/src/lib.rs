//! Regression reproducer for RUSTSEC-2021-0039 / endian_trait.
//!
//! This benchmark invokes the real `endian_trait` implementation for mutable
//! slices. A user-defined safe `Endian` implementation panics during conversion;
//! affected versions can double-drop because the crate temporarily duplicates
//! ownership with `ptr::read` before calling user code.

use endian_trait::Endian;
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::cell::Cell;
use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;

pub const SITE_ENDIAN_TRAIT_SLICE_TO_BE_BOUNDARY: &str = "S00001";
pub const FN_ENDIAN_TRAIT_SLICE_TO_BE: &str = "crate::run_public_api_poc";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndianObservation {
    pub user_impl_panicked: bool,
    pub drop_count_after_unwind: usize,
}

#[derive(Debug)]
pub struct DropTracker {
    id: u32,
    drops: Rc<Cell<usize>>,
    _payload: Box<u64>,
}

impl DropTracker {
    pub fn new(id: u32, drops: Rc<Cell<usize>>) -> Self {
        Self {
            id,
            drops,
            _payload: Box::new(0xEAD1_0000_u64 ^ id as u64),
        }
    }
}

impl Drop for DropTracker {
    fn drop(&mut self) {
        let next = self.drops.get() + 1;
        self.drops.set(next);
        println!("Dropping endian_trait {} count {}", self.id, next);
    }
}

#[derive(Debug)]
pub struct PanickingEndian {
    marker: DropTracker,
    panic_on_to_be: bool,
}

impl PanickingEndian {
    fn new(id: u32, drops: Rc<Cell<usize>>, panic_on_to_be: bool) -> Self {
        Self {
            marker: DropTracker::new(id, drops),
            panic_on_to_be,
        }
    }
}

impl Endian for PanickingEndian {
    fn to_be(self) -> Self {
        if self.panic_on_to_be {
            panic!("RUSTDPR_ENDIAN_TRAIT_USER_IMPL_PANIC");
        }
        self
    }

    fn to_le(self) -> Self {
        self
    }

    fn from_be(self) -> Self {
        self
    }

    fn from_le(self) -> Self {
        self
    }
}

/// Real public-API PoC for RUSTSEC-2021-0039.
pub fn run_public_api_poc() -> EndianObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_ENDIAN_TRAIT_SLICE_TO_BE);

    let drops = Rc::new(Cell::new(0usize));
    let mut values = vec![PanickingEndian::new(39, drops.clone(), true)];

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        dpr_hit!(SITE_ENDIAN_TRAIT_SLICE_TO_BE_BOUNDARY);
        let slice: &mut [PanickingEndian] = values.as_mut_slice();
        let _ = <&mut [PanickingEndian] as Endian>::to_be(slice);
    }));

    drop(values);

    EndianObservation {
        user_impl_panicked: result.is_err(),
        drop_count_after_unwind: drops.get(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[ignore = "intentionally triggers the historical endian_trait panic-safety bug"]
    fn reproduces_public_advisory() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        let observation = run_public_api_poc();
        assert!(observation.user_impl_panicked);
    }
}
