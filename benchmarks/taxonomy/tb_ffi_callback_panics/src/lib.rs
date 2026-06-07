use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FFI_BOUNDARY: &str = "S00001";
pub const FN_BRIDGE: &str = "crate::bridge";

pub type Predicate = extern "C-unwind" fn(u8) -> bool;

extern "C-unwind" fn predicate(byte: u8) -> bool {
    if byte == 0xff {
        panic!("taxonomy callback predicate panic across FFI boundary");
    }
    byte % 2 == 0
}

pub fn bridge(input: &[u8]) -> bool {
    install_panic_hook();
    let _guard = dpr_function!(FN_BRIDGE);
    let byte = input.first().copied().unwrap_or(0xff);
    unsafe {
        dpr_hit!(SITE_FFI_BOUNDARY);
        let pred: Predicate = predicate;
        pred(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn predicate_panics_across_boundary() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = bridge(&[0xff]);
    }
}
