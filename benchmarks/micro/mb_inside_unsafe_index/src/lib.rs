use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNSAFE_INDEX_REGION: &str = "S00001";
pub const FN_PICK: &str = "crate::pick_inside_unsafe";

pub fn pick_inside_unsafe(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PICK);

    unsafe {
        dpr_hit!(SITE_UNSAFE_INDEX_REGION);
        let idx = input.first().copied().unwrap_or(9) as usize;
        // Deliberately use safe indexing inside the unsafe region so the panic
        // site is temporally and structurally inside the dangerous region.
        input[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn index_panic_inside_unsafe_region() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = pick_inside_unsafe(&[4, 10]);
    }

    #[test]
    fn in_bounds_index_returns_value() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(pick_inside_unsafe(&[1, 77]), 77);
    }
}
