use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_SET_LEN: &str = "S00001";
pub const FN_BUILD: &str = "crate::build_vec";

pub fn build_vec(trigger: bool) {
    install_panic_hook();
    let _guard = dpr_function!(FN_BUILD);

    let mut v: Vec<u8> = Vec::with_capacity(4);
    unsafe {
        dpr_hit!(SITE_SET_LEN);
        v.set_len(4);
    }

    assert!(!trigger, "panic after set_len dangerous site");
    drop(v);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_set_len() {
        init_trace("artifacts/trace.jsonl").unwrap();
        build_vec(true);
    }
}
