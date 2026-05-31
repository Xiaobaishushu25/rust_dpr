use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNSAFE_REGION: &str = "S00001";
pub const FN_TRIGGER: &str = "crate::trigger";

pub fn trigger(input: &[u8]) {
    install_panic_hook();
    let _guard = dpr_function!(FN_TRIGGER);

    unsafe {
        dpr_hit!(SITE_UNSAFE_REGION);
        if input.first() == Some(&0xff) {
            panic!("panic while executing inside unsafe region");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_inside_unsafe_region() {
        init_trace("artifacts/trace.jsonl").unwrap();
        trigger(&[0xff]);
    }
}
