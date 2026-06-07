use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::ffi::{CString, c_char};

pub const SITE_FOREIGN_GETENV: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

unsafe extern "C" {
    fn getenv(name: *const c_char) -> *mut c_char;
}

pub fn process(input: &[u8]) -> bool {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let key = if input.first().copied().unwrap_or(0) == 0 {
        "RUSTDPR_UNLIKELY_ENV_KEY_0"
    } else {
        "RUSTDPR_UNLIKELY_ENV_KEY_1"
    };
    let c_key = CString::new(key).unwrap();

    unsafe {
        dpr_hit!(SITE_FOREIGN_GETENV);
        !getenv(c_key.as_ptr()).is_null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn normal_runtime_can_call_foreign_getenv() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[0]);
    }
}
