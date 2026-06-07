use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNSAFE: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

pub fn process(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    unsafe {
        dpr_hit!(SITE_UNSAFE);
        let width = input.get(0).copied().unwrap() as usize;
        let ptr = &width as *const usize;
        *ptr
    }
}
