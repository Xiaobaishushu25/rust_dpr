use rustdpr_trace::hit;

pub fn trigger(flag: bool) {
    if flag {
        panic!("guard panic before unsafe");
    }

    let x = 1u8;
    let p = &x as *const u8;

    unsafe {
        hit("S0001");
        let _ = *p;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::{init_trace, install_panic_hook};
    use std::path::PathBuf;

    #[test]
    fn trigger_blocking_panic() {
        init_trace(PathBuf::from("trace.jsonl")).unwrap();
        install_panic_hook();
        let _ = std::panic::catch_unwind(|| trigger(true));
    }
}