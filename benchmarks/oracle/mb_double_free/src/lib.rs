use rustdpr_trace::hit;

pub fn trigger(flag: bool) {
    let b = Box::new(123u8);
    let ptr = Box::into_raw(b);

    unsafe {
        hit("S0001");

        if flag {
            drop(Box::from_raw(ptr));
            drop(Box::from_raw(ptr));
        } else {
            drop(Box::from_raw(ptr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::{init_trace, install_panic_hook};
    use std::path::PathBuf;

    #[test]
    fn trigger_double_free() {
        init_trace(PathBuf::from("trace.jsonl")).unwrap();
        install_panic_hook();

        trigger(true);
    }
}