use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::ManuallyDrop;
use std::ptr;

pub const SITE_PTR_READ: &str = "S00001";
pub const FN_PROCESS: &str = "crate::duplicate_then_panic";

pub struct DropBox {
    inner: ManuallyDrop<Box<u8>>,
}

impl DropBox {
    pub fn new(v: u8) -> Self {
        Self {
            inner: ManuallyDrop::new(Box::new(v)),
        }
    }
}

impl Drop for DropBox {
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.inner);
        }
    }
}

pub fn duplicate_then_panic(flag: bool) {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let original = DropBox::new(7);
    unsafe {
        dpr_hit!(SITE_PTR_READ);
        let duplicate = ptr::read(&original);
        if flag {
            panic!("panic after ptr::read duplicates drop ownership");
        }
        std::mem::forget(duplicate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn nonpanic_path_forgets_duplicate() {
        init_trace("artifacts/trace.jsonl").unwrap();
        duplicate_then_panic(false);
    }

    #[test]
    #[ignore = "intentionally creates a double-drop style panic-safety hazard"]
    fn panic_path_is_dangerous() {
        init_trace("artifacts/trace.jsonl").unwrap();
        duplicate_then_panic(true);
    }
}
