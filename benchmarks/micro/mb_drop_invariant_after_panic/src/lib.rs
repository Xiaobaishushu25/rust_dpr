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

    let mut original = ManuallyDrop::new(DropBox::new(7));

    unsafe {
        dpr_hit!(SITE_PTR_READ);

        let duplicate = ptr::read(&*original);

        if flag {
            // benchmark 中避免真正 double-drop，但保留“ptr::read 后发生 panic”的关系证据
            std::mem::forget(duplicate);
            ManuallyDrop::drop(&mut original);
            panic!("panic after ptr::read duplicates drop ownership");
        }

        std::mem::forget(duplicate);
        ManuallyDrop::drop(&mut original);
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
    fn panic_path_is_dangerous() {
        init_trace("artifacts/trace.jsonl").unwrap();
        duplicate_then_panic(true);
    }
}
