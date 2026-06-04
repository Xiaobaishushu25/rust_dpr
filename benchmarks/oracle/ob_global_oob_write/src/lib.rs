use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

static mut GLOBAL: [u8; 4] = [0; 4];

pub fn trigger(index: usize) {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    unsafe {
        dpr_hit!("S00001");
        let base = core::ptr::addr_of_mut!(GLOBAL) as *mut u8;
        base.add(index).write(0x41);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn global_oob_write() {
        init_trace("artifacts/trace.jsonl").unwrap();
        trigger(16);
    }
}
