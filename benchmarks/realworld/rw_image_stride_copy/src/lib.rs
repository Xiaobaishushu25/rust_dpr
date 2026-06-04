use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn copy_row(input: &[u8], width: usize, stride: usize) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::copy_row");
    if input.len() < width || width == 0 { return 0; }
    let mut out = vec![0u8; width];
    unsafe {
        dpr_hit!("S00001");
        std::ptr::copy_nonoverlapping(input.as_ptr(), out.as_mut_ptr(), width);
    }
    if stride < width {
        panic!("invalid image stride after row copy");
    }
    out.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_copy_nonoverlapping() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = copy_row(&[1, 2, 3, 4], 4, 2);
    }
}
