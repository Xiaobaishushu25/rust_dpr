use rustdpr_trace::{dpr_hit, install_panic_hook};

pub fn parse(input: &[u8]) -> u8 {
    install_panic_hook();

    let header = input.first().unwrap();

    let mut out = 0u8;
    unsafe {
        dpr_hit!("S0001");
        let ptr = &mut out as *mut u8;
        *ptr = *header;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn empty_panics_before_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = parse(&[]);
    }
}