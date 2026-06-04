#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rustdpr_trace::init_trace("fuzz_trace.jsonl");
    rustdpr_trace::install_panic_hook();

    if data.is_empty() {
        return;
    }

    let _ = rw_smoke_raw_slice_view::parse_packet(data);
});