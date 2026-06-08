#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rsec_slice_deque_2021_0047_vuln::fuzz_entry(data);
});
