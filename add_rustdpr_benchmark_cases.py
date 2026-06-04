from __future__ import annotations

from pathlib import Path
import re
import textwrap

ROOT = Path.cwd()
BENCH = ROOT / "benchmarks"


def w(path: str, content: str) -> None:
    p = ROOT / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def cargo_toml(case: str, suite: str) -> str:
    return f'''
    [package]
    name = "{case}"
    version = "0.1.0"
    edition = "2021"
    publish = false

    [dependencies]
    rustdpr-trace = {{ path = "../../../crates/rustdpr-trace" }}
    '''


def fuzz_cargo(case: str) -> str:
    return f'''
    [package]
    name = "{case}-fuzz"
    version = "0.0.0"
    publish = false
    edition = "2021"

    [package.metadata]
    cargo-fuzz = true

    [dependencies]
    libfuzzer-sys = "0.4"
    {case} = {{ path = ".." }}
    rustdpr-trace = {{ path = "../../../../crates/rustdpr-trace" }}

    [[bin]]
    name = "fuzz_target_1"
    path = "fuzz_targets/fuzz_target_1.rs"
    test = false
    doc = false
    bench = false

    [workspace]
    '''


def fuzz_target(case: str, call_expr: str, min_len: int = 1, catch: bool = True) -> str:
    body = f'''
    #![no_main]

    use libfuzzer_sys::fuzz_target;
    use rustdpr_trace::{{init_trace, install_panic_hook}};

    fuzz_target!(|data: &[u8]| {{
        if data.len() < {min_len} {{
            return;
        }}
        let _ = init_trace("fuzz_trace.jsonl");
        install_panic_hook();
    '''
    if catch:
        body += f'''
        let _ = std::panic::catch_unwind(|| {{
            {call_expr};
        }});
    }});
    '''
    else:
        body += f'''
        {call_expr};
    }});
    '''
    return body


def yaml_list_block(items: list[str]) -> str:
    if not items:
        return "[]"
    return "\n" + "\n".join(f"  - {x}" for x in items)


def expected(
    case_id: str,
    suite: str,
    category: str,
    primary: str,
    relation: str,
    oracle: str,
    security: bool,
    confirmable: bool,
    reached: int,
    dangerous: list[str],
    panic: list[str],
    source_crate: str,
    version: str = "local",
    advisory: str | None = None,
    fixed_version: str | None = None,
    url: str | None = None,
    reason: str = "",
    note: str = "",
) -> str:
    advisory_s = "null" if advisory is None else advisory
    fixed_s = "null" if fixed_version is None else fixed_version
    url_s = "null" if url is None else url

    dangerous_s = yaml_list_block(dangerous)
    panic_s = yaml_list_block(panic)

    if dangerous:
        dangerous_block = f"dangerous_categories:{dangerous_s}"
    else:
        dangerous_block = "dangerous_categories: []"

    if panic:
        panic_block = f"panic_kinds:{panic_s}"
    else:
        panic_block = "panic_kinds: []"

    return f"""case_id: {case_id}
suite: {suite}
category: {category}

source:
  crate_name: {source_crate}
  version: {version}
  advisory: {advisory_s}
  fixed_version: {fixed_s}
  url: {url_s}

ground_truth:
  primary_label: {primary}
  relation: {relation}
  oracle_verdict: {oracle}
  harness_status: LikelyValid
  security_relevant: {str(security).lower()}
  oracle_confirmable: {str(confirmable).lower()}
  expected_reached_count: {reached}

{dangerous_block}
{panic_block}

harness:
  path: fuzz/fuzz_targets/fuzz_target_1.rs
  validity_rationale: >
    deterministic local harness maps bytes to public API without directly
    fabricating invalid external pointers

selection:
  reason: >
    {reason}
  negative_case: {str(not security).lower()}
  manually_labeled: true

notes:
  - {note or reason}
"""


ORACLE = {
"ob_stack_oob_read": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn trigger(index: usize) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    let data = [1u8, 2, 3, 4];
    unsafe {
        dpr_hit!("S00001");
        *data.as_ptr().add(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn stack_oob_read() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger(16);
    }
}
''',
"ob_global_oob_write": r'''
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
''',
"ob_null_deref_miri": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn trigger() -> u8 {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    let ptr = core::ptr::null::<u8>();
    unsafe {
        dpr_hit!("S00001");
        core::ptr::read(ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn null_deref_is_ub() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger();
    }
}
''',
"ob_uninit_bool_miri": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::MaybeUninit;

pub fn trigger() -> bool {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    unsafe {
        dpr_hit!("S00001");
        MaybeUninit::<bool>::uninit().assume_init()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn uninit_bool_is_ub() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger();
    }
}
''',
"ob_invalid_bool_miri": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn trigger(byte: u8) -> bool {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    unsafe {
        dpr_hit!("S00001");
        std::mem::transmute::<u8, bool>(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn invalid_bool_is_ub() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger(2);
    }
}
''',
"ob_misaligned_read_miri": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn trigger() -> u32 {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    let bytes = [0u8; 8];
    let ptr = unsafe { bytes.as_ptr().add(1) as *const u32 };
    unsafe {
        dpr_hit!("S00001");
        core::ptr::read(ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn misaligned_read_is_ub() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger();
    }
}
''',
}

REGRESSION = {
"rsec_slice_deque_drain_filter_panic": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn drain_filter_like(should_panic: bool) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::drain_filter_like");
    let mut data = vec![10u8, 20, 30];
    let ptr = data.as_mut_ptr();
    unsafe {
        dpr_hit!("S00001");
        let _candidate = ptr.add(1);
    }
    if should_panic {
        panic!("predicate panic during drain_filter-like iteration");
    }
    data.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn predicate_panic_after_raw_iterator_state() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = drain_filter_like(true);
    }
}
''',
"rsec_toodee_draincol_copy_size": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn drain_col_like(trigger_panic: bool) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::drain_col_like");
    let mut data = vec![1u8, 2, 3, 4, 5, 6];
    unsafe {
        dpr_hit!("S00001");
        let dst = data.as_mut_ptr();
        let src = data.as_ptr().add(1);
        std::ptr::copy(src, dst, data.len() - 1);
    }
    if trigger_panic {
        panic!("drop-time invariant check after drain column copy");
    }
    data.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_draincol_copy() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = drain_col_like(true);
    }
}
''',
"rsec_tracing_into_inner_forget": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::ManuallyDrop;

pub struct InstrumentedLike<T> {
    span_id: usize,
    inner: T,
}

pub fn into_inner_like(trigger_panic: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!("crate::into_inner_like");
    let this = ManuallyDrop::new(InstrumentedLike { span_id: 7, inner: 9u8 });
    let inner_ptr: *const u8 = &this.inner;
    unsafe {
        dpr_hit!("S00001");
        let value = std::ptr::read(inner_ptr);
        if trigger_panic {
            panic!("panic after ptr::read in into_inner-like code");
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_forget_style_ptr_read() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = into_inner_like(true);
    }
}
''',
"rsec_direct_ring_buffer_set_len": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn create_ring_buffer_like(cap: usize, trigger_panic: bool) -> Vec<u8> {
    install_panic_hook();
    let _guard = dpr_function!("crate::create_ring_buffer_like");
    let mut buf: Vec<u8> = Vec::with_capacity(cap);
    unsafe {
        dpr_hit!("S00001");
        buf.set_len(cap);
    }
    if trigger_panic {
        panic!("panic after set_len-created ring buffer");
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_set_len_ring_buffer() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = create_ring_buffer_like(8, true);
    }
}
''',
"rsec_borrowck_any_as_u8_slice": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

#[repr(C)]
pub struct Padded {
    pub a: u8,
    pub b: u32,
}

pub fn any_as_u8_slice_like(value: &Padded, trigger_panic: bool) -> &[u8] {
    install_panic_hook();
    let _guard = dpr_function!("crate::any_as_u8_slice_like");
    let bytes = unsafe {
        dpr_hit!("S00001");
        std::slice::from_raw_parts(
            value as *const Padded as *const u8,
            std::mem::size_of::<Padded>(),
        )
    };
    if trigger_panic {
        panic!("panic after exposing padded object as byte slice");
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_any_as_u8_slice() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let value = Padded { a: 1, b: 2 };
        let _ = any_as_u8_slice_like(&value, true);
    }
}
''',
}

REALWORLD = {
"rw_bytes_frame_parser": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn parse_frame(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::parse_frame");
    if input.len() < 2 { return 0; }
    let declared = input[0] as usize;
    let payload = unsafe {
        dpr_hit!("S00001");
        std::slice::from_raw_parts(input.as_ptr().add(1), input.len() - 1)
    };
    if declared > payload.len() {
        panic!("declared frame length exceeds payload");
    }
    payload[..declared].len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_payload_view() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = parse_frame(&[8, 1, 2, 3]);
    }
}
''',
"rw_ffi_cstr_boundary": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub unsafe extern "C" fn c_len(ptr: *const u8, len: usize) -> usize {
    if ptr.is_null() { return 0; }
    len
}

pub fn adapt_buffer(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::adapt_buffer");
    if input.is_empty() { return 0; }
    let n = unsafe {
        dpr_hit!("S00001");
        c_len(input.as_ptr(), input.len())
    };
    if input[0] == 0xff {
        panic!("panic after FFI boundary validation");
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_ffi_boundary() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = adapt_buffer(&[0xff, 1, 2]);
    }
}
''',
"rw_image_stride_copy": r'''
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
''',
"rw_arena_nonnull_handle": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::ptr::NonNull;

pub fn allocate_handle(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::allocate_handle");
    if input.is_empty() { return 0; }
    let mut buf = input.to_vec();
    let handle = unsafe {
        dpr_hit!("S00001");
        NonNull::new_unchecked(buf.as_mut_ptr())
    };
    if input[0] == 0xfe {
        panic!("panic after arena handle creation");
    }
    handle.as_ptr() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_nonnull_handle() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = allocate_handle(&[0xfe, 1, 2]);
    }
}
''',
"rw_packet_set_len_decoder": r'''
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn decode_packet(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::decode_packet");
    if input.len() < 2 { return 0; }
    let len = input[0] as usize;
    let mut out: Vec<u8> = Vec::with_capacity(len.min(32));
    unsafe {
        dpr_hit!("S00001");
        out.set_len(len.min(32));
    }
    if len > input.len() - 1 {
        panic!("decoded packet length exceeds input");
    }
    out.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_decoder_set_len() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = decode_packet(&[9, 1, 2, 3]);
    }
}
''',
}


def add_standard_case(suite: str, case: str, lib_rs: str, exp: str, call: str, min_len: int = 1, catch: bool = True) -> None:
    base = f"benchmarks/{suite}/{case}"
    w(f"{base}/Cargo.toml", cargo_toml(case, suite))
    w(f"{base}/src/lib.rs", lib_rs)
    w(f"{base}/expected.yaml", exp)
    w(f"{base}/fuzz/Cargo.toml", fuzz_cargo(case))
    w(f"{base}/fuzz/fuzz_targets/fuzz_target_1.rs", fuzz_target(case, call, min_len=min_len, catch=catch))
    w(f"{base}/fuzz/.gitignore", "target\nartifacts\ncorpus\ncrashes\n")


def ensure_manifest(suite: str, cases: list[str]) -> None:
    path = BENCH / suite / "manifest.yaml"
    existing = []
    if path.exists():
        text = path.read_text(encoding="utf-8")
        existing = re.findall(r"^\s*-\s*([A-Za-z0-9_\-]+)\s*$", text, re.M)
    all_cases = []
    for c in existing + cases:
        if c not in all_cases:
            all_cases.append(c)
    text = "suite: {}\ncases:\n{}\n".format(suite, "\n".join(f"  - {c}" for c in all_cases))
    path.write_text(text, encoding="utf-8")


def ensure_cargo_members(new_members: list[str], new_excludes: list[str]) -> None:
    path = ROOT / "Cargo.toml"
    text = path.read_text(encoding="utf-8")

    def add_to_array(src: str, array_name: str, lines: list[str]) -> str:
        m = re.search(rf'({array_name}\s*=\s*\[)(.*?)(\n\])', src, re.S)
        if not m:
            raise RuntimeError(f"cannot find {array_name} array in Cargo.toml")
        body = m.group(2)
        present = set(re.findall(r'"([^"]+)"', body))
        add = ""
        for line in lines:
            if line not in present:
                add += f'\n  "{line}",'
        return src[:m.start(3)] + add + src[m.start(3):]

    text = add_to_array(text, "members", new_members)
    text = add_to_array(text, "exclude", new_excludes)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    oracle_cases = list(ORACLE.keys())
    for case, lib in ORACLE.items():
        if case in {"ob_stack_oob_read", "ob_global_oob_write"}:
            oracle_verdict = "AddressSanitizerOutOfBounds"
            call = f"let idx = (data[0] as usize) + 8; let _ = {case}::trigger(idx)"
            catch = False
        elif case == "ob_invalid_bool_miri":
            oracle_verdict = "MiriUndefinedBehavior"
            call = f"let byte = if data[0] < 2 {{ 2 }} else {{ data[0] }}; let _ = {case}::trigger(byte)"
            catch = False
        else:
            oracle_verdict = "MiriUndefinedBehavior"
            call = f"let _ = {case}::trigger()"
            catch = False
        exp = expected(case, "oracle", "oracle", "OracleConfirmedBug", "NoneObserved", oracle_verdict,
                       True, True, 1, ["RawPointer"], [], case,
                       reason=f"controlled oracle case for {oracle_verdict}",
                       note="Use run_oracle_suite.py so ASan/Miri evidence is attached before expected-label checking.")
        add_standard_case("oracle", case, lib, exp, call, min_len=1, catch=catch)

    regression_meta = {
        "rsec_slice_deque_drain_filter_panic": ("slice-deque", "RUSTSEC-2021-0047", "https://rustsec.org/advisories/RUSTSEC-2021-0047", "panic in drain_filter-style predicate after unsafe iterator state"),
        "rsec_toodee_draincol_copy_size": ("toodee", "RUSTSEC-2025-0062", "https://rustsec.org/advisories/RUSTSEC-2025-0062", "drop-time drain column copy-size regression pattern"),
        "rsec_tracing_into_inner_forget": ("tracing", "RUSTSEC-2023-0078", "https://rustsec.org/advisories/RUSTSEC-2023-0078", "mem::forget/ptr::read stack-use-after-free regression pattern"),
        "rsec_direct_ring_buffer_set_len": ("direct_ring_buffer", "RUSTSEC-2025-0105", "https://rustsec.org/advisories/RUSTSEC-2025-0105", "Vec::with_capacity plus set_len creates uninitialized ring buffer pattern"),
        "rsec_borrowck_any_as_u8_slice": ("borrowck_sacrifices", "RUSTSEC-2025-0107", "https://rustsec.org/advisories/RUSTSEC-2025-0107", "slice::from_raw_parts over padded object byte representation"),
    }
    for case, lib in REGRESSION.items():
        crate, advisory, url, reason = regression_meta[case]
        exp = expected(case, "regression", "regression-minimized", "PanicAfterUnsafe", "AfterUnsafe", "Unknown",
                       True, False, 1, ["RawPointer"], ["PanicMacro"], crate,
                       version="minimized", advisory=advisory, url=url, reason=reason,
                       note="Minimized regression reproducer; replace or supplement with pinned vulnerable crate snapshot for the final paper artifact.")
        add_standard_case("regression", case, lib, exp, f"let _ = {case}::" + {
            "rsec_slice_deque_drain_filter_panic": "drain_filter_like(true)",
            "rsec_toodee_draincol_copy_size": "drain_col_like(true)",
            "rsec_tracing_into_inner_forget": "into_inner_like(true)",
            "rsec_direct_ring_buffer_set_len": "create_ring_buffer_like(8, true)",
            "rsec_borrowck_any_as_u8_slice": "any_as_u8_slice_like(&rsec_borrowck_any_as_u8_slice::Padded { a: 1, b: 2 }, true)",
        }[case], min_len=1, catch=True)

    real_meta = {
        "rw_bytes_frame_parser": ("frame-parser-local", "raw-slice packet parser pattern"),
        "rw_ffi_cstr_boundary": ("ffi-adapter-local", "FFI boundary adapter pattern"),
        "rw_image_stride_copy": ("image-stride-local", "image row copy and stride validation pattern"),
        "rw_arena_nonnull_handle": ("arena-handle-local", "arena handle creation via NonNull pattern"),
        "rw_packet_set_len_decoder": ("packet-decoder-local", "decoder output buffer set_len pattern"),
    }
    calls = {
        "rw_bytes_frame_parser": "let buf = [8u8, data[0], data[1]]; let _ = parse_frame(&buf)",
        "rw_ffi_cstr_boundary": "let buf = [0xffu8, data[0]]; let _ = adapt_buffer(&buf)",
        "rw_image_stride_copy": "let _ = copy_row(data, data.len().min(8), 1)",
        "rw_arena_nonnull_handle": "let buf = [0xfeu8, data[0]]; let _ = allocate_handle(&buf)",
        "rw_packet_set_len_decoder": "let buf = [9u8, data[0], data[1]]; let _ = decode_packet(&buf)",
    }
    for case, lib in REALWORLD.items():
        crate, reason = real_meta[case]
        exp = expected(case, "realworld", "realworld-local", "PanicAfterUnsafe", "AfterUnsafe", "Unknown",
                       True, False, 1, ["RawPointer"], ["PanicMacro"], crate,
                       version="local-extract", reason=reason,
                       note="Local real-world-style extract for scaling the pipeline; final CCFA submission should add pinned external crate snapshots.")
        add_standard_case("realworld", case, lib, exp, f"use {case}::*; {calls[case]}", min_len=2, catch=True)

    ensure_manifest("oracle", oracle_cases)
    ensure_manifest("regression", list(REGRESSION.keys()))
    ensure_manifest("realworld", list(REALWORLD.keys()))

    new_members = [f"benchmarks/oracle/{c}" for c in oracle_cases]
    new_members += [f"benchmarks/regression/{c}" for c in REGRESSION]
    new_members += [f"benchmarks/realworld/{c}" for c in REALWORLD]
    new_excludes = [f"benchmarks/oracle/{c}/fuzz" for c in oracle_cases]
    new_excludes += [f"benchmarks/regression/{c}/fuzz" for c in REGRESSION]
    new_excludes += [f"benchmarks/realworld/{c}/fuzz" for c in REALWORLD]
    ensure_cargo_members(new_members, new_excludes)

    print("[done] added benchmark cases:")
    print("  oracle    :", ", ".join(oracle_cases))
    print("  regression:", ", ".join(REGRESSION.keys()))
    print("  realworld :", ", ".join(REALWORLD.keys()))
    print("Next: cargo fmt --all && cargo check --workspace")


if __name__ == "__main__":
    main()
