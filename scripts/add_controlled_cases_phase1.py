#!/usr/bin/env python3
"""
Add RustDPR controlled benchmark cases, phase 1.

Run from repository root:
    python3 scripts/add_controlled_cases_phase1.py

This script creates 10 controlled cases and updates:
    - benchmarks/micro/manifest.yaml
    - benchmarks/taxonomy/manifest.yaml
    - benchmarks/oracle/manifest.yaml
    - root Cargo.toml workspace members/exclude

The cases assume the label/oracle patch has already been applied, i.e. these
labels exist in Rust/Python schema:
    RelationLabel::HarnessMisuse
    RelationLabel::UnsupportedOracle
    OracleVerdict::NoOracleFinding
    OracleVerdict::OracleBuildFailure
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import textwrap

ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = ROOT / "benchmarks"


@dataclass(frozen=True)
class Case:
    suite: str
    name: str
    lib_rs: str
    expected_yaml: str
    fuzz_target_rs: str


def trim(s: str) -> str:
    return textwrap.dedent(s).strip() + "\n"


def cargo_toml(case: Case) -> str:
    return trim(f"""
        [package]
        name = "{case.name}"
        version = "0.1.0"
        edition = "2024"

        [dependencies]
        rustdpr-trace = {{ path = "../../../crates/rustdpr-trace" }}
    """)


def fuzz_cargo_toml(case: Case) -> str:
    return trim(f"""
        [package]
        name = "{case.name}-fuzz"
        version = "0.0.0"
        publish = false
        edition = "2024"

        [package.metadata]
        cargo-fuzz = true

        [dependencies]
        libfuzzer-sys = "0.4"
        {case.name} = {{ path = ".." }}
        rustdpr-trace = {{ path = "../../../../crates/rustdpr-trace" }}
        rustdpr-core = {{ path = "../../../../crates/rustdpr-core" }}

        [[bin]]
        name = "fuzz_target_1"
        path = "fuzz_targets/fuzz_target_1.rs"
        test = false
        doc = false
        bench = false

        [workspace]
    """)


CASES: list[Case] = [
    Case(
        suite="micro",
        name="mb_before_unsafe_nested_call",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_RAW_READ: &str = "S00001";
            pub const FN_PROCESS: &str = "crate::process";
            pub const FN_INNER: &str = "crate::inner_raw_read";

            fn validate(input: &[u8]) {
                assert!(!input.is_empty(), "input must not be empty before unsafe helper");
                assert!(input[0] != 0, "zero is rejected before unsafe helper");
            }

            fn inner_raw_read(input: &[u8]) -> u8 {
                let _guard = dpr_function!(FN_INNER);
                unsafe {
                    dpr_hit!(SITE_RAW_READ);
                    *input.as_ptr()
                }
            }

            pub fn process(input: &[u8]) -> u8 {
                install_panic_hook();
                let _guard = dpr_function!(FN_PROCESS);
                validate(input);
                inner_raw_read(input)
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                #[should_panic]
                fn empty_panics_before_nested_unsafe() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let _ = process(&[]);
                }

                #[test]
                #[should_panic]
                fn zero_panics_before_nested_unsafe() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let _ = process(&[0]);
                }

                #[test]
                fn nonzero_reaches_nested_unsafe() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    assert_eq!(process(&[7]), 7);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: mb_before_unsafe_nested_call
            suite: micro
            category: controlled

            source:
              crate_name: mb_before_unsafe_nested_call
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: BlockingPanic
              relation: BeforeUnsafe
              oracle_verdict: Unknown
              harness_status: LikelyValid
              security_relevant: false
              oracle_confirmable: false
              expected_reached_count: 0

            dangerous_categories:
              - RawPointer
            panic_kinds:
              - AssertMacro
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: fuzz target passes raw bytes into safe API; panic is an API contract guard before nested unsafe helper
            selection:
              reason: stress case for panic in caller before a nested callee contains the dangerous site
              negative_case: true
              manually_labeled: true
            notes:
              - expected relation should be BeforeUnsafe on empty or zero inputs, despite static dangerous site in inner helper
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use mb_before_unsafe_nested_call::process;
            use rustdpr_trace::{init_trace, install_panic_hook};

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let _ = std::panic::catch_unwind(|| {
                    let _ = process(data);
                });
            });
        '''),
    ),
    Case(
        suite="micro",
        name="mb_inside_unsafe_assert",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_UNSAFE_REGION: &str = "S00001";
            pub const FN_PROCESS: &str = "crate::process";

            pub fn process(input: &[u8]) -> u8 {
                install_panic_hook();
                let _guard = dpr_function!(FN_PROCESS);
                let mut out = 0u8;

                unsafe {
                    dpr_hit!(SITE_UNSAFE_REGION);
                    assert!(!input.is_empty(), "panic occurs inside unsafe region");
                    let ptr = &mut out as *mut u8;
                    *ptr = *input.as_ptr();
                }

                out
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                #[should_panic]
                fn empty_panics_inside_unsafe() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let _ = process(&[]);
                }

                #[test]
                fn non_empty_ok() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    assert_eq!(process(&[9]), 9);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: mb_inside_unsafe_assert
            suite: micro
            category: controlled

            source:
              crate_name: mb_inside_unsafe_assert
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: InsideUnsafePanic
              relation: InsideUnsafe
              oracle_verdict: Unknown
              harness_status: LikelyValid
              security_relevant: true
              oracle_confirmable: false
              expected_reached_count: 1

            dangerous_categories:
              - UnsafeRust
              - RawPointer
            panic_kinds:
              - AssertMacro
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: safe API receives arbitrary bytes; empty input triggers an in-region panic
            selection:
              reason: differentiates InsideUnsafe from AfterUnsafe by placing assertion inside the unsafe region
              negative_case: false
              manually_labeled: true
            notes:
              - expected trace order is Hit(S00001) then Panic from inside the same unsafe block
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use mb_inside_unsafe_assert::process;
            use rustdpr_trace::{init_trace, install_panic_hook};

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let _ = std::panic::catch_unwind(|| {
                    let _ = process(data);
                });
            });
        '''),
    ),
    Case(
        suite="micro",
        name="mb_none_static_unsafe_unreached",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_UNREACHED_RAW_READ: &str = "S00001";
            pub const FN_PROCESS: &str = "crate::process";
            pub const FN_UNREACHED: &str = "crate::unreached_raw_read";

            #[allow(dead_code)]
            fn unreached_raw_read(input: &[u8]) -> u8 {
                let _guard = dpr_function!(FN_UNREACHED);
                unsafe {
                    dpr_hit!(SITE_UNREACHED_RAW_READ);
                    *input.as_ptr()
                }
            }

            pub fn process(input: &[u8]) -> usize {
                install_panic_hook();
                let _guard = dpr_function!(FN_PROCESS);
                assert!(input.len() >= 4, "contract panic without dangerous path reachability");
                input.len()
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                #[should_panic]
                fn short_input_contract_panic() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let _ = process(&[1, 2]);
                }

                #[test]
                fn long_input_no_dangerous_path() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    assert_eq!(process(&[1, 2, 3, 4]), 4);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: mb_none_static_unsafe_unreached
            suite: micro
            category: controlled-negative

            source:
              crate_name: mb_none_static_unsafe_unreached
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: ContractPanic
              relation: NoneObserved
              oracle_verdict: Unknown
              harness_status: LikelyValid
              security_relevant: false
              oracle_confirmable: false
              expected_reached_count: 0

            dangerous_categories:
              - RawPointer
            panic_kinds:
              - AssertMacro
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: fuzz target calls a safe API; panic is an ordinary contract violation
            selection:
              reason: hard negative with static unsafe code present but dynamically unreachable from observed panic path
              negative_case: true
              manually_labeled: true
            notes:
              - useful for static-only false-positive analysis
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use mb_none_static_unsafe_unreached::process;
            use rustdpr_trace::{init_trace, install_panic_hook};

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let _ = std::panic::catch_unwind(|| {
                    let _ = process(data);
                });
            });
        '''),
    ),
    Case(
        suite="micro",
        name="mb_harness_invalid_len_capacity",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_RAW_PARTS_READ: &str = "S00001";
            pub const FN_SUM_RAW_PARTS: &str = "crate::sum_raw_parts";

            /// Sums a raw byte slice.
            ///
            /// # Safety
            /// `ptr` must be non-null and valid for `len` initialized bytes.
            pub unsafe fn sum_raw_parts(ptr: *const u8, len: usize) -> u32 {
                install_panic_hook();
                let _guard = dpr_function!(FN_SUM_RAW_PARTS);

                assert!(!ptr.is_null(), "harness supplied a null pointer");
                assert!(len <= 16, "harness supplied an unrealistic raw slice length");

                unsafe {
                    dpr_hit!(SITE_RAW_PARTS_READ);
                    std::slice::from_raw_parts(ptr, len).iter().map(|b| *b as u32).sum()
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                #[should_panic]
                fn invalid_harness_null_pointer() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    unsafe {
                        let _ = sum_raw_parts(std::ptr::null(), 8);
                    }
                }

                #[test]
                #[should_panic]
                fn invalid_harness_length_capacity() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let data = [1u8, 2, 3, 4];
                    unsafe {
                        let _ = sum_raw_parts(data.as_ptr(), 64);
                    }
                }

                #[test]
                fn valid_harness_input() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let data = [1u8, 2, 3, 4];
                    let sum = unsafe { sum_raw_parts(data.as_ptr(), data.len()) };
                    assert_eq!(sum, 10);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: mb_harness_invalid_len_capacity
            suite: micro
            category: harness-misuse

            source:
              crate_name: mb_harness_invalid_len_capacity
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: HarnessMisuse
              relation: HarnessMisuse
              oracle_verdict: Unknown
              harness_status: LikelyMisuse
              security_relevant: false
              oracle_confirmable: false
              expected_reached_count: 0

            dangerous_categories:
              - RawPointer
              - AllocationOwnership
            panic_kinds:
              - AssertMacro
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: fuzz target deliberately fabricates raw pointer/length pairs that violate the unsafe API safety contract
            selection:
              reason: controlled case for rejecting invalid harness artifacts before attributing the panic to library code
              negative_case: true
              manually_labeled: true
            notes:
              - the invalid tests panic before the raw slice dangerous site is reached
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use mb_harness_invalid_len_capacity::sum_raw_parts;
            use rustdpr_trace::{init_trace, install_panic_hook};

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let len = data.first().copied().unwrap_or(0) as usize;
                let ptr = if data.len() > 1 { data[1..].as_ptr() } else { std::ptr::null() };
                let _ = std::panic::catch_unwind(|| unsafe {
                    let _ = sum_raw_parts(ptr, len);
                });
            });
        '''),
    ),
    Case(
        suite="micro",
        name="mb_ffi_callback_panics",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_FFI_CALLBACK: &str = "S00001";
            pub const FN_CALL_CALLBACK: &str = "crate::call_callback";

            pub type Callback = extern "C-unwind" fn(u8) -> u8;

            extern "C-unwind" fn panicking_callback(x: u8) -> u8 {
                assert!(x != 0, "callback panic crosses C-unwind ABI boundary");
                x
            }

            pub fn call_callback(input: &[u8]) -> u8 {
                install_panic_hook();
                let _guard = dpr_function!(FN_CALL_CALLBACK);
                let cb: Callback = panicking_callback;
                let x = input.first().copied().unwrap_or(0);

                unsafe {
                    dpr_hit!(SITE_FFI_CALLBACK);
                    cb(x)
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                #[should_panic]
                fn zero_panics_at_ffi_boundary() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let _ = call_callback(&[0]);
                }

                #[test]
                fn nonzero_ok() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    assert_eq!(call_callback(&[5]), 5);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: mb_ffi_callback_panics
            suite: micro
            category: controlled-ffi

            source:
              crate_name: mb_ffi_callback_panics
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: InsideUnsafePanic
              relation: FfiBoundary
              oracle_verdict: Unknown
              harness_status: LikelyValid
              security_relevant: true
              oracle_confirmable: false
              expected_reached_count: 1

            dangerous_categories:
              - Ffi
              - PanicBoundary
            panic_kinds:
              - FfiUnwindPanicCandidate
              - AssertMacro
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: safe wrapper receives arbitrary bytes; panic occurs through an extern C-unwind callback boundary
            selection:
              reason: adds a controlled FfiBoundary relation without depending on a native C library
              negative_case: false
              manually_labeled: true
            notes:
              - intended to stress FFI boundary labeling, not ASan/Miri confirmation
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use mb_ffi_callback_panics::call_callback;
            use rustdpr_trace::{init_trace, install_panic_hook};

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let _ = std::panic::catch_unwind(|| {
                    let _ = call_callback(data);
                });
            });
        '''),
    ),
    Case(
        suite="taxonomy",
        name="tb_before_same_function_later_block",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_LATER_BLOCK: &str = "S00001";
            pub const FN_PROCESS: &str = "crate::process";

            pub fn process(input: &[u8]) -> u8 {
                install_panic_hook();
                let _guard = dpr_function!(FN_PROCESS);

                if input.len() < 2 {
                    panic!("same function panic before later unsafe block");
                }

                let mut out = 0u8;
                unsafe {
                    dpr_hit!(SITE_LATER_BLOCK);
                    *(&mut out as *mut u8) = input[1];
                }
                out
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                #[should_panic]
                fn panic_before_later_block() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let _ = process(&[1]);
                }

                #[test]
                fn reaches_later_block() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    assert_eq!(process(&[1, 6]), 6);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: tb_before_same_function_later_block
            suite: taxonomy
            category: taxonomy-before-unsafe

            source:
              crate_name: tb_before_same_function_later_block
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: BlockingPanic
              relation: BeforeUnsafe
              oracle_verdict: Unknown
              harness_status: LikelyValid
              security_relevant: false
              oracle_confirmable: false
              expected_reached_count: 0

            dangerous_categories:
              - RawPointer
            panic_kinds:
              - PanicMacro
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: safe API; panic is a guard in the same function before the dangerous block
            selection:
              reason: hard taxonomy case where static function-level matching may incorrectly associate panic with the later unsafe block
              negative_case: true
              manually_labeled: true
            notes:
              - same enclosing function but different dynamic order
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use rustdpr_trace::{init_trace, install_panic_hook};
            use tb_before_same_function_later_block::process;

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let _ = std::panic::catch_unwind(|| {
                    let _ = process(data);
                });
            });
        '''),
    ),
    Case(
        suite="taxonomy",
        name="tb_static_unsafe_unreached",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_DEAD_UNSAFE: &str = "S00001";
            pub const FN_PROCESS: &str = "crate::process";
            pub const FN_DEAD: &str = "crate::dead_unsafe_helper";

            #[allow(dead_code)]
            fn dead_unsafe_helper(input: &[u8]) -> u8 {
                let _guard = dpr_function!(FN_DEAD);
                unsafe {
                    dpr_hit!(SITE_DEAD_UNSAFE);
                    *input.as_ptr()
                }
            }

            pub fn process(input: &[u8]) -> u8 {
                install_panic_hook();
                let _guard = dpr_function!(FN_PROCESS);
                input.first().copied().expect("panic-only path; dead unsafe helper is not called")
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                #[should_panic]
                fn empty_input_panic_no_dangerous_hit() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let _ = process(&[]);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: tb_static_unsafe_unreached
            suite: taxonomy
            category: taxonomy-none-observed

            source:
              crate_name: tb_static_unsafe_unreached
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: ContractPanic
              relation: NoneObserved
              oracle_verdict: Unknown
              harness_status: LikelyValid
              security_relevant: false
              oracle_confirmable: false
              expected_reached_count: 0

            dangerous_categories:
              - RawPointer
            panic_kinds:
              - ExpectLike
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: safe API; panic is not related to the dead unsafe helper
            selection:
              reason: taxonomy hard negative for static-only baseline and DPG-only false positives
              negative_case: true
              manually_labeled: true
            notes:
              - static analysis should find a dangerous site, but trace should not reach it
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use rustdpr_trace::{init_trace, install_panic_hook};
            use tb_static_unsafe_unreached::process;

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let _ = std::panic::catch_unwind(|| {
                    let _ = process(data);
                });
            });
        '''),
    ),
    Case(
        suite="taxonomy",
        name="tb_harness_bad_from_raw_parts",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_FROM_RAW_PARTS: &str = "S00001";
            pub const FN_VIEW_RAW: &str = "crate::view_raw_parts";

            /// Returns the first byte of a raw slice.
            ///
            /// # Safety
            /// The caller must provide a non-null pointer valid for `len` bytes.
            pub unsafe fn view_raw_parts(ptr: *const u8, len: usize) -> Option<u8> {
                install_panic_hook();
                let _guard = dpr_function!(FN_VIEW_RAW);

                assert!(!ptr.is_null(), "null raw pointer supplied by harness");
                assert!(len <= 8, "oversized length supplied by harness");

                unsafe {
                    dpr_hit!(SITE_FROM_RAW_PARTS);
                    std::slice::from_raw_parts(ptr, len).first().copied()
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                #[should_panic]
                fn null_pointer_is_harness_misuse() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    unsafe {
                        let _ = view_raw_parts(std::ptr::null(), 4);
                    }
                }

                #[test]
                #[should_panic]
                fn bad_length_is_harness_misuse() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let data = [1u8, 2, 3, 4];
                    unsafe {
                        let _ = view_raw_parts(data.as_ptr(), 128);
                    }
                }

                #[test]
                fn valid_raw_parts() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let data = [11u8, 12, 13, 14];
                    let got = unsafe { view_raw_parts(data.as_ptr(), data.len()) };
                    assert_eq!(got, Some(11));
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: tb_harness_bad_from_raw_parts
            suite: taxonomy
            category: taxonomy-harness-misuse

            source:
              crate_name: tb_harness_bad_from_raw_parts
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: HarnessMisuse
              relation: HarnessMisuse
              oracle_verdict: Unknown
              harness_status: LikelyMisuse
              security_relevant: false
              oracle_confirmable: false
              expected_reached_count: 0

            dangerous_categories:
              - AllocationOwnership
              - RawPointer
            panic_kinds:
              - AssertMacro
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: fuzz target constructs raw pointer/length pairs outside the unsafe API contract
            selection:
              reason: taxonomy case for distinguishing harness misuse from library vulnerability candidate
              negative_case: true
              manually_labeled: true
            notes:
              - invalid inputs panic before the from_raw_parts dangerous site
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use rustdpr_trace::{init_trace, install_panic_hook};
            use tb_harness_bad_from_raw_parts::view_raw_parts;

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let len = data.first().copied().unwrap_or(0) as usize;
                let ptr = if data.len() > 1 { data[1..].as_ptr() } else { std::ptr::null() };
                let _ = std::panic::catch_unwind(|| unsafe {
                    let _ = view_raw_parts(ptr, len);
                });
            });
        '''),
    ),
    Case(
        suite="oracle",
        name="ob_asan_no_finding_control",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

            pub const SITE_SAFE_RAW_READ: &str = "S00001";
            pub const FN_PROCESS: &str = "crate::process";

            pub fn process(input: &[u8]) -> u8 {
                install_panic_hook();
                let _guard = dpr_function!(FN_PROCESS);
                let value = input.first().copied().unwrap_or(0);
                let ptr = &value as *const u8;

                unsafe {
                    dpr_hit!(SITE_SAFE_RAW_READ);
                    *ptr
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                fn safe_raw_read_has_no_oracle_finding() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    assert_eq!(process(&[42]), 42);
                    assert_eq!(process(&[]), 0);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: ob_asan_no_finding_control
            suite: oracle
            category: oracle-negative-control

            source:
              crate_name: ob_asan_no_finding_control
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: DangerousPathReached
              relation: AfterUnsafe
              oracle_verdict: NoOracleFinding
              harness_status: LikelyValid
              security_relevant: false
              oracle_confirmable: true
              expected_reached_count: 1

            dangerous_categories:
              - RawPointer
            panic_kinds: []
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: safe API performs a valid raw pointer read from a stack byte
            selection:
              reason: oracle negative control; dangerous-looking raw pointer operation should not automatically become an oracle-confirmed bug
              negative_case: true
              manually_labeled: true
            notes:
              - expected ASan/Miri verdict is NoOracleFinding after the oracle parser patch
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use ob_asan_no_finding_control::process;
            use rustdpr_trace::{init_trace, install_panic_hook};

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let _ = process(data);
            });
        '''),
    ),
    Case(
        suite="oracle",
        name="ob_miri_unsupported_ffi",
        lib_rs=trim(r'''
            use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
            use std::ffi::{c_char, CString};

            pub const SITE_FOREIGN_GETENV: &str = "S00001";
            pub const FN_PROCESS: &str = "crate::process";

            unsafe extern "C" {
                fn getenv(name: *const c_char) -> *mut c_char;
            }

            pub fn process(input: &[u8]) -> bool {
                install_panic_hook();
                let _guard = dpr_function!(FN_PROCESS);
                let key = if input.first().copied().unwrap_or(0) == 0 {
                    "RUSTDPR_UNLIKELY_ENV_KEY_0"
                } else {
                    "RUSTDPR_UNLIKELY_ENV_KEY_1"
                };
                let c_key = CString::new(key).unwrap();

                unsafe {
                    dpr_hit!(SITE_FOREIGN_GETENV);
                    !getenv(c_key.as_ptr()).is_null()
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use rustdpr_trace::init_trace;

                #[test]
                fn normal_runtime_can_call_foreign_getenv() {
                    init_trace("artifacts/trace.jsonl").unwrap();
                    let _ = process(&[0]);
                }
            }
        '''),
        expected_yaml=trim('''
            case_id: ob_miri_unsupported_ffi
            suite: oracle
            category: oracle-unsupported-control

            source:
              crate_name: ob_miri_unsupported_ffi
              version: local
              advisory: null
              fixed_version: null
              url: null

            ground_truth:
              primary_label: SuspiciousCandidate
              relation: UnsupportedOracle
              oracle_verdict: MiriUnsupported
              harness_status: LikelyValid
              security_relevant: false
              oracle_confirmable: false
              expected_reached_count: 1

            dangerous_categories:
              - Ffi
            panic_kinds: []
            harness:
              path: fuzz/fuzz_targets/fuzz_target_1.rs
              validity_rationale: safe wrapper chooses a fixed C string; unsupported status comes from oracle environment, not invalid harness input
            selection:
              reason: controlled Miri unsupported case for FFI boundary oracle accounting
              negative_case: true
              manually_labeled: true
            notes:
              - Miri should report unsupported foreign function rather than UB; ASan should normally have no finding
        '''),
        fuzz_target_rs=trim(r'''
            #![no_main]
            use libfuzzer_sys::fuzz_target;
            use ob_miri_unsupported_ffi::process;
            use rustdpr_trace::{init_trace, install_panic_hook};

            fuzz_target!(|data: &[u8]| {
                let _ = init_trace("fuzz_trace.jsonl");
                install_panic_hook();
                let _ = std::panic::catch_unwind(|| {
                    let _ = process(data);
                });
            });
        '''),
    ),
]


def write_file(path: Path, content: str, *, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        print(f"[skip] {path.relative_to(ROOT)} exists")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"[write] {path.relative_to(ROOT)}")


def append_manifest_case(suite: str, case_name: str) -> None:
    path = BENCHMARKS / suite / "manifest.yaml"
    text = path.read_text(encoding="utf-8") if path.exists() else f"suite: {suite}\ncases:\n"
    entry = f"  - {case_name}\n"
    if entry in text:
        print(f"[skip] {path.relative_to(ROOT)} already has {case_name}")
        return
    if not text.endswith("\n"):
        text += "\n"
    text += entry
    path.write_text(text, encoding="utf-8")
    print(f"[update] {path.relative_to(ROOT)} + {case_name}")


def insert_into_toml_array(text: str, key: str, value: str) -> str:
    entry = f'  "{value}",'
    if entry in text:
        return text

    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == f"{key} = [":
            start = i
            break
    if start is None:
        raise RuntimeError(f"could not find `{key} = [` in Cargo.toml")

    end = None
    for j in range(start + 1, len(lines)):
        if lines[j].strip() == "]":
            end = j
            break
    if end is None:
        raise RuntimeError(f"could not find closing `]` for `{key}` in Cargo.toml")

    lines.insert(end, entry)
    return "\n".join(lines) + "\n"


def update_root_cargo(cases: list[Case]) -> None:
    path = ROOT / "Cargo.toml"
    text = path.read_text(encoding="utf-8")
    old = text
    for case in cases:
        member = f"benchmarks/{case.suite}/{case.name}"
        text = insert_into_toml_array(text, "members", member)
        text = insert_into_toml_array(text, "exclude", f"{member}/fuzz")
    if text != old:
        path.write_text(text, encoding="utf-8")
        print(f"[update] {path.relative_to(ROOT)} workspace members/exclude")
    else:
        print(f"[skip] {path.relative_to(ROOT)} already updated")


def create_case(case: Case) -> None:
    base = BENCHMARKS / case.suite / case.name
    write_file(base / "Cargo.toml", cargo_toml(case))
    write_file(base / "src" / "lib.rs", case.lib_rs)
    write_file(base / "expected.yaml", case.expected_yaml)
    write_file(base / "fuzz" / ".gitignore", "target\ncorpus\nartifacts\ncoverage\n")
    write_file(base / "fuzz" / "Cargo.toml", fuzz_cargo_toml(case))
    write_file(base / "fuzz" / "fuzz_targets" / "fuzz_target_1.rs", case.fuzz_target_rs)
    append_manifest_case(case.suite, case.name)


def main() -> int:
    if not (ROOT / "Cargo.toml").exists() or not (ROOT / "crates").exists():
        raise SystemExit("run this script from inside scripts/ in the RustDPR repository, or keep it at scripts/add_controlled_cases_phase1.py")

    for case in CASES:
        create_case(case)
    update_root_cargo(CASES)

    print("\n[next]")
    print("  cargo fmt --all")
    print("  cargo check --workspace")
    print("  python3 scripts/validate_benchmark_manifest.py --suite micro")
    print("  python3 scripts/validate_benchmark_manifest.py --suite taxonomy")
    print("  python3 scripts/validate_benchmark_manifest.py --suite oracle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
