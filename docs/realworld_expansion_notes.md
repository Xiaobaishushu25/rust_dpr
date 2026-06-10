# Realworld expansion notes: round 1
## Design intent
This round implements the requested transition from local real-world-style extracts to pinned external crate wrappers. Each wrapper is intentionally thin: it pins the dependency, exposes `run_input(data: &[u8])`, initializes RustDPR tracing, and calls the external crate public API. The wrapper does not reimplement parser, codec, compression, zero-copy, buffer, or data-structure logic.

## Case selection rationale
| case_id | Why included | Benchmark value |
|---|---|---|
| `rw_png_decode` | PNG parser/codec with reader-based public API and upstream fuzzing history. | Negative/parser control for high coverage with low dangerous-path evidence. |
| `rw_jpeg_decoder_decode` | JPEG decoder with public `Decoder` API driven directly by bytes. | Parser/codec case for malformed-input triage and bounded decode behavior. |
| `rw_postcard_deser` | Serde-compatible binary deserializer with compact structured input. | Serialization/deserialization case for error-vs-panic triage. |
| `rw_bytes_buf_ops` | Widely used byte-buffer crate with cursor/split APIs. | Bytes/buffer manipulation case for API coverage and operation-sequence harnessing. |
| `rw_zerocopy_header_ref` | Zero-copy conversion crate designed for parsing bytes as structured data. | Zero-copy/bytes case for alignment/size constrained public API behavior. |
| `rw_lz4_flex_block_decode` | Pure Rust LZ4 implementation with size-prepended block decoder. | Compression case with explicit decompressed-size guard and error-return behavior. |
| `rw_flate2_zlib_decode` | DEFLATE/zlib/gzip stream crate with Rust backend option. | Streaming decompression case for coverage and timeout/output-cap behavior. |
| `rw_smallvec_ops` | Inline-storage vector crate whose public operations exercise inline-to-heap transitions. | Data-structure case for operation sequence fuzzing and allocation/drop-sensitive behavior. |

## Harness validity policy
- All fuzz targets call only `run_input(data)` and initialize RustDPR tracing.
- No harness constructs null raw pointers, invalid `from_raw_parts`, fake lifetimes, or private unsafe preconditions.
- Allocation-heavy decoders use simple caps (`MAX_OUTPUT`, `MAX_PIXELS`, `MAX_DECODE_BUFFER`) before expensive decode paths.
- Expected labels are intentionally `Unknown`/`NoneObserved` because these are realworld compatibility and evidence-collection cases, not historical vulnerability reproductions.

## Current analyzer caveat
The current `analyze-sites --crate-root <case>` implementation walks the wrapper directory. These wrappers are still valid round-1 benchmark assets, but dependency-source dangerous-site accounting requires either cargo-vendored dependency source under the case directory or a future RustDPR `--include-deps` analyzer mode. The expected files explicitly record this caveat so that paper tables do not overclaim dependency DPC before dependency scanning is enabled.

## Commands to run after applying the patch
```bash
python3 scripts/validate_benchmark_manifest.py --suite realworld --paper-strict
python3 scripts/benchmark_inventory.py --suite realworld
cargo check --workspace
```
