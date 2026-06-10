# Realworld inventory v1
This inventory separates the existing local pilot cases from the new round-1 external crate wrappers. Local pilot cases are kept for smoke testing and should not be used as the main paper realworld table.
## Summary
| Bucket | Count | Paper role |
|---|---:|---|
| Existing local/pilot extracts | 6 | Smoke/pipeline only |
| New pinned external crate wrappers | 8 | Realworld round-1 main candidates |
| Total realworld directories after round 1 | 14 | Inventory/manifest coverage |

## Existing pilot cases
| case_id | Status | Paper-main recommendation |
|---|---|---|
| `rw_smoke_raw_slice_view` | local extract already present | Exclude from main realworld table; retain for smoke/pipeline regression |
| `rw_bytes_frame_parser` | local extract already present | Exclude from main realworld table; retain for smoke/pipeline regression |
| `rw_ffi_cstr_boundary` | local extract already present | Exclude from main realworld table; retain for smoke/pipeline regression |
| `rw_image_stride_copy` | local extract already present | Exclude from main realworld table; retain for smoke/pipeline regression |
| `rw_arena_nonnull_handle` | local extract already present | Exclude from main realworld table; retain for smoke/pipeline regression |
| `rw_packet_set_len_decoder` | local extract already present | Exclude from main realworld table; retain for smoke/pipeline regression |

## New external crate cases
| case_id | crate | pinned version | domain | license | fuzz entrypoint | input kind | notes |
|---|---|---:|---|---|---|---|---|
| `rw_png_decode` | `png` | `=0.18.1` | parser | MIT OR Apache-2.0 | `png::Decoder::read_info / next_frame` | reader-bytes | negative parser control; no known vulnerability target |
| `rw_jpeg_decoder_decode` | `jpeg-decoder` | `=0.3.2` | parser | MIT OR Apache-2.0 | `jpeg_decoder::Decoder::read_info / decode` | reader-bytes | bounded JPEG metadata/decode path |
| `rw_postcard_deser` | `postcard` | `=1.1.3` | serialization | MIT OR Apache-2.0 | `postcard::from_bytes::<Packet>` | bytes | Serde-compatible binary deserialization |
| `rw_bytes_buf_ops` | `bytes` | `=1.11.1` | bytes | MIT | `bytes::{BytesMut, Buf, BufMut}` | operation-sequence | buffer/cursor operations through safe public API |
| `rw_zerocopy_header_ref` | `zerocopy` | `=0.8.48` | bytes | BSD-2-Clause OR Apache-2.0 OR MIT | `zerocopy::Ref::from_prefix::<PacketHeader>` | bytes | zero-copy header view with crate-enforced size/alignment checks |
| `rw_lz4_flex_block_decode` | `lz4_flex` | `=0.13.1` | compression | MIT OR Apache-2.0 | `lz4_flex::block::decompress_size_prepended` | bytes | bounded size-prepended LZ4 block decode |
| `rw_flate2_zlib_decode` | `flate2` | `=1.1.9` | compression | MIT OR Apache-2.0 | `flate2::read::ZlibDecoder` | reader-bytes | bounded zlib stream decode using rust_backend |
| `rw_smallvec_ops` | `smallvec` | `=1.15.1` | datastructure | MIT OR Apache-2.0 | `smallvec::SmallVec safe operations` | operation-sequence | inline/spilled storage transition via public API |

## Validation status in this environment
- `python3 scripts/validate_benchmark_manifest.py --suite realworld --paper-strict`: PASS for all 14 realworld cases.
- `python3 scripts/benchmark_inventory.py --suite realworld`: PASS; relation distribution is now 8 `NoneObserved` external controls plus 6 existing `AfterUnsafe` local pilots.
- `cargo check --workspace`: not executed here because the sandbox image does not provide the `cargo` binary. Run it in the RustDPR development environment after applying the patch.
