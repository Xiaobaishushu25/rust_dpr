# Real-world Crate Benchmark

Selection criteria:

- builds with pinned RustDPR toolchain;
- contains unsafe/FFI/manual allocation/drop-sensitive code;
- has stable public API or fuzz target;
- not selected solely because RustDPR succeeds.

For each crate, record:

- crate name and version;
- domain;
- unsafe density;
- number of dangerous sites by category;
- build status;
- fuzz harness source.
