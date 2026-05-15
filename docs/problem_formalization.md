# Panic-aware Dangerous-path Validation

RustDPR 的目标不是报告更多 panic，而是判断一次执行是否提供了
unsafe / FFI dangerous path 的有效验证证据。

## Core Objects
- Dangerous Site
- Panic Site
- Dangerous Path
- Harness Validity
- Oracle Evidence
- Primary Classification