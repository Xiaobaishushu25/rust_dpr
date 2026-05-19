# RustDPR Experiment Protocol

## Suites

- `micro`: controlled semantic cases with ground truth labels.
- `oracle`: controlled ASan/Miri-confirmable memory/UB cases.
- `taxonomy`: panic-danger relation taxonomy cases.
- `regression`: historical RustSec/CVE/GitHub issue cases.
- `realworld`: selected crates from the Rust ecosystem.

## Run Identity

Each run is identified by:

```text
<suite>/<case>/<tool>/<variant>/<seed>/<run_index>