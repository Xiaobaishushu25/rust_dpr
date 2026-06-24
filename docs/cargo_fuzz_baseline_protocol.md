# RustDPR × cargo-fuzz：论文级对比协议

## 1. 论文中的公平主张

本实验不比较“谁生成了更好的 harness”，也不把 RustDPR 描述为 cargo-fuzz 的替代 fuzzer。主张应限定为：

> 在相同 crate、相同 cargo-fuzz target、相同 seed、相同时间预算、相同 libFuzzer artifact 集合上，RustDPR 是否能以更高的候选精度、更低的 panic-noise FPR 和更低的人工审查负担，对 cargo-fuzz 输出进行安全相关性验证与分流。

主实验的两个 pipeline 必须消费同一 artifact 集合：

| Pipeline | 输入 | 判定 |
|---|---|---|
| `cargo-fuzz/crash-only` | 当前 campaign 的全部 libFuzzer artifacts | 每个 artifact 都进入人工审查队列 |
| `cargo-fuzz/full` | 完全相同的 artifacts | 每个 artifact 单独 replay、单独 trace、单独分类 |

Corpus reachability/coverage 是另一类实验，不得把 corpus 只交给 RustDPR、而 baseline 只看 artifacts。

## 2. 不可违反的实验不变量

1. 一个 artifact = 一个 candidate = 一个独立 trace = 一个独立 classification。
2. 不允许把多个输入的 trace 拼接后分类。
3. 每个 target/seed/run 使用隔离的 corpus 与 artifact 目录。
4. 每个 seed 从同一只读 seed-corpus snapshot 开始；不得继承上一 seed 新发现的 corpus。
5. candidate ID 由完整输入内容 SHA-256 派生，不由绝对路径派生。
6. baseline 与 RustDPR 使用完全相同的 artifact SHA-256 集合。
7. case-level `expected.yaml` 不得自动赋给同一 case 下的每个 artifact。
8. MCP/FPR 使用 candidate-level、盲法人工标注；`NoOracleFinding` 不是负样本真值。
9. fuzz CPU 时间按 campaign 计一次，不得对 campaign 中的每个 artifact 重复计费。
10. 即使某个 campaign 产生 0 个 artifact，也必须保留 `campaign_record.json`，计入 campaign 数和 CPU-hour 分母。
11. 最终可复现性实验使用 `replay_repeat=10`；`replay_stable=true` 仅表示 10/10 次均为非零退出、均产生独立 RustDPR trace，且退出码一致。
12. missing trace、build failure、timeout、unsupported oracle 均显式报告，不能删除。

## 3. 当前脚本的数据布局

```text
data/
  cargo_fuzz_campaigns/<case>/<target>/seed-<s>/run-<r>/
    corpus/
    artifacts/
  external_inputs/cargo-fuzz/<case>/<target>/seed-<s>/run-<r>/
  external_runs/cargo-fuzz/<case>/<target>/seed-<s>/run-<r>/run_meta.json
  external_replays/cargo-fuzz/<case>/<target>/seed-<s>/run-<r>/
    per_input_traces/<input-id>/replay-XX.jsonl
    per_input_replay/<input-id>.json
    per_input_meta/<input-id>.json
  runs/<suite>/<case>/cargo-fuzz/<variant>/<target>/seed-<s>/run-<r>/
    campaign_record.json
    <input-id>/
      run_meta.json
      classification.json
      trace_log.json
      site_map.json
      dpg.json
      harness_validity.json
      candidates.jsonl
```

## 4. Windows PowerShell + WSL2 环境

cargo-fuzz/libFuzzer campaign 建议统一在 WSL2 Linux 中运行。以下示例假设仓库位于 WSL 的 `~/rust_dpr-master`。

```powershell
wsl -d Ubuntu-24.04 -- bash -lc "rustup toolchain install nightly"
wsl -d Ubuntu-24.04 -- bash -lc "rustup +nightly component add rust-src llvm-tools-preview miri"
wsl -d Ubuntu-24.04 -- bash -lc "cargo install cargo-fuzz --locked"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 -m pip install --user pyyaml"
```

静态检查：

```powershell
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 -m compileall -q scripts external_tools"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/validate_benchmark_manifest.py"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && cargo check --workspace"
```

`cargo check --workspace` 只检查 RustDPR 顶层 workspace 中明确列出的包，不能作为
regression 全量实验的完整构建门槛。历史 vulnerable/fixed case 允许使用彼此不兼容的
依赖图；cargo-fuzz 实验以 matrix manifest 为 case 清单，并从每个 case 的
`fuzz/Cargo.toml` 独立构建。顶层 `Cargo.toml` 是否包含某个 fixed case 不决定该 case
是否进入 cargo-fuzz 实验。

## 5. 先做 smoke，再做全矩阵兼容性门槛

### 5.1 生成 regression smoke manifest

```powershell
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/discover_cargo_fuzz_cases.py --search-root benchmarks/regression --out scripts/cargo_fuzz_matrix.regression.smoke.yaml --seeds 1,2,3 --budget-seconds 300 --replay-repeat 1 --run-index 1 --input-kind artifacts"
```

### 5.2 运行一个 case 的端到端 smoke

```powershell
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/run_cargo_fuzz_matrix.py --manifest scripts/cargo_fuzz_matrix.regression.smoke.yaml --phase preflight --limit-cases 1"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/run_cargo_fuzz_matrix.py --manifest scripts/cargo_fuzz_matrix.regression.smoke.yaml --phase run-fuzz --limit-cases 1"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/run_cargo_fuzz_matrix.py --manifest scripts/cargo_fuzz_matrix.regression.smoke.yaml --phase collect --limit-cases 1"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/run_cargo_fuzz_matrix.py --manifest scripts/cargo_fuzz_matrix.regression.smoke.yaml --phase validate --limit-cases 1 --asan-from-replay-log"
```

验收：

- 每个 campaign 有独立的 corpus/artifacts；
- 每个 artifact 只有一个 candidate 目录；
- 每个 candidate 的 `input_files` 长度为 1；
- candidate trace 路径位于自身 `per_input_traces/<id>/` 下；
- aggregate replay meta 含 `classification_forbidden=true`；
- treatment 与 baseline 的 artifact SHA-256 集合完全相同；
- 0-artifact campaign 仍存在 `campaign_record.json`。

### 5.3 全矩阵构建门槛

在投入多 seed、长预算之前，必须对 manifest 中每个 target 运行一次真实
`cargo fuzz build`。该步骤会发现旧版本依赖解析失败、MSRV/工具链问题、平台问题以及
局部 patch 未进入 fuzz workspace 等错误：

先生成一个只用于兼容性检查和 1-seed pilot 的 manifest。它应发现 regression 目录下的全部 case，是否位于顶层 Cargo workspace 与此无关：

```powershell
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/discover_cargo_fuzz_cases.py --search-root benchmarks/regression --out scripts/cargo_fuzz_matrix.regression.compat.yaml --seeds 1 --budget-seconds 60 --replay-repeat 1 --run-index 2 --input-kind artifacts"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/run_cargo_fuzz_matrix.py --manifest scripts/cargo_fuzz_matrix.regression.compat.yaml --phase build-check --continue-on-error --summary-out reports/cargo_fuzz_regression_build_check_summary.json"
```

构建日志位于：

```text
reports/cargo_fuzz_build_check/<case>/<target>.log
```

只有全部 case 构建通过后，才进入全矩阵 1-seed pilot。对使用本地 vendored vulnerable
snapshot 的 case，`[patch.crates-io]` 必须写在 `fuzz/Cargo.toml` 这一 fuzz workspace
root 中；只写在仓库顶层 `Cargo.toml` 不足以影响独立 fuzz workspace。

```powershell
$Compat = "scripts/cargo_fuzz_matrix.regression.compat.yaml"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Compat --phase run-fuzz --continue-on-error"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Compat --phase collect --continue-on-error"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Compat --phase validate --asan-from-replay-log --continue-on-error"
```

## 6. 5-seed pilot 与 10-seed final

建议使用不同的 `run_index` 隔离不同实验批次：`1=smoke`、`2=全矩阵 1-seed`、`3=5-seed pilot`、`4=10-seed final`。后处理脚本必须按 final 的 run index 过滤，否则旧 smoke/pilot 会混入论文表。矩阵脚本在 `baseline` 和 `metrics` 阶段会自动读取 manifest 中的 run index 并传递过滤条件。

先做 5-seed pilot 检查方差和失败率，再固定协议做 10-seed final。下面展示 final 配置示例；时间预算应在预实验后冻结，不能看到结果后按 case 调整。

```powershell
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/discover_cargo_fuzz_cases.py --search-root benchmarks/regression --out scripts/cargo_fuzz_matrix.regression.final.yaml --seeds 1,2,3,4,5,6,7,8,9,10 --budget-seconds 1800 --replay-repeat 10 --run-index 4 --input-kind artifacts"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/discover_cargo_fuzz_cases.py --search-root benchmarks/realworld --out scripts/cargo_fuzz_matrix.realworld.final.yaml --seeds 1,2,3,4,5,6,7,8,9,10 --budget-seconds 3600 --replay-repeat 10 --run-index 4 --input-kind artifacts"
```

逐阶段执行便于断点恢复：

```powershell
$Repo = "~/rust_dpr-master"
$Regression = "scripts/cargo_fuzz_matrix.regression.final.yaml"
$Realworld = "scripts/cargo_fuzz_matrix.realworld.final.yaml"

wsl -d Ubuntu-24.04 -- bash -lc "cd $Repo && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Regression --phase preflight"
wsl -d Ubuntu-24.04 -- bash -lc "cd $Repo && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Regression --phase run-fuzz --continue-on-error"
wsl -d Ubuntu-24.04 -- bash -lc "cd $Repo && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Regression --phase collect --continue-on-error"
wsl -d Ubuntu-24.04 -- bash -lc "cd $Repo && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Regression --phase validate --asan-from-replay-log --continue-on-error"

wsl -d Ubuntu-24.04 -- bash -lc "cd $Repo && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Realworld --phase preflight"
wsl -d Ubuntu-24.04 -- bash -lc "cd $Repo && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Realworld --phase run-fuzz --continue-on-error"
wsl -d Ubuntu-24.04 -- bash -lc "cd $Repo && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Realworld --phase collect --continue-on-error"
wsl -d Ubuntu-24.04 -- bash -lc "cd $Repo && python3 scripts/run_cargo_fuzz_matrix.py --manifest $Realworld --phase validate --asan-from-replay-log --continue-on-error"
```

`--continue-on-error` 只用于让整个矩阵继续；最终表必须列出每个失败 case/seed，不能把失败项从分母删除。

## 7. Candidate-level 盲法标注

先导出不包含 RustDPR 预测标签的模板：

```powershell
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/export_candidate_truth_template.py --suite regression --tool cargo-fuzz --variant full --run-index 4 --out annotations/cargo_fuzz_regression_truth.csv"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/export_candidate_truth_template.py --suite realworld --tool cargo-fuzz --variant full --run-index 4 --out annotations/cargo_fuzz_realworld_truth.csv"
```

至少填写：

- `security_relevant`：`true` / `false`；
- `truth_source`；
- `annotator_1`、`annotator_2`；
- `adjudicated`；
- `rationale`。

推荐同时填写 relation、harness status 和 oracle verdict，供错误分析使用。两位标注者先独立标注，再 adjudication；标注阶段不要查看 RustDPR classification。

## 8. 生成 baseline、指标和论文表格

```powershell
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/materialize_external_baselines.py --suite regression --source-tool cargo-fuzz --source-variant full --baseline crash-only --out-variant crash-only --run-index 4"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/compute_metrics.py --suite regression --candidate-truth annotations/cargo_fuzz_regression_truth.csv --run-index 4 --out reports/metrics_regression_cargo_fuzz.json"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/compare_pipelines.py --metrics reports/metrics_regression_cargo_fuzz.json --baseline cargo-fuzz/crash-only --treatment cargo-fuzz/full --out-json reports/regression_cargo_fuzz_delta.json --out-csv reports/regression_cargo_fuzz_delta.csv --out-md reports/regression_cargo_fuzz_delta.md"

wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/materialize_external_baselines.py --suite realworld --source-tool cargo-fuzz --source-variant full --baseline crash-only --out-variant crash-only --run-index 4"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/compute_metrics.py --suite realworld --candidate-truth annotations/cargo_fuzz_realworld_truth.csv --run-index 4 --out reports/metrics_realworld_cargo_fuzz.json"
wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/compare_pipelines.py --metrics reports/metrics_realworld_cargo_fuzz.json --baseline cargo-fuzz/crash-only --treatment cargo-fuzz/full --out-json reports/realworld_cargo_fuzz_delta.json --out-csv reports/realworld_cargo_fuzz_delta.csv --out-md reports/realworld_cargo_fuzz_delta.md"

wsl -d Ubuntu-24.04 -- bash -lc "cd ~/rust_dpr-master && python3 scripts/make_cargo_fuzz_paper_table.py --metrics regression=reports/metrics_regression_cargo_fuzz.json --metrics realworld=reports/metrics_realworld_cargo_fuzz.json --out-prefix reports/tables/cargo_fuzz_main"
```

输出：

```text
reports/tables/cargo_fuzz_main.csv
reports/tables/cargo_fuzz_main.md
reports/tables/cargo_fuzz_main.tex
```

## 9. 主表进入论文前的硬门槛

- regression 和 realworld 均完成；micro 只能做协议/语义 sanity check；
- candidate truth coverage 至少 95%，最好 100%；
- 两个 pipeline 的 unique artifact SHA-256 集合一致；
- campaign 数包含 0-artifact seed；
- fuzz campaign CPU-hour 不按 artifact 重复计费；
- replay repeat 固定为 10，稳定性定义公开；
- missing independent trace 单独列出；
- ASan/Miri unsupported/build failure/timeout 单独列出；
- 不把全 0 的 oracle 列作为论文 headline 结果；
- 至少报告 median/IQR，并按 paired case/seed 做统计检验；
- 每张表均可由脚本从原始 run data 一键生成。

## 10. 与 RPG/RULF 的衔接

cargo-fuzz 表冻结后，再进入 generated-harness 对比。RPG/RULF 阶段需要新增的公平维度是：

- generated target count；
- compile rate；
- valid harness rate；
- API/dependency/unsafe-API coverage；
- artifact 数与 candidate-level MCP/FPR；
- harness misuse rate；
- oracle-confirmed rate；
- review load。

当前 `external_tools/rpg/adapter.py` 与 `external_tools/rulf/adapter.py` 只是输出规范化 adapter，不是工具复现。没有完成原工具构建、target generation 和 fuzz campaign 前，不得在论文中写成“已复现 RPG/RULF”。
