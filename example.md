
## 🔄 RustDPR 项目的完整工作流程

### **阶段 1：静态分析（Static Analysis）**

```bash
# 命令：rustdpr analyze-sites --crate-dir <路径> --out <输出文件>
```


**做的事情：**
1. 读取 Crate 的所有 `.rs` 源代码文件
2. 使用 `syn` 库解析 AST（抽象语法树）
3. 遍历 AST，找出所有：
    - **危险站点**（Dangerous Sites）：unsafe 函数/块、FFI、transmute、索引操作等
    - **Panic 站点**（Panic Sites）：unwrap()、expect()、panic!、assert! 等
4. 生成 `site_map.json` 文件

**输出示例**（就是你提供的这个文件）：
```json
{
  "crate_name": "mb_panic_after_unsafe",
  "dangerous_sites": [
    {
      "site_id": "S0001",           // 危险站点编号
      "kind": "UnsafeBlock",        // 类型：unsafe 代码块
      "enclosing_fn": "process",    // 所在函数
      "span": {                     // 位置：第 8 行
        "file": "...",
        "line_start": 8,
        "line_end": 8
      }
    }
  ],
  "panic_sites": [
    {
      "panic_id": "P0001",          // Panic 站点编号
      "kind": "UnwrapCall",         // 类型：unwrap() 调用
      "enclosing_fn": "empty_panics_after_unsafe",
      "span": {                     // 位置：第 29 行
        "file": "...",
        "line_start": 29,
        "line_end": 29
      }
    }
  ]
}
```


---

### **阶段 2：运行时追踪（Runtime Tracing）**

```bash
# 这一步需要你在测试代码中集成 rustdpr-trace
# 通常在 #[test] 函数中：
init_trace(PathBuf::from("trace.jsonl")).unwrap();
install_panic_hook();
```


**做的事情：**
1. 在测试代码中初始化追踪系统
2. 在实际执行时，每当进入危险站点，调用 `hit("S0001")` 记录
3. 如果发生 panic，自动捕获并记录
4. 生成 `trace.jsonl` 文件（每行一个 JSON 事件）

**输出示例**：
```jsonl
{"Hit":{"site_id":"S0001","ts_millis":1778502028883}}
{"Panic":{"message":"out must not be zero after unsafe write","file":"...","line":16,"ts_millis":1778502028883}}
```


---

### **阶段 3：分类（Classification）**

```bash
# 命令：rustdpr classify --trace trace.jsonl --site-map site_map.json --out result.json
```


**做的事情：**
1. 读取 `trace.jsonl`（运行时实际发生的事件）
2. 读取 `site_map.json`（静态分析发现的所有站点）
3. 分析事件的时间顺序：
    - 是否有危险站点被访问？
    - panic 发生在什么时候？
    - 危险操作和 panic 的先后关系？
4. 根据规则进行分类

**分类规则**（在 `rustdpr-classifier/src/lib.rs` 中）：

| 条件 | Relation | Class | 说明 |
|------|----------|-------|------|
| 有 panic，无危险站点访问 | `NoDangerousSiteReached` | `NormalContractPanic` | 正常的契约检查失败 |
| 有 panic，panic **前**有危险站点访问 | `AfterUnsafe` | `PanicAfterUnsafe` | ⚠️ 危险操作后的 panic |
| 有 panic，所有危险站点都在 panic **后** | `BeforeUnsafe` | `BlockingPanic` | panic 阻止了危险路径 |
| 无 panic，但有危险站点访问 | `Unknown` | `SuspiciousCandidate` | 可疑候选（可能需要关注） |
| 既无 panic 也无危险访问 | `Unknown` | `Unknown` | 未知/正常情况 |

**输出示例** (`result.json`)：
```json
{
  "relation": "AfterUnsafe",
  "class": "PanicAfterUnsafe",
  "reached_site_ids": ["S0001"],
  "notes": ["dangerous site reached before panic"]
}
```


---

### **阶段 4：生成报告（Report Generation）**

```bash
# 命令：rustdpr report --trace trace.jsonl --site-map site_map.json --result result.json --out report.md
```


**做的事情：**
1. 整合所有信息：
    - 站点地图（所有潜在的危险点和 panic 点）
    - 追踪日志（实际发生的事件）
    - 分类结果（判断结论）
2. 生成 Markdown 格式的可读报告

**输出示例** (`report.md`)：
```markdown
# RustDPR Report: mb_panic_after_unsafe

## Dangerous Sites
- S0001 UnsafeBlock ...:8-8

## Panic Sites
- P0001 UnwrapCall ...:29-29

## Trace Events
- Hit { site_id: "S0001", ... }
- Panic { message: "out must not be zero...", line: 16, ... }

## Classification
- Relation: AfterUnsafe
- Class: PanicAfterUnsafe
- Reached Sites: ["S0001"]

## Notes
- dangerous site reached before panic
```


---

## 📋 完整的 CLI 命令流程

根据你的项目结构，实际使用时是这样的：

```bash
# 1. 收集元数据（可选）
rustdpr collect --crate-dir ./benchmarks/micro/mb_panic_after_unsafe --out data/meta.json

# 2. 静态分析：生成站点地图
rustdpr analyze-sites \
  --crate-dir ./benchmarks/micro/mb_panic_after_unsafe \
  --out data/mb_panic_after_unsafe/site_map.json

# 3. 运行测试（需要在测试代码中集成 trace）
cd benchmarks/micro/mb_panic_after_unsafe
cargo test empty_panics_after_unsafe
# 这会生成 trace_after_unsafe.jsonl

# 4. 分类：分析追踪日志
rustdpr classify \
  --trace trace_after_unsafe.jsonl \
  --site-map ../../../data/mb_panic_after_unsafe/site_map.json \
  --out result.json

# 5. 生成报告
rustdpr report \
  --trace trace_after_unsafe.jsonl \
  --site-map ../../../data/mb_panic_after_unsafe/site_map.json \
  --result result.json \
  --out reports/mb_panic_after_unsafe.md
```


---

## 🎯 核心价值

这个工具的核心目的是：

> **检测"危险操作后的 panic"场景**，帮助开发者发现那些可能已经造成内存破坏但随后又 panic 的代码路径。

**典型用例：**
- ✅ 先执行了 `unsafe` 指针操作
- ✅ 然后进行了健全性检查（如 `assert!`）
- ✅ 检查失败触发 panic

这种情况虽然程序会终止，但 **unsafe 代码可能已经破坏了内存安全**，需要特别关注！

---

**总结：你的理解完全正确！** 这是一个典型的"静态分析 + 动态追踪 + 分类决策"的安全分析工具。