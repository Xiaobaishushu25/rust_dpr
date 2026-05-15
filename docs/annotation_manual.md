# RustDPR Annotation Manual

## Primary Labels
- Noise
- ContractPanic
- HarnessMisuse
- BlockingPanic
- PanicAfterUnsafe
- InsideUnsafePanic
- DangerousPathReached
- OracleConfirmedBug
- SuspiciousCandidate
- Unknown

## Relation Labels
- NoneObserved
- BeforeUnsafe
- AfterUnsafe
- InsideUnsafe
- AdjacentToUnsafe
- FfiBoundary
- Unknown

## Harness Validity
- ConfirmedValid
- LikelyValid
- LikelyMisuse
- Invalid
- Unknown

## Rule
1. 如果 harness 明显构造 raw/null pointer 并主导错误，优先标记 HarnessMisuse。
2. 如果 ASan/Miri 明确确认，优先标记 OracleConfirmedBug。
3. 如果 trace 命中 dangerous site 后再 panic，优先标记 PanicAfterUnsafe。
4. 如果 panic 与 dangerous site 临近但未命中，标记 BlockingPanic 或 Unknown。