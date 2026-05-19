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

## Annotation Procedure

1. Annotators inspect source code, harness code, trace, and oracle logs.
2. Annotators must not inspect RustDPR final classification before assigning labels.
3. Each case receives:
   - primary_label
   - relation
   - harness_status
   - oracle_verdict
   - security_relevant
   - rationale
4. Disagreements are resolved by adjudication.

## Label Priority

1. Invalid or misuse harness dominates unless oracle evidence proves target bug under valid preconditions.
2. OracleConfirmedBug dominates panic relation labels.
3. InsideUnsafePanic dominates PanicAfterUnsafe.
4. BlockingPanic requires evidence that panic occurs before dangerous-site hit or before statically adjacent dangerous path.
5. ContractPanic requires no dangerous-site hit and no near dangerous-path evidence.
