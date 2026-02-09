# Incidents And Learnings

## Entry Schema
- Date
- Trigger
- Impact
- Root Cause
- Fix
- Prevention Rule
- Evidence
- Commit
- Confidence

## Entries
- Date: 2026-02-09
- Trigger: Scheduled GitHub Actions `Rust SLO Gate` failed (run `21812678088`) with `failed to parse bench output`.
- Impact: CI gate red; no SLO signal for reconnect fan-out workloads.
- Root Cause: Gate scripts required `p95_us` to exist even when the bench produced `ok=0` (no latency samples), and the synthetic agent config inherited the `pssh` profile’s `sign_timeout_ms` behavior, which can zero out successes under heavy fan-out on contended runners.
- Fix: Disabled `sign_timeout_ms` in gate-generated agent configs, made gate/soak scripts fail with explicit “latency stats missing” diagnostics instead of parse errors, and routed `secretive-bench` logs to stderr so `--json-compact` stdout stays machine-parseable.
- Prevention Rule: Synthetic CI gates must explicitly set/disable internal timeouts that can mask throughput (for example `sign_timeout_ms`) and must not assume latency fields exist before verifying `ok>0`; JSON stdout modes must remain log-free.
- Evidence: Local `./scripts/check_shell.sh` + `cargo test -p secretive-bench` + `./scripts/bench_smoke_gate.sh` + `./scripts/bench_slo_gate.sh` passes; CI failure run `21812678088` (untrusted external log).
- Commit: f877d58
- Confidence: high
