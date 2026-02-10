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

- Date: 2026-02-10
- Trigger: GitHub Actions `Rust Bench Smoke` failed (run `21853702657`) with high `connect_failures` during reconnect fan-out.
- Impact: CI gate red; reconnect smoke signal blocked and implied possible agent protocol instability.
- Root Cause: Agent framed-request read path used `read_buf` into a buffer with excess capacity, allowing reads to overrun the declared frame length and consume bytes from the next request. Under fan-out this desynchronized the protocol stream and surfaced as connect/write failures.
- Fix: Read exactly `len` bytes by resizing the buffer and using `read_exact`, and add a regression test that writes two frames back-to-back and asserts both are parsed independently.
- Prevention Rule: For framed protocols, never use `read_buf` without bounding reads to the remaining frame length; add multi-frame read tests to catch over-read regressions.
- Evidence: Local `BENCH_CONCURRENCY=64 BENCH_REQUESTS=4 MIN_RPS=1 ./scripts/bench_smoke_gate.sh` (pass); CI failure run `21853702657` (untrusted external log).
- Commit: 32e1511, 67ed34c
- Confidence: high
