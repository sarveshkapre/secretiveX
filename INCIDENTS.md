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
- Date: 2026-02-11
- Trigger: GitHub Actions `Rust Lint` failed for commit `3301e2d` (run `21894477861`) with unresolved imports in `crates/secretive-core/src/secure_enclave_store.rs`.
- Impact: Lint pipeline red on main until a follow-up patch landed.
- Root Cause: Secure Enclave helper functions were target-gated to macOS, but the helper test module still compiled for non-mac targets during `cargo clippy --workspace --all-targets`, leaving imports unresolved on Linux.
- Fix: Scoped helper tests to `#[cfg(all(test, target_os = "macos"))]` so test compilation matches helper availability.
- Prevention Rule: Any target-gating change must include a same-file test-module gate audit; verify with `cargo clippy --workspace --all-targets` before push.
- Evidence: CI run `21894477861` (untrusted external log), local `cargo clippy --workspace --all-targets` and `cargo test -p secretive-core` after patch (pass).
- Commit: e08a78d
- Confidence: high

- Date: 2026-02-11
- Trigger: Scheduled GitHub Actions `Rust Fanout 1000 Gate` failed (run `21892142757`) with `SLO failure: throughput below minimum (rps=0.0 min=20)` and bench JSON `attempted=0`.
- Impact: Scheduled high-fanout CI signal was red and did not validate reconnect throughput/latency as intended.
- Root Cause: `secretive-bench` duration-mode runs inherited default `--warmup 10`; warmup executes before the timed loop and is excluded from counters. At 1000 reconnect workers, warmup consumed the entire 15-second window, so timed workload recorded zero attempts.
- Fix: Made duration-mode benchmarks default to `warmup=0` unless `--warmup` is explicitly passed, added parser regression tests for default and override behavior, and set `bench_slo_gate.sh` default `SLO_WARMUP=0` with explicit pass-through.
- Prevention Rule: Duration-based CI gates must set warmup explicitly and benchmark argument parsing must have tests for default-vs-override semantics to avoid hidden pre-measurement work.
- Evidence: CI run `21892142757` (untrusted external log); local `cargo test -p secretive-bench` + `AGENT_STARTUP_TIMEOUT_SECS=90 SLO_CONCURRENCY=64 SLO_DURATION_SECS=2 SLO_MIN_RPS=1 SLO_MAX_P95_US=10000000 SLO_MAX_FAILURE_RATE=1 ./scripts/bench_slo_gate.sh` (pass).
- Commit: 7d73122
- Confidence: high

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

### 2026-02-12T20:01:39Z | Codex execution failure
- Date: 2026-02-12T20:01:39Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-2.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:05:07Z | Codex execution failure
- Date: 2026-02-12T20:05:07Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-3.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:08:36Z | Codex execution failure
- Date: 2026-02-12T20:08:36Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-4.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:12:02Z | Codex execution failure
- Date: 2026-02-12T20:12:02Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-5.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:15:36Z | Codex execution failure
- Date: 2026-02-12T20:15:36Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-6.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:19:04Z | Codex execution failure
- Date: 2026-02-12T20:19:04Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-7.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:22:27Z | Codex execution failure
- Date: 2026-02-12T20:22:27Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-8.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:26:04Z | Codex execution failure
- Date: 2026-02-12T20:26:04Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-9.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:29:38Z | Codex execution failure
- Date: 2026-02-12T20:29:38Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-10.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:33:06Z | Codex execution failure
- Date: 2026-02-12T20:33:06Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-11.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:36:35Z | Codex execution failure
- Date: 2026-02-12T20:36:35Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-12.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:40:02Z | Codex execution failure
- Date: 2026-02-12T20:40:02Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-13.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:43:33Z | Codex execution failure
- Date: 2026-02-12T20:43:33Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-14.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:47:08Z | Codex execution failure
- Date: 2026-02-12T20:47:08Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-15.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:50:34Z | Codex execution failure
- Date: 2026-02-12T20:50:34Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-16.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:54:08Z | Codex execution failure
- Date: 2026-02-12T20:54:08Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-17.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:57:42Z | Codex execution failure
- Date: 2026-02-12T20:57:42Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-18.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:01:09Z | Codex execution failure
- Date: 2026-02-12T21:01:09Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-19.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:04:35Z | Codex execution failure
- Date: 2026-02-12T21:04:35Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-secretiveX-cycle-20.log
- Commit: pending
- Confidence: medium
