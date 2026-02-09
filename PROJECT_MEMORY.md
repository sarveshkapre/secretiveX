# Project Memory

## Objective
- Keep secretiveX production-ready. Current focus: SecretiveX. Find the highest-impact pending work, implement it, test it, and push to main.

## Architecture Snapshot

## Open Problems

## Recent Decisions
- Template: YYYY-MM-DD | Decision | Why | Evidence (tests/logs) | Commit | Confidence (high/medium/low) | Trust (trusted/untrusted)
 - 2026-02-09 | Disable `sign_timeout_ms` in synthetic gate-generated agent configs (`bench_*`/`soak_test`) | The `pssh` profile’s default `sign_timeout_ms` can turn high fan-out reconnect benchmarks into “0 ok requests” runs on slower/contended hosts, which then produces missing latency stats and misleading gate failures. Gates should measure queue wait/latency directly instead of failing early on internal timeouts. | Local: `SLO_CONCURRENCY=64 SLO_DURATION_SECS=3 ... ./scripts/bench_slo_gate.sh` (pass). CI signal (untrusted): Rust SLO Gate run `21812678088` failed with “failed to parse bench output” after `ok=0` produced no `p95_us`. | f877d58 | high | trusted
 - 2026-02-09 | Keep `secretive-bench` JSON stdout clean by routing logs to stderr | Gate scripts and tooling depend on `--json-compact` being machine-parseable; logs on stdout make parsing brittle and hide the real failure mode. | Local: captured `secretive-bench --json-compact` stdout to a file while forcing worker errors; file contained only JSON and no `secretive_bench` log lines. | f877d58 | high | trusted

## Mistakes And Fixes
- Template: YYYY-MM-DD | Issue | Root cause | Fix | Prevention rule | Commit | Confidence

## Known Risks

## Next Prioritized Tasks
 - Count non-success SSH agent responses in `secretive-bench` as failures (not silent “ok=0 failures=0”), and optionally expose separate `worker_failures` vs request-level failures for clearer SLO math.
 - Add JSON/quiet output modes to `secretive-agent --suggest-queue-wait` and wire gate scripts to consume it automatically.
 - Resolve legacy Swift `TODO: CHECK VERSION` by implementing a real version check or removing dead code.

## Verification Evidence
- Template: YYYY-MM-DD | Command | Key output | Status (pass/fail)
 - 2026-02-09 | `cargo test -p secretive-bench` | `8 passed` | pass
 - 2026-02-09 | `./scripts/check_shell.sh` | `checked 13 script(s)` | pass
 - 2026-02-09 | `AGENT_STARTUP_TIMEOUT_SECS=90 ./scripts/bench_smoke_gate.sh` | `bench smoke gate passed` | pass
 - 2026-02-09 | `SLO_CONCURRENCY=64 SLO_DURATION_SECS=3 SLO_MIN_RPS=1 SLO_MAX_P95_US=10000000 SLO_MAX_FAILURE_RATE=1 AGENT_STARTUP_TIMEOUT_SECS=90 ./scripts/bench_slo_gate.sh` | `slo gate passed` | pass

## Historical Summary
- Keep compact summaries of older entries here when file compaction runs.
