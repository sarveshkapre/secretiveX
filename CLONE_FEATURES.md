# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] Teach `secretive-client --metrics-file` to summarize histogram percentiles (p50/p95) so humans can reason without spreadsheets.
- [ ] Wire histogram parsing into the SLO/soak gate scripts to fail fast when high-tail queue wait buckets spike.
- [ ] Add a `--reset-metrics` admin signal to zero histogram/snapshot counters for interval-based observability.

## Implemented
- 2026-02-08: Added queue wait histogram tracking/export in Rust agent metrics and surfaced it via `secretive-client --metrics-file` (crates/secretive-agent/src/main.rs, crates/secretive-client/src/main.rs, README/docs updates, tests).

## Insights
- Queue-wait regressions were hard to diagnose with only avg/max; histogram buckets now expose whether tail latency or bursts are driving pressure, and the client can show that without jq.

## Notes
- This file is maintained by the autonomous clone loop.
