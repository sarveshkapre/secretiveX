# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] Add a `secretive-agent --suggest-queue-wait` helper that inspects the current profile/hardware and prints recommended tail thresholds for operators tweaking CI or production agents.
- [ ] Teach `secretive-client --metrics-file` to flag when the most recent snapshot exceeds the profile's guardrail so humans can spot tail pressure without rerunning the gate script.

## Implemented
- 2026-02-08: Added SIGUSR2/`secretive-agent --reset-metrics` admin helper so operators can zero metrics counters mid-run and emit a fresh snapshot (crates/secretive-agent/src/main.rs, README.md, docs/RUST_CONFIG.md, cargo test -p secretive-agent).
- 2026-02-08: Bench SLO gate enforces histogram-derived queue-wait tail ratios so p95/p99 regressions surface automatically (scripts/bench_slo_gate.sh, README.md, docs/SLO.md, docs/RUST_BENCH.md).
- 2026-02-08: Bench SLO gate now auto-picks queue-wait tail thresholds per profile so developers/CI get sensible guardrails out of the box (scripts/bench_slo_gate.sh, README.md, docs/SLO.md, docs/RUST_BENCH.md).
- 2026-02-08: Added queue wait histogram tracking/export in Rust agent metrics and surfaced it via `secretive-client --metrics-file` (crates/secretive-agent/src/main.rs, crates/secretive-client/src/main.rs, README/docs updates, tests).
- 2026-02-08: `secretive-client --metrics-file` now prints queue-wait percentile estimates (p50/p90/p95/p99) directly from histogram buckets so humans can eyeball tail pressure without spreadsheets (crates/secretive-client/src/main.rs, docs/RUST_CLIENT.md, cargo test -p secretive-client).
- 2026-02-08: Agent snapshots now embed `queue_wait_percentiles` (p50/p90/p95/p99) and the CLI prefers them before falling back to histogram math, so SLO reviews get exact tail numbers on every scrape (crates/secretive-agent/src/main.rs, crates/secretive-client/src/main.rs, README.md, docs/RUST_CONFIG.md, docs/RUST_CLIENT.md, docs/SLO.md, cargo test -p secretive-agent, cargo test -p secretive-client).
- 2026-02-08: Bench SLO gate prefers agent-provided queue-wait percentiles for tail enforcement, falling back to histograms only when necessary, so pipeline verdicts no longer depend on ad-hoc parsing (scripts/bench_slo_gate.sh, README.md, docs/SLO.md, docs/RUST_BENCH.md, ./scripts/bench_slo_gate.sh).
- 2026-02-08: `secretive-bench` records queue-wait guardrails/percentiles directly in its JSON (CLI/env flags + docs + tests) so dashboards can ingest the exact thresholds applied during SLO runs (crates/secretive-bench/src/main.rs, docs/RUST_BENCH.md, docs/SLO.md, scripts/bench_slo_gate.sh, scripts/soak_test.sh, cargo test -p secretive-bench).

## Insights
- Queue-wait regressions were hard to diagnose with only avg/max; histogram buckets now expose whether tail latency or bursts are driving pressure, and the client can show that without jq.
- Human-friendly percentile summaries make it obvious when p95+ queue wait spikes, so operators can set alert thresholds without exporting the histogram elsewhere.
- Tail-ratio gating turns histogram data into an actionable SLO knob, so we can alert on 5%+ queue waits before averages move—next we should auto-suggest sane thresholds per workload profile.
- Auto guardrails ensure every gate run enforces a tail envelope even if engineers forget to export env vars; we should follow up with tooling that surfaces the chosen thresholds alongside the observed percentiles.
- Resetting counters with SIGUSR2 or the CLI helper keeps dashboards from mixing baselines when incidents happen, so observability tooling can treat each interval independently without recycling the agent.
- Precomputing percentiles in the agent keeps us aligned with modern observability guidance (for example, [Anyscale's latest latency benchmarking guide](https://docs.anyscale.com/llm/serving/benchmarking/metrics) and [Google SRE's "Metrics That Matter"](https://cacm.acm.org/practice/metrics-that-matter/) both insist on monitoring p50/p95/p99), reducing toil for both humans and scripts inspecting queue pressure.
- Tail verdicts now resolve instantly when percentiles exist, so SLO gates stay actionable even if histogram buckets are missing (or redacted) from field captures.
- Embedding the queue-wait guardrail inputs/output straight into bench JSON gives us a clean, machine-readable audit trail for every CI run; now we can diff actual percentiles vs thresholds without parsing shell logs, which sets up future alerting in Grafana/Looker or even a `--suggest-queue-wait` CLI.

## Notes
- This file is maintained by the autonomous clone loop.
