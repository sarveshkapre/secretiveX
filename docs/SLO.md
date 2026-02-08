# SecretiveX Initial SLOs

This document defines initial performance and reliability SLOs for reconnect fan-out workloads.

## Target workload

- Mode: reconnect (`secretive-bench --reconnect`)
- Workload: signing requests with file-store keys
- Fan-out: up to 1000 concurrent workers

## Initial SLO thresholds

- Throughput: `rps >= 20`
- Latency: `p95_us <= 300000`
- Reliability: `failure_rate <= 0.01`

These are baseline guardrails and should tighten as implementation matures.

Queue-wait envelopes are treated as strict when configured:
- Non-zero queue-wait thresholds require queue-wait metrics to be present.
- Missing queue-wait metrics with strict envelopes fails the gate.
- Tail thresholds are available when both `SLO_QUEUE_WAIT_TAIL_NS` and `SLO_QUEUE_WAIT_TAIL_MAX_RATIO` are non-zero. The gate now prefers agent-provided percentiles (`queue_wait_percentiles`) to calculate whether the configured tail percentile violates the threshold; when percentiles are missing it falls back to summing histogram buckets whose upper bound is greater than or equal to the tail threshold and fails when their ratio exceeds the configured maximum.
- Agent metrics also emit `queue_wait_percentiles` (p50/p90/p95/p99) so you can make quick pass/fail calls without crunching histograms; scripts can prefer these when the JSON snapshot has them.
- Leaving both tail knobs unset now auto-selects sane defaults for the configured profile (`pssh` uses 4ms with ≤3% tail, `fanout` 6ms/≤4%, `balanced` 8ms/≤5%, `low-memory` 12ms/≤7%); override the env vars to customize.
- `secretive-bench` now accepts `--metrics-file` + `--queue-wait-tail-*` flags and emits a `queue_wait` block in its JSON output (also driven by `SECRETIVE_BENCH_*` env vars). `bench_slo_gate.sh` wires these flags automatically so CI artifacts always include both the configured guardrail and the observed percentile/histogram tail.
- For quick investigations without re-running the bench, `secretive-client --metrics-file /tmp/agent.json --queue-wait-tail-profile pssh [--queue-wait-max-age-ms 5000]` enforces the same tail guardrails offline and exits non-zero (code `3`) when the snapshot is stale or violates the envelope.
- `secretive-agent --suggest-queue-wait [--profile ... | --config ...]` inspects the merged config plus hardware concurrency and prints a recommended `tail_ns`/`tail_ratio` pair (and matching env exports) so you can align CI thresholds with whatever profile or machine you're targeting before running the gate.

## Enforcing SLOs

Run gate locally:

```bash
./scripts/bench_slo_gate.sh
```

Tune gate inputs and thresholds:

```bash
SLO_CONCURRENCY=1000 \
SLO_DURATION_SECS=20 \
SLO_MIN_RPS=20 \
SLO_MAX_P95_US=300000 \
SLO_MAX_FAILURE_RATE=0.01 \
./scripts/bench_slo_gate.sh
```

For faster developer checks:

```bash
SLO_CONCURRENCY=128 SLO_DURATION_SECS=5 ./scripts/bench_slo_gate.sh
```
