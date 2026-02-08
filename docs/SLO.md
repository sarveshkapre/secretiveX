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
- Tail thresholds are available when both `SLO_QUEUE_WAIT_TAIL_NS` and `SLO_QUEUE_WAIT_TAIL_MAX_RATIO` are non-zero. The gate sums histogram buckets whose upper bound is greater than or equal to the tail threshold and fails when their ratio exceeds the configured maximum.
- Agent metrics also emit `queue_wait_percentiles` (p50/p90/p95/p99) so you can make quick pass/fail calls without crunching histograms; scripts can prefer these when the JSON snapshot has them.

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
