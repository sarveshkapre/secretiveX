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
