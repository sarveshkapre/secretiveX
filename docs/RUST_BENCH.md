# Rust Benchmarking

`secretive-bench` is a lightweight load generator for the Rust agent.

Load-shaping controls:
- `--worker-start-spread-ms <n>` staggers worker start times across `n` milliseconds.

## Basic usage

```bash
cargo run -p secretive-bench -- --concurrency 64 --requests 200
```

## JSON output

```bash
cargo run -p secretive-bench -- --concurrency 100 --requests 50 --json
```

Compact JSON:

```bash
cargo run -p secretive-bench -- --concurrency 100 --requests 50 --json-compact
```

JSON now includes metadata fields for dashboards and traceability:
- `meta.schema_version`
- `meta.bench_version`
- `meta.started_unix_ms` / `meta.finished_unix_ms`
- `meta.hostname`, `meta.pid`
- `meta.target_os`, `meta.target_arch`

## CSV output

Emit a single CSV row for spreadsheet or ingestion pipelines:

```bash
cargo run -p secretive-bench -- --concurrency 100 --requests 50 --csv
```

Skip CSV header row:

```bash
cargo run -p secretive-bench -- --concurrency 100 --requests 50 --csv --no-csv-header
```

## High fan-out simulation

```bash
cargo run -p secretive-bench -- \
  --concurrency 1000 \
  --requests 10 \
  --warmup 5 \
  --worker-start-spread-ms 2000 \
  --payload-size 128
```

## Fixed payloads

Disable randomizing payload bytes to focus on signing throughput:

```bash
cargo run -p secretive-bench -- --concurrency 500 --requests 20 --fixed
```

## Reconnect per request

Use `--reconnect` to open a fresh connection for every sign request (closer to pssh fan-out).

```bash
cargo run -p secretive-bench -- \
  --concurrency 500 \
  --requests 5 \
  --reconnect
```

## Duration-based run

```bash
cargo run -p secretive-bench -- --concurrency 200 --duration 30
```

## Response timeout

```bash
cargo run -p secretive-bench -- --concurrency 200 --duration 30 --response-timeout-ms 500
```

## Latency percentiles

Collect p50/p95/p99/max/avg request latency in microseconds:

```bash
cargo run -p secretive-bench -- --concurrency 200 --duration 30 --latency
```

Cap latency samples to bound memory:

```bash
cargo run -p secretive-bench -- --concurrency 200 --duration 30 --latency --latency-max-samples 50000
```

## Identity list benchmark

```bash
cargo run -p secretive-bench -- --concurrency 200 --requests 50 --list
```

## Reuse a key blob

Fetch a key once via `secretive-client --list --json` and pass the hex blob:

```bash
cargo run -p secretive-bench -- --concurrency 200 --requests 50 --key <hex_blob>
```

## RSA hash flags

Use `--flags` to exercise RSA SHA-256/512 flags (2 or 4 respectively), or pass `sha256`/`sha512`/`ssh-rsa`.

## CI smoke gate

Run the reconnect fan-out smoke gate locally:

```bash
./scripts/bench_smoke_gate.sh
```

Tune thresholds:

```bash
MIN_RPS=50 BENCH_CONCURRENCY=256 BENCH_REQUESTS=8 ./scripts/bench_smoke_gate.sh
```

## Regression gate

Run consolidated regression checks (OpenSSH matrix smoke + reconnect smoke + SLO gate):

```bash
./scripts/regression_gate.sh
```

## SLO gate

Run initial reconnect SLO checks (throughput, p95 latency, failure rate):

```bash
./scripts/bench_slo_gate.sh
```

Default SLO gate uses staggered worker start (`SLO_WORKER_START_SPREAD_MS=1500`) to model fan-out ramp while keeping load high.

## Dedicated 1000-session gate

Run the dedicated high-fanout gate:

```bash
./scripts/fanout_1000_gate.sh
```

This script wraps `bench_slo_gate.sh` with defaults for the 1000-session reconnect target.

## Soak test

Run a long-duration soak test (default 30 minutes):

```bash
./scripts/soak_test.sh
```

Tune duration and load:

```bash
SOAK_DURATION_SECS=3600 SOAK_CONCURRENCY=512 SOAK_RECONNECT=1 ./scripts/soak_test.sh
```

Run soak test against an already-running agent:

```bash
SOAK_SOCKET=\"$XDG_RUNTIME_DIR/secretive/agent.sock\" ./scripts/soak_test.sh
```
