# Rust Benchmarking

`secretive-bench` is a lightweight load generator for the Rust agent.

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

## High fan-out simulation

```bash
cargo run -p secretive-bench -- \
  --concurrency 1000 \
  --requests 10 \
  --warmup 5 \
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

## SLO gate

Run initial reconnect SLO checks (throughput, p95 latency, failure rate):

```bash
./scripts/bench_slo_gate.sh
```
