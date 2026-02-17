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

### Schema notes

`meta.schema_version` is an integer you should treat as the primary compatibility signal when ingesting `secretive-bench` JSON into dashboards or pipelines.

Versioning expectations:
- Additive changes (new fields) should be treated as backwards compatible; ingesters should ignore unknown fields.
- `schema_version` increments when existing field meanings or types change, or when fields are removed/renamed.
- Units are encoded in field names (for example `*_ms`, `*_us`, `*_ns`).

Top-level fields (schema v4):
- Counters: `ok`, `failures`, `attempted`, `request_failures`, `request_timeouts`, `connect_failures`, `worker_failures`
- Rates/timing: `success_rate`, `failure_rate`, `elapsed_ms`, `rps`
- Run shape: `mode` (`sign`/`list`), `reconnect`, `concurrency`, `requests_per_worker`, `requested_total` (optional), `duration_secs` (optional)
- Payload: `randomize_payload`, `payload_size`, `flags`, `response_timeout_ms` (optional), `connect_timeout_ms` (optional)
- Socket: `socket_path`
- Latency: `latency_enabled`, `latency_max_samples`, `latency` (optional object: `samples`, `p50_us`, `p95_us`, `p99_us`, `max_us`, `avg_us`)
- Metadata: `meta` object (`schema_version`, `bench_version`, `started_unix_ms`, `finished_unix_ms`, `pid`, `hostname`, `target_os`, `target_arch`)
- Queue wait: `queue_wait` (optional; see below)

Result counters:
- `ok`: number of successful responses (sign or list).
- `failures`: number of request-level failures (agent returned `Failure`, unexpected response types, timeouts, or connect/write failures).
- Breakdown fields (for debugging and clearer SLO math):
  - `request_failures`: agent-level `Failure` responses or unexpected response types.
  - `request_timeouts`: response timeouts when `--response-timeout-ms` is set.
  - `connect_failures`: per-request connect/write failures and hard EOF-style read failures.
  - `worker_failures`: worker task failures (should be `0` in healthy runs; indicates a bench-side bug or unrecoverable worker error).

## Queue-wait guardrails

Point `secretive-bench` at the agent's live metrics snapshot to capture queue-wait guardrail data alongside throughput/latency:

```bash
cargo run -p secretive-bench -- \
  --concurrency 512 \
  --duration 30 \
  --metrics-file /tmp/agent-metrics.json \
  --queue-wait-tail-profile pssh \
  --queue-wait-tail-ns 4000000 \
  --queue-wait-tail-max-ratio 0.03 \
  --json-compact
```

Flags and matching environment variables:

| Flag | Env var | Description |
| --- | --- | --- |
| `--metrics-file <path>` | `SECRETIVE_BENCH_METRICS` | Load the agent's JSON snapshot emitted via `metrics_output_path`. |
| `--queue-wait-tail-profile <pssh|fanout|balanced|low-memory>` | `SECRETIVE_BENCH_QUEUE_WAIT_PROFILE` | Auto-fill thresholds that match the agent profile guardrails (4/6/8/12 ms with ≤3%/4%/5%/7% tail). |
| `--queue-wait-tail-ns <ns>` | `SECRETIVE_BENCH_QUEUE_WAIT_TAIL_NS` | Manually set the queue-wait tail threshold in nanoseconds. |
| `--queue-wait-tail-max-ratio <ratio>` | `SECRETIVE_BENCH_QUEUE_WAIT_TAIL_MAX_RATIO` | Maximum fraction of requests allowed at or beyond the threshold. |

When those inputs are provided, the JSON payload gains a `queue_wait` block that records both the configured guardrail and the measured queue-wait percentiles/histogram tail so dashboards no longer need to scrape shell output. Example:

```json
{
  "queue_wait": {
    "tail_threshold_ns": 4000000,
    "tail_max_ratio": 0.03,
    "auto_profile": "pssh",
    "tail_mode": "percentile",
    "tail_percentile": {
      "label": "p95",
      "percentile": 0.95,
      "ns": 3100000,
      "derived_ratio": 0.05
    },
    "queue_wait_avg_ns": 820000.0,
    "percentiles": {
      "p50": {"ns": 210000, "open_ended": false},
      "p90": {"ns": 2400000, "open_ended": false},
      "p95": {"ns": 3100000, "open_ended": false},
      "p99": {"ns": 5500000, "open_ended": false}
    }
  }
}
```

This keeps the raw histogram/percentile story close to the throughput numbers, matching recent observability guidance that recommends pairing histogram buckets with P50/P95/P99 tail tracking when reviewing latency guardrails.¹

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

Duration runs default to `warmup=0` unless `--warmup` is explicitly provided, so the timed window is spent on measured requests.

## Response timeout

```bash
cargo run -p secretive-bench -- --concurrency 200 --duration 30 --response-timeout-ms 500
```

## Connect timeout

```bash
cargo run -p secretive-bench -- --concurrency 200 --duration 30 --connect-timeout-ms 1500
```

Use this for reconnect-heavy runs to fail fast when socket/pipe connect attempts stall.

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

## pssh preflight helper

Run a fast local readiness/key-health/queue-tail preflight before large fan-out jobs:

```bash
./scripts/pssh_preflight.sh
```

Optional knobs:
- `PSSH_PREFLIGHT_SOCKET` forces a socket path instead of env/default discovery.
- `PSSH_PREFLIGHT_METRICS_FILE` enables queue-wait guardrail validation from a metrics snapshot.
- `PSSH_PREFLIGHT_QUEUE_WAIT_PROFILE` picks the guardrail profile (`pssh` default).
- `PSSH_PREFLIGHT_QUEUE_WAIT_MAX_AGE_MS` rejects stale metrics snapshots.

Profile selection:
- `BENCH_PROFILE` controls the agent profile for smoke gate config (default: `fanout`).
- `BENCH_CONNECT_TIMEOUT_MS` sets `--connect-timeout-ms` for reconnect bench calls (default: `1500`).
- `AGENT_STARTUP_TIMEOUT_SECS` controls how long gate scripts wait for the agent to become ready (default: `90`).
- `AGENT_READY_POLL_MS` tunes readiness polling interval used by gate scripts (default: `200`).

## Regression gate

Run consolidated regression checks (OpenSSH matrix smoke + reconnect smoke + duration-mode reconnect smoke + SLO gate):

```bash
./scripts/regression_gate.sh
```

If CI or cold-start local runs are still compiling crates and hit readiness timeouts, raise:

```bash
AGENT_STARTUP_TIMEOUT_SECS=120 ./scripts/regression_gate.sh
```

Run the duration-mode reconnect smoke directly:

```bash
./scripts/duration_reconnect_smoke.sh
```

## SLO gate

Run initial reconnect SLO checks (throughput, p95 latency, failure rate):

```bash
./scripts/bench_slo_gate.sh
```

Default SLO gate uses staggered worker start (`SLO_WORKER_START_SPREAD_MS=1500`) to model fan-out ramp while keeping load high.
It also captures agent queue-wait metrics from `metrics_output_path`, reports `queue_wait_avg_ns` / `queue_wait_max_ns`, and now prefers agent-provided `queue_wait_percentiles` for tail enforcement before falling back to histogram buckets.
`SLO_PROFILE` controls the agent profile for gate config (default: `pssh`).
Optional thresholds:
- `SLO_MAX_QUEUE_WAIT_AVG_NS` (default `0`, disabled)
- `SLO_MAX_QUEUE_WAIT_MAX_NS` (default `0`, disabled)
- `SLO_QUEUE_WAIT_TAIL_NS` + `SLO_QUEUE_WAIT_TAIL_MAX_RATIO` (defaults `0`): fail if more than the allowed ratio of requests land in histogram buckets whose upper bound is >= the tail threshold. Example: `SLO_QUEUE_WAIT_TAIL_NS=5000000 SLO_QUEUE_WAIT_TAIL_MAX_RATIO=0.05` alerts when >5% of signs wait ≥5ms in the queue.
- CI jobs set conservative non-zero defaults for queue-wait sanity checks.
- Leaving both tail knobs unset now auto-selects a guardrail for the chosen profile (`pssh` uses 4ms <=3% tail, `fanout` 6ms <=4%, `balanced` 8ms <=5%, `low-memory` 12ms <=7%). Override the environment variables to customize these values.
- `SLO_WARMUP` (default `0`) controls pre-measurement warmup requests per worker for SLO gate runs.
- `SLO_CONNECT_TIMEOUT_MS` (default `1500`) sets fail-fast connect timeout per reconnect attempt.
- `SLO_QUEUE_WAIT_MAX_AGE_MS` (default `10000`) runs a freshness precheck against `metrics_output_path` and fails if snapshots are stale before tail enforcement.
- `AGENT_STARTUP_TIMEOUT_SECS` (default `90`) controls readiness wait for the temporary agent process before the bench run starts.

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
SOAK_SOCKET="$XDG_RUNTIME_DIR/secretive/agent.sock" ./scripts/soak_test.sh
```

Persist soak JSON result to a specific path:

```bash
SOAK_OUTPUT_JSON=/tmp/secretive-soak.json ./scripts/soak_test.sh
```

Persist agent metrics snapshot JSON from soak run:

```bash
SOAK_OUTPUT_METRICS=/tmp/secretive-soak-metrics.json ./scripts/soak_test.sh
```

Optional queue-wait thresholds for soak:
- `SOAK_MAX_QUEUE_WAIT_AVG_NS` (default `0`, disabled)
- `SOAK_MAX_QUEUE_WAIT_MAX_NS` (default `0`, disabled)
- `SOAK_REQUIRE_QUEUE_WAIT_METRICS` (default `0`): fail if queue-wait metrics are missing.
- `SOAK_MAX_P95_US` (default `0`, disabled): enforce p95 latency envelope.
- `SOAK_WORKER_START_SPREAD_MS` (default `2000`): stagger long-run start ramps.
- `SOAK_CONNECT_TIMEOUT_MS` (default `1500`): sets fail-fast connect timeout per reconnect attempt.

## PKCS#11 smoke

Run local PKCS#11 smoke test (uses SoftHSM when available):

```bash
./scripts/pkcs11_smoke.sh
```

Force failure when required tools are missing:

```bash
PKCS11_SMOKE_REQUIRE_TOOLS=1 ./scripts/pkcs11_smoke.sh
```

---

¹ See [OneUptime's 2025 guide on OpenTelemetry histograms](https://oneuptime.com/blog/post/2025-08-26-what-are-metrics-in-opentelemetry/view) for more context on why histograms plus percentiles are the recommended backbone for latency guardrails, especially when tracking queue-wait distributions.

## Multi-host stress gate

Run strict long-duration host-tier stress envelopes:

```bash
./scripts/multi_host_stress_gate.sh
```

Run one specific case:

```bash
STRESS_CASES=host1024 ./scripts/multi_host_stress_gate.sh
```

Artifacts are written under `target/multi-host-stress` by default.
