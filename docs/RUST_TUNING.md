# Rust Agent Tuning

Use these knobs to keep the Rust agent responsive under large fan-out workloads (for example `pssh` across thousands of hosts).

## High-concurrency checklist

- Increase `socket_backlog` to absorb bursts of new connections.
- Cap `max_connections` to avoid unbounded memory growth.
- Raise `max_signers` (and `max_blocking_threads`) if CPU is underutilized during signing.
- Set `worker_threads` to match the core count when async tasks are starved.
- Enable `inline_sign` only for fast local keys (file store) to cut spawn overhead.
- Raise `identity_cache_ms` to reduce list churn under heavy fan-out.
- Set `idle_timeout_ms` to close idle client connections faster.

## Sample configuration

```json
{
  "socket_backlog": 2048,
  "max_connections": 5000,
  "max_signers": 128,
  "max_blocking_threads": 128,
  "worker_threads": 16,
  "inline_sign": true,
  "identity_cache_ms": 5000,
  "idle_timeout_ms": 10000
}
```

Notes:
- Start with conservative values and raise limits while monitoring CPU, latency, and error rates.
- `inline_sign` should remain `false` when using PKCS#11 or Secure Enclave stores.
