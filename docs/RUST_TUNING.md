# Rust Agent Tuning

Use these knobs to keep the Rust agent responsive under large fan-out workloads (for example `pssh` across thousands of hosts).

## High-concurrency checklist

- Increase `socket_backlog` to absorb bursts of new connections.
- Cap `max_connections` to avoid unbounded memory growth.
- Raise `max_signers` (and `max_blocking_threads`) if CPU is underutilized during signing.
- Set `worker_threads` to match the core count when async tasks are starved.
- Leave `inline_sign` in auto mode by default (it enables itself when no PKCS#11 store is loaded).
- Raise `identity_cache_ms` to reduce list churn under heavy fan-out.
- Set `idle_timeout_ms` to close idle client connections faster.
- Set `sign_timeout_ms` to fail fast when the signing queue backs up.

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
  "idle_timeout_ms": 10000,
  "sign_timeout_ms": 250
}
```

Notes:
- Start with conservative values and raise limits while monitoring CPU, latency, and error rates.
- `inline_sign` auto mode disables itself when a PKCS#11 store is loaded.
