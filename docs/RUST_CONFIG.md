# Rust Agent Config

The Rust agent supports a JSON configuration file. You can point to it via `SECRETIVE_CONFIG` or `--config`.

Validate config and exits:
- `secretive-agent --check-config`
- `secretive-agent --check-config --config /path/to/agent.json`
- `secretive-agent --dump-effective-config` (prints merged config and exits)

`--check-config` warns when automatic metrics emission is disabled (`metrics_every=0` and `metrics_interval_ms` unset/0), especially if `metrics_output_path` is configured.

If no path is provided, the agent looks for:
- `$XDG_CONFIG_HOME/secretive/agent.json`
- `<config_dir>/secretive/agent.json` (from `directories::BaseDirs`)

Reset metrics counters without restarting (Unix only):
- `secretive-agent --reset-metrics --pid <pid>`
- `secretive-agent --reset-metrics --pid-file /path/to/agent.pid`

`--pid` targets a running agent PID directly. `--pid-file` reads the PID from a file created via the runtime `pid_file` option. Both forms send `SIGUSR2`, which zeros the sign metrics counters and queue-wait histogram before emitting a `reset` snapshot line.

Socket path overrides:
- `SECRETIVE_SOCK` (Unix) or `SECRETIVE_PIPE` (Windows) override the socket/pipe path when `socket_path` is unset.

## Top-level fields

- `profile` (string): optional preset (`balanced`, `fanout`, `pssh`, `low-memory`) applied to unset fields.
- `socket_path` (string): override the Unix socket path or Windows named pipe.
- `socket_backlog` (number): override the Unix socket listen backlog (0 or omitted uses system default).
- `stores` (array): ordered list of key stores to load.
- `policy` (object): optional allow/deny controls for sign requests.
- `max_signers` (number): optional cap for concurrent sign operations.
- `max_connections` (number): optional cap for concurrent client connections.
- `max_blocking_threads` (number): cap for Tokio's blocking thread pool (defaults to `max_signers`).
- `worker_threads` (number): override Tokio worker thread count (defaults to Tokio's auto-detected value).
- `watch_files` (bool): enable or disable file-store watching (default: true).
- `watch_debounce_ms` (number): debounce interval for file watcher reloads (default: 200).
- `metrics_every` (number): log metrics every N sign operations (default: 1000). Use `0` to disable.
- `metrics_interval_ms` (number): emit periodic metrics snapshots every N milliseconds (default: disabled). Use `0` to disable.
- `metrics_json` (bool): emit sign metrics as JSON lines in logs (default: false). Includes per-store counters (`store_sign_file`, `store_sign_pkcs11`, `store_sign_secure_enclave`, `store_sign_other`) and queue wait telemetry (`queue_wait_avg_ns`, `queue_wait_max_ns`, `queue_wait_histogram` buckets).
- `metrics_output_path` (string): write the latest metrics snapshot JSON to this path (atomically via temp+rename) for scrape/file collection.
- `audit_requests` (bool): emit privacy-safe structured audit logs for list/sign requests (default: false).
- `sign_timeout_ms` (number): fail sign requests if a permit isn't acquired in N milliseconds (default: disabled). Use `0` to disable.
- `pid_file` (string): write the agent PID to this file and remove on shutdown.
- `identity_cache_ms` (number): cache list-identities responses for N milliseconds (default: 1000). Use `0` to disable.
- `idle_timeout_ms` (number): close idle client connections after N milliseconds (default: disabled). Use `0` to disable.
- `inline_sign` (bool): perform signing on the async runtime thread. Default is auto: `true` when no PKCS#11 store is loaded, `false` when PKCS#11 is present.

Environment overrides (when config/CLI unset):
- `SECRETIVE_MAX_SIGNERS` sets `max_signers`.
- `SECRETIVE_PROFILE` sets `profile`.
- `SECRETIVE_MAX_CONNECTIONS` sets `max_connections`.
- `SECRETIVE_MAX_BLOCKING_THREADS` sets `max_blocking_threads`.
- `SECRETIVE_WORKER_THREADS` sets `worker_threads`.
- `SECRETIVE_METRICS_EVERY` sets `metrics_every`.
- `SECRETIVE_METRICS_INTERVAL_MS` sets `metrics_interval_ms`.
- `SECRETIVE_METRICS_JSON` sets `metrics_json` (`true`/`false`).
- `SECRETIVE_METRICS_OUTPUT` sets `metrics_output_path`.
- `SECRETIVE_AUDIT_REQUESTS` sets `audit_requests` (`true`/`false`).
- `SECRETIVE_SIGN_TIMEOUT_MS` sets `sign_timeout_ms`.
- `SECRETIVE_IDENTITY_CACHE_MS` sets `identity_cache_ms`.
- `SECRETIVE_WATCH_FILES` sets `watch_files` (`true`/`false`).
- `SECRETIVE_WATCH_DEBOUNCE_MS` sets `watch_debounce_ms`.
- `SECRETIVE_SOCKET_BACKLOG` sets `socket_backlog`.
- `SECRETIVE_IDLE_TIMEOUT_MS` sets `idle_timeout_ms`.
- `SECRETIVE_INLINE_SIGN` sets `inline_sign` (`true`/`false`).

Legacy fields (used only when `stores` is not provided):
- `key_paths` (array of strings): explicit private key paths.
- `scan_default_dir` (bool): whether to scan `~/.ssh` for private keys.

## Profile presets

Profiles only set fields that are still unset after CLI/config/env overrides.

- `balanced`: general-purpose defaults (`max_connections=1024`, `sign_timeout_ms=500`, `identity_cache_ms=1000`).
- `fanout`: aggressive concurrency (`max_connections=8192`, `socket_backlog=2048`, low sign timeout).
- `pssh`: very high fan-out defaults for thousands of short-lived sessions (`max_connections=32768`, `socket_backlog=4096`, `identity_cache_ms=10000`, `sign_timeout_ms=150`).
- `low-memory`: conservative resource use (`max_connections=256`, lower cache, higher sign timeout).

## Store definitions

### File store

```json
{
  "type": "file",
  "paths": ["/Users/me/.ssh/id_ed25519"],
  "scan_default_dir": true
}
```

### Secure Enclave store (macOS)

```json
{
  "type": "secure_enclave"
}
```

Note: `secure_enclave` is validated and supported only on macOS.
The Rust store discovers Secure Enclave-backed private keys from Keychain and exposes ECDSA identities/signing via the SSH agent protocol.

### PKCS#11 store (planned)

```json
{
  "type": "pkcs11",
  "module_path": "/usr/local/lib/your-pkcs11.so",
  "slot": 0,
  "pin_env": "PKCS11_PIN",
  "refresh_min_interval_ms": 250
}
```

Note: PKCS#11 support is behind the `pkcs11` feature in `secretive-core`.
`refresh_min_interval_ms` throttles non-forced key refresh scans to reduce contention (default: `250`; use `0` to disable throttling).
The runtime also applies session pooling and transient retry/backoff for common token/session churn errors.

## Policy controls

`policy` supports optional allow/deny lists:

- `allow_key_blobs` / `deny_key_blobs`: array of hex-encoded key blobs.
- `pin_fingerprints`: array of required fingerprints (acts as an allowlist by fingerprint).
- `allow_fingerprints` / `deny_fingerprints`: array of SSH fingerprints (for example `SHA256:...`).
- `allow_comments` / `deny_comments`: array of identity comments (case-insensitive exact match).

Deny rules are applied first. If any allow list is configured, a request must match at least one allow entry.

Example:

```json
{
  "policy": {
    "pin_fingerprints": ["SHA256:JQ6FV0rf7qqJHZqIj4zNH8eV0oB8KLKh9Pph3FTD98g"],
    "deny_comments": ["deprecated-key"]
  }
}
```
