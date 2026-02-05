# Rust Agent Config

The Rust agent supports a JSON configuration file. You can point to it via `SECRETIVE_CONFIG` or `--config`.

If no path is provided, the agent looks for:
- `$XDG_CONFIG_HOME/secretive/agent.json`
- `<config_dir>/secretive/agent.json` (from `directories::BaseDirs`)

Socket path overrides:
- `SECRETIVE_SOCK` (Unix) or `SECRETIVE_PIPE` (Windows) override the socket/pipe path when `socket_path` is unset.

## Top-level fields

- `socket_path` (string): override the Unix socket path or Windows named pipe.
- `socket_backlog` (number): override the Unix socket listen backlog (0 or omitted uses system default).
- `stores` (array): ordered list of key stores to load.
- `max_signers` (number): optional cap for concurrent sign operations.
- `max_blocking_threads` (number): cap for Tokio's blocking thread pool (defaults to `max_signers`).
- `worker_threads` (number): override Tokio worker thread count (defaults to Tokio's auto-detected value).
- `watch_files` (bool): enable or disable file-store watching (default: true).
- `metrics_every` (number): log metrics every N sign operations (default: 1000). Use `0` to disable.
- `pid_file` (string): write the agent PID to this file and remove on shutdown.
- `identity_cache_ms` (number): cache list-identities responses for N milliseconds (default: 1000). Use `0` to disable.

Environment overrides (when config/CLI unset):
- `SECRETIVE_MAX_SIGNERS` sets `max_signers`.
- `SECRETIVE_MAX_BLOCKING_THREADS` sets `max_blocking_threads`.
- `SECRETIVE_WORKER_THREADS` sets `worker_threads`.
- `SECRETIVE_METRICS_EVERY` sets `metrics_every`.
- `SECRETIVE_IDENTITY_CACHE_MS` sets `identity_cache_ms`.
- `SECRETIVE_WATCH_FILES` sets `watch_files` (`true`/`false`).
- `SECRETIVE_SOCKET_BACKLOG` sets `socket_backlog`.

Legacy fields (used only when `stores` is not provided):
- `key_paths` (array of strings): explicit private key paths.
- `scan_default_dir` (bool): whether to scan `~/.ssh` for private keys.

## Store definitions

### File store

```json
{
  "type": "file",
  "paths": ["/Users/me/.ssh/id_ed25519"],
  "scan_default_dir": true
}
```

### Secure Enclave store (macOS, planned)

```json
{
  "type": "secure_enclave"
}
```

### PKCS#11 store (planned)

```json
{
  "type": "pkcs11",
  "module_path": "/usr/local/lib/your-pkcs11.so",
  "slot": 0,
  "pin_env": "PKCS11_PIN"
}
```

Note: PKCS#11 support is behind the `pkcs11` feature in `secretive-core`.
