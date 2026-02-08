# SecretiveX


SecretiveX is an app and toolkit for protecting and managing SSH keys with secure backends.

## Rust Rewrite (WIP)

This repository now includes an in-progress Rust rewrite focused on cross-platform support and high-concurrency SSH agent performance. The new implementation lives in `crates/` and is being built in phases:
- `secretive-proto`: SSH agent protocol parsing/encoding
- `secretive-core`: key store abstractions and policy plumbing
- `secretive-agent`: cross-platform daemon skeleton (Unix socket / Windows named pipe)

The legacy Swift app in this repository remains a reference while the Rust version reaches feature parity.

Current Rust milestones:
- File-based SSH key discovery (`~/.ssh`) with RSA/Ed25519/ECDSA signing
- High-concurrency agent skeleton with async I/O and blocking-sign offload
- Reusable protocol buffers to reduce per-request allocations
- Hot-reload keys on `SIGHUP` (Unix)
- CLI flags for config, socket path, and key overrides
- Config-driven store list (file now; pkcs11 placeholder)
- PKCS#11 store (enable via `secretive-core` feature `pkcs11`)
- PKCS#11 key refresh is serialized to reduce contention under concurrent load
- PKCS#11 signing resolves private key handles per session with one-shot refresh retry
- PKCS#11 supports `refresh_min_interval_ms` to throttle refresh scans under fan-out
- File-store auto reload via filesystem watchers (plus SIGHUP on Unix)
- Secure Enclave store implementation on macOS (key discovery + signing)
- Config supports `secure_enclave` store type (macOS)
- Agent exposes simple sign latency metrics in logs
- `sign_timeout_ms` caps how long sign requests wait for a worker
- Concurrent sign requests are bounded by CPU-aware semaphore
- `max_signers` lets you override concurrency
- `max_connections` caps concurrent client sessions
- `max_blocking_threads` and `worker_threads` tune Tokio thread pools
- `profile` presets (`balanced`, `fanout`, `pssh`, `low-memory`) set sensible defaults
- `socket_backlog` tunes Unix socket listen backlog for large fan-out
- Send `SIGUSR1` on Unix to log a metrics snapshot
- `watch_files` controls automatic reloads
- `watch_debounce_ms` tunes reload debounce for file watchers
- `metrics_every` controls logging frequency
- `metrics_interval_ms` emits periodic metrics snapshots on wall clock interval
- `metrics_json` emits machine-readable JSON metrics lines
- `metrics_output_path` writes latest metrics JSON snapshot atomically for scrapers
- metrics include per-store sign counters (`file`, `pkcs11`, `secure_enclave`, `other`)
- metrics include queue wait telemetry (`queue_wait_avg_ns`, `queue_wait_max_ns`)
- `audit_requests` emits privacy-safe structured request audit logs
- `policy` rules can allow/deny sign requests by key blob, fingerprint, or comment
- `pid_file` writes the agent PID for monitoring
- `identity_cache_ms` caches identity lists for fast fan-out
- `idle_timeout_ms` closes idle connections to free resources
- `inline_sign` auto mode enables async-thread signing when no PKCS#11 store is loaded
- `pssh` profile sets high-fanout defaults tuned for thousands of short-lived sessions
- `--check-config` validates config and exits before starting the daemon
- `--dump-effective-config` prints merged runtime config (profile/env/CLI resolved)
- Linux `systemd --user` service template and install/uninstall scripts
- Windows service install/uninstall scripts for `secretive-agent`
- Unix default socket path prefers `XDG_RUNTIME_DIR`
- Load-testing CLI (`secretive-bench`) for concurrency/throughput checks
- Bench supports reconnect and list-only modes for pssh-like fan-out
- Bench supports worker start spreading (`--worker-start-spread-ms`) for burst modeling
- Bench supports CSV export and enriched JSON metadata for dashboards
- CI includes reconnect fan-out benchmark smoke gating
- CI includes OpenSSH compatibility matrix checks (ed25519/rsa/ecdsa on Linux/macOS)
- CI includes a consolidated Rust regression gate (compat + smoke + SLO checks)
- CI validates `secretive-core` builds with `pkcs11` feature on Linux and macOS
- CI validates `secretive-agent` builds with `pkcs11` feature on Linux and macOS
- CI includes a dedicated scheduled 1000-session fan-out gate
- CI gate jobs use retry wrapping to reduce transient flake failures
- CI includes a scheduled Rust soak gate with uploaded benchmark artifacts
- CI includes shell script syntax sanity checks (`scripts/*.sh`)
- SLO/soak gates report agent queue-wait metrics (`queue_wait_avg_ns`, `queue_wait_max_ns`)
- SLO/fanout/soak CI gates enforce conservative queue-wait threshold checks
- CI includes SoftHSM-backed PKCS#11 list/sign smoke coverage on Linux
- CI includes Windows named-pipe list/sign smoke coverage
- Initial SLO gate script and scheduled CI job for reconnect workloads
- End-to-end soak test script for multi-minute/hour reliability runs
- Debug CLI (`secretive-client`) for listing identities and signing test payloads
- Client `--health` diagnostics for invalid keys, duplicates, and algorithm mix
- Client `--metrics-file` inspects structured metrics snapshots without agent socket access
- Client `--pssh-hints` prints recommended OpenSSH/pssh options for high fan-out runs
- Client `--raw` list mode skips key parsing for faster output
- Client `--json-compact` for compact JSON output

Rust config format: see `docs/RUST_CONFIG.md`.
Bench usage: see `docs/RUST_BENCH.md`.
Client usage: see `docs/RUST_CLIENT.md`.
Tuning guidance: see `docs/RUST_TUNING.md`.
Linux service setup: see `docs/LINUX_SYSTEMD.md`.
Windows service setup: see `docs/WINDOWS_SERVICE.md`.
OpenSSH compatibility smoke: see `docs/OPENSSH_COMPAT.md`.
SLO definitions and gate: see `docs/SLO.md`.
Product roadmap: see `docs/PRODUCT_FEATURES.md`.
Release policy: see `docs/RELEASE_POLICY.md`.
Architecture and ownership: see `docs/ARCHITECTURE.md`.
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="/.github/readme/app-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="/.github/readme/app-light.png">
  <img src="/.github/readme/app-dark.png" alt="Screenshot of Secretive" width="600">
</picture>


## Why?

### Safer Storage

The most common setup for SSH keys is just keeping them on disk, guarded by proper permissions. This is fine in most cases, but it's not super hard for malicious users or malware to copy your private key. If you protect your keys with the Secure Enclave, it's impossible to export them, by design.

### Access Control

If your Mac has a Secure Enclave, it also has support for strong access controls like Touch ID, or authentication with Apple Watch. You can configure your keys so that they require Touch ID (or Watch) authentication before they're accessed.

<img src="/.github/readme/touchid.png" alt="Screenshot of Secretive authenticating with Touch ID" width="400">

### Notifications

Secretive also notifies you whenever your keys are accessed, so you're never caught off guard.

<img src="/.github/readme/notification.png" alt="Screenshot of Secretive notifying the user" width="600">

### Support for Smart Cards Too!

For Macs without Secure Enclaves, you can configure a Smart Card (such as a YubiKey) and use it for signing as well.

## Getting Started

### Installation

#### Direct Download

You can download the latest release on the [SecretiveX Releases Page](https://github.com/sarveshkapre/secretiveX/releases).

#### Using Homebrew

    Homebrew formula for SecretiveX is not published yet.

### FAQ

There's a [FAQ here](FAQ.md).

### Auditable Build Process

Builds are produced by GitHub Actions with an auditable build and release generation process. Builds can be attested using [GitHub Artifact Attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations). Attestations are viewable in workflow logs and on the [SecretiveX attestation page](https://github.com/sarveshkapre/secretiveX/attestations).

### A Note Around Code Signing and Keychains

While SecretiveX uses the Secure Enclave to protect keys, it still relies on Keychain APIs to store and access them. Keychain restricts reads of keys to the app (and specifically, the bundle ID) that created them. If you build SecretiveX from source, make sure you are consistent in which bundle ID you use so that the Keychain is able to locate your keys.

### Backups and Transfers to New Machines

Because secrets in the Secure Enclave are not exportable, they are not able to be backed up, and you will not be able to transfer them to a new machine. If you get a new Mac, just create a new set of secrets specific to that Mac.

## Security

SecretiveX's security policy is detailed in [SECURITY.md](SECURITY.md). To report security issues, please use [GitHub's private reporting feature.](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability#privately-reporting-a-security-vulnerability)

## Acknowledgements

### sekey
Secretive was inspired by the [sekey project](https://github.com/sekey/sekey).

### Localization
Secretive is localized to many languages by a generous team of volunteers. To learn more, see [LOCALIZING.md](LOCALIZING.md). Secretive's localization workflow is generously provided by [Crowdin](https://crowdin.com).
