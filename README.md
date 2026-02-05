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
- File-store auto reload via filesystem watchers (plus SIGHUP on Unix)
- Secure Enclave store stub (macOS implementation next)
- Config supports `secure_enclave` store type (stub)
- Agent exposes simple sign latency metrics in logs
- `sign_timeout_ms` caps how long sign requests wait for a worker
- Concurrent sign requests are bounded by CPU-aware semaphore
- `max_signers` lets you override concurrency
- `max_connections` caps concurrent client sessions
- `max_blocking_threads` and `worker_threads` tune Tokio thread pools
- `socket_backlog` tunes Unix socket listen backlog for large fan-out
- Send `SIGUSR1` on Unix to log a metrics snapshot
- `watch_files` controls automatic reloads
- `watch_debounce_ms` tunes reload debounce for file watchers
- `metrics_every` controls logging frequency
- `pid_file` writes the agent PID for monitoring
- `identity_cache_ms` caches identity lists for fast fan-out
- `idle_timeout_ms` closes idle connections to free resources
- `inline_sign` keeps signing on async threads for lower latency on local keys
- `--check-config` validates config and exits before starting the daemon
- Unix default socket path prefers `XDG_RUNTIME_DIR`
- Load-testing CLI (`secretive-bench`) for concurrency/throughput checks
- Bench supports reconnect and list-only modes for pssh-like fan-out
- Debug CLI (`secretive-client`) for listing identities and signing test payloads
- Client `--raw` list mode skips key parsing for faster output
- Client `--json-compact` for compact JSON output

Rust config format: see `docs/RUST_CONFIG.md`.
Bench usage: see `docs/RUST_BENCH.md`.
Tuning guidance: see `docs/RUST_TUNING.md`.
Product roadmap: see `docs/PRODUCT_FEATURES.md`.
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
