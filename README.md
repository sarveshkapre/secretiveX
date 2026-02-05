# Secretive [![Test](https://github.com/maxgoedjen/secretive/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/maxgoedjen/secretive/actions/workflows/test.yml) ![Release](https://github.com/maxgoedjen/secretive/workflows/Release/badge.svg)


Secretive is an app for protecting and managing SSH keys with the Secure Enclave.

## Rust Rewrite (WIP)

This repository now includes an in-progress Rust rewrite focused on cross-platform support and high-concurrency SSH agent performance. The new implementation lives in `crates/` and is being built in phases:
- `secretive-proto`: SSH agent protocol parsing/encoding
- `secretive-core`: key store abstractions and policy plumbing
- `secretive-agent`: cross-platform daemon skeleton (Unix socket / Windows named pipe)

The existing Swift app remains the reference implementation while the Rust version reaches feature parity.

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
- Concurrent sign requests are bounded by CPU-aware semaphore
- `max_signers` lets you override concurrency
- Send `SIGUSR1` on Unix to log a metrics snapshot
- `watch_files` controls automatic reloads
- `metrics_every` controls logging frequency
- `pid_file` writes the agent PID for monitoring
- Load-testing CLI (`secretive-bench`) for concurrency/throughput checks
- Debug CLI (`secretive-client`) for listing identities and signing test payloads

Rust config format: see `docs/RUST_CONFIG.md`.
Bench usage: see `docs/RUST_BENCH.md`.
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

You can download the latest release over on the [Releases Page](https://github.com/maxgoedjen/secretive/releases)

#### Using Homebrew

    brew install secretive

### FAQ

There's a [FAQ here](FAQ.md).

### Auditable Build Process

Builds are produced by GitHub Actions with an auditable build and release generation process. Starting with Secretive 3.0, builds are attested using [GitHub Artifact Attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations). Attestations are viewable in the build log for a build, and also on the [main attestation page](https://github.com/maxgoedjen/secretive/attestations).

### A Note Around Code Signing and Keychains

While Secretive uses the Secure Enclave to protect keys, it still relies on Keychain APIs to store and access them. Keychain restricts reads of keys to the app (and specifically, the bundle ID) that created them. If you build Secretive from source, make sure you are consistent in which bundle ID you use so that the Keychain is able to locate your keys.

### Backups and Transfers to New Machines

Because secrets in the Secure Enclave are not exportable, they are not able to be backed up, and you will not be able to transfer them to a new machine. If you get a new Mac, just create a new set of secrets specific to that Mac.

## Security

Secretive's security policy is detailed in [SECURITY.md](SECURITY.md). To report security issues, please use [GitHub's private reporting feature.](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability#privately-reporting-a-security-vulnerability)

## Acknowledgements

### sekey
Secretive was inspired by the [sekey project](https://github.com/sekey/sekey).

### Localization
Secretive is localized to many languages by a generous team of volunteers. To learn more, see [LOCALIZING.md](LOCALIZING.md). Secretive's localization workflow is generously provided by [Crowdin](https://crowdin.com).
