# SecretiveX Product Goals and Feature Roadmap

## What We Are Building

SecretiveX is a cross-platform, high-throughput SSH agent platform designed for:
- Large fan-out automation workloads (for example, `pssh` across thousands of hosts).
- Strong key security with pluggable backends (file, PKCS#11, Secure Enclave).
- Predictable performance under bursty connection and signing load.

## Top Goals

1. Cross-platform parity: first-class Linux, macOS, and Windows agent behavior.
2. Fan-out performance: stable low-latency signing with very high concurrent sessions.
3. Security and policy: support hardware-backed keys and enforce signing controls.
4. Operational reliability: safe defaults, observability, and graceful failure behavior.
5. Product usability: simple install, clear config, and strong tooling for testing/tuning.

## Current State (Shipped)

- Rust crates in place: protocol, core stores, agent daemon, client CLI, bench CLI.
- High-concurrency controls: `max_signers`, `max_connections`, `socket_backlog`, thread tuning.
- Backpressure/fail-fast controls: `sign_timeout_ms`, `idle_timeout_ms`.
- Watch/reload controls: `watch_files`, `watch_debounce_ms`, `SIGHUP` reload.
- List caching and low-allocation protocol paths for fan-out scenarios.
- Bench tooling includes reconnect mode, list mode, response timeout, and latency percentiles.
- PKCS#11 key refresh is serialized to reduce refresh storms during concurrent load.
- PKCS#11 signing now resolves private key handles per session and retries once after refresh on churn.
- PKCS#11 refresh scans support interval throttling to limit churn during fan-out bursts.

## Gaps to Close for V1

- Secure Enclave backend is still a stub (no production implementation yet).
- PKCS#11 needs production hardening coverage and wider integration tests.
- Windows packaging is in place; pipe ACL hardening still needs real-host validation coverage.
- CI regression gate exists; stress coverage and flake resistance need expansion.

## Prioritized Feature List

## P0 (Critical)

- [ ] Implement macOS Secure Enclave store end-to-end (key discovery + sign + policy hooks).
- [x] Add Linux service packaging (`systemd` service/unit + install flow).
- [x] Add Windows service packaging and named-pipe ACL hardening.
- [x] Add protocol compatibility tests against OpenSSH client flows (list/sign/error paths).
- [x] Add CI benchmark smoke gate for reconnect fan-out workloads.
- [x] Define and enforce initial SLOs:
  - Reconnect fan-out with 1000 clients.
  - p95 sign latency and minimum throughput targets.
  - Failure-rate threshold under sustained load.

## P1 (High)

- [ ] Harden PKCS#11 behavior under contention and token/session churn.
- [x] Add per-store metrics (file vs PKCS#11 vs Secure Enclave) in agent logs/JSON.
- [x] Add optional structured metrics endpoint/output format for scraping.
- [x] Add config profile presets (`balanced`, `fanout`, `low-memory`) with documented defaults.
- [x] Add graceful startup validation (`--check-config`) with actionable errors.
- [x] Add end-to-end soak test script for multi-minute and multi-hour runs.

## P2 (Medium)

- [x] Add policy controls (allowlist by key/comment/fingerprint, optional deny rules).
- [x] Add request auditing mode with privacy-safe structured logs.
- [x] Add optional key pinning and per-request key selection constraints.
- [x] Add key source health diagnostics in `secretive-client`.
- [x] Improve benchmark export formats (CSV + richer JSON metadata for dashboards).

## Product Cleanup and Independence

- [x] Replace remaining upstream branding and links in `README.md`.
- [x] Define SecretiveX release/versioning policy and changelog format.
- [x] Add a project-specific architecture doc and long-term ownership model.

## Execution Rhythm

- Short term (next 1-2 weeks): complete P0 packaging and compatibility test foundations.
- Mid term (next 1-2 months): Secure Enclave implementation + CI performance gates.
- Long term: policy/audit features and operational quality-of-life improvements.
