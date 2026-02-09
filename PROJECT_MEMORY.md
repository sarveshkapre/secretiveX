# Project Memory

## Objective
- Keep secretiveX production-ready. Current focus: SecretiveX. Find the highest-impact pending work, implement it, test it, and push to main.

## Architecture Snapshot

## Market Scan (Bounded)
- 2026-02-09 (untrusted): Baseline expectations for “secure SSH agent” tools include: drop-in `SSH_AUTH_SOCK` integration, cross-platform support, clear key provenance (file vs hardware-backed), and predictable UX around approvals/timeouts.
  - 1Password SSH agent: SSH key management + agent integration with `SSH_AUTH_SOCK`. Source: https://developer.1password.com/docs/ssh/agent/
  - GnuPG `gpg-agent`: supports SSH-agent mode via `enable-ssh-support`. Source: https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html
  - `age` (and Nix `agenix`): file-based encryption workflows commonly used alongside SSH keys for secrets distribution (adjacent, not an agent). Sources: https://github.com/FiloSottile/age , https://github.com/ryantm/agenix
- 2026-02-09 (untrusted): Hardware-backed SSH key workflows often rely on PKCS#11 plumbing and agent drop-in configuration.
  - Yubico PIV: OpenSSH + PKCS#11 usage and `SSH_AUTH_SOCK`-style flows. Source: https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html

## Open Problems
## Gap Map
- Missing: polished “approval UX” parity with password-manager agents (prompts/allowlists/UX), plus broader real-token integration testing for PKCS#11 and Windows ACL hardening validation on real hosts.
- Weak: CI gate ergonomics (machine-parseable outputs, clear failure diagnostics, flake resistance) and semantics alignment between bench JSON fields and gate scripts.
- Parity: drop-in SSH agent behavior (Unix socket/named pipe), basic key discovery/signing, and straightforward docs for setup.
- Differentiator: high-concurrency focus with queue-wait metrics + SLO gating, and macOS Secure Enclave-backed store support.

## Cycle 3 Session 2026-02-09 Task Scoring
- Selected (shipped this session):
  - Fix macOS Nightly/One-Off CI signing/notarization robustness + local zip (impact 5, effort 2, fit 5, diff 2, risk 2, confidence high)
  - Fix updater to query SecretiveX releases + add repo URL sanity smoke check (impact 4, effort 1, fit 5, diff 2, risk 1, confidence high)
  - Resolve `TODO: CHECK VERSION` by detecting stale SecretAgent processes after in-place updates (impact 3, effort 2, fit 4, diff 1, risk 2, confidence medium)
- Not selected (backlog):
  - Count non-success SSH agent responses in `secretive-bench` as failures (impact 4, effort 2, fit 5, diff 3, risk 2, confidence medium)
  - Add JSON/quiet output modes to `secretive-agent --suggest-queue-wait` + wire gates to consume it (impact 4, effort 3, fit 5, diff 3, risk 2, confidence medium)
  - Prebuild Rust binaries in gate scripts to reduce flake and JSON noise (impact 3, effort 3, fit 4, diff 2, risk 2, confidence medium)

## Cycle 4 Session 2026-02-09 Task Scoring
- Selected (shipped this session):
  - Count request-level failures in `secretive-bench` output + expose breakdown fields (impact 5, effort 2, fit 5, diff 3, risk 2, confidence high)
  - Add `secretive-agent --suggest-queue-wait-json/--suggest-queue-wait-quiet` outputs + docs (impact 4, effort 2, fit 5, diff 3, risk 1, confidence high)
  - Prebuild Rust tools in gate scripts + prefer prebuilt `secretive-client` for readiness (impact 4, effort 2, fit 5, diff 2, risk 2, confidence high)
  - Wire `bench_slo_gate.sh` to consume host-aware guardrails via `--suggest-queue-wait-quiet` (impact 4, effort 1, fit 5, diff 2, risk 1, confidence high)
- Not selected (backlog):
  - Emit suggested queue-wait guardrails in metrics snapshots for dashboards (impact 3, effort 2, fit 4, diff 2, risk 2, confidence medium)
  - Rust fmt/clippy CI (impact 3, effort 2, fit 4, diff 1, risk 1, confidence medium)

## Recent Decisions
- Template: YYYY-MM-DD | Decision | Why | Evidence (tests/logs) | Commit | Confidence (high/medium/low) | Trust (trusted/untrusted)
 - 2026-02-09 | Disable `sign_timeout_ms` in synthetic gate-generated agent configs (`bench_*`/`soak_test`) | The `pssh` profile’s default `sign_timeout_ms` can turn high fan-out reconnect benchmarks into “0 ok requests” runs on slower/contended hosts, which then produces missing latency stats and misleading gate failures. Gates should measure queue wait/latency directly instead of failing early on internal timeouts. | Local: `SLO_CONCURRENCY=64 SLO_DURATION_SECS=3 ... ./scripts/bench_slo_gate.sh` (pass). CI signal (untrusted): Rust SLO Gate run `21812678088` failed with “failed to parse bench output” after `ok=0` produced no `p95_us`. | f877d58 | high | trusted
 - 2026-02-09 | Keep `secretive-bench` JSON stdout clean by routing logs to stderr | Gate scripts and tooling depend on `--json-compact` being machine-parseable; logs on stdout make parsing brittle and hide the real failure mode. | Local: captured `secretive-bench --json-compact` stdout to a file while forcing worker errors; file contained only JSON and no `secretive_bench` log lines. | f877d58 | high | trusted
 - 2026-02-09 | Make macOS workflows resilient when signing secrets are absent, and generate `Secretive.zip` locally | Scheduled Nightly runs should stay green even when signing/notarization secrets aren’t configured; local zip removes a brittle “upload then curl-download” dependency and ensures the notarization artifact is exactly what was built. | Local: `ruby -e "require 'yaml'; YAML.load_file(...)"` (pass); `./scripts/check_shell.sh` (pass). CI signal (untrusted): Nightly run `21817537420` failed with missing profiles/certs before this change. | b65be6a, 33332a9 | high | trusted
 - 2026-02-09 | Fix updater to query SecretiveX releases and add a cheap repo URL regression gate | Release checks should not silently query upstream repositories; a tiny `rg`-backed script in CI catches drift quickly and cheaply. | Local: `./scripts/repo_sanity.sh` (pass); Shell Sanity workflow (push) includes it. | 84227cc | high | trusted
 - 2026-02-09 | Detect stale SecretAgent processes after in-place updates via launch time vs binary mtime | If the host app updates in-place, the login item can keep running an older binary; treating it as stale forces a restart path and avoids host/agent protocol drift. | Local: build passes `xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme PackageTests test` (pass). | da60605 | medium | trusted
 - 2026-02-09 | Upgrade CodeQL action to v4 | CodeQL v3 intermittently failed with `Bad credentials` during feature enablement checks; v4 is the current supported line and avoids the upcoming v3 deprecation window. | Local: `ruby -e "require 'yaml'; YAML.load_file('.github/workflows/codeql.yml')"` (pass). CI signal (untrusted): CodeQL run `21831499249` failed with `HttpError: Bad credentials`. | f0638e3 | medium | trusted
 - 2026-02-09 | Make `secretive-bench` failures request-based (and expose breakdown) | Worker-level failure counting hid agent-side `Failure` responses and could produce misleading `ok=0 failures=0`-style summaries; SLO math needs per-request attempts/failures. | Local: `cargo test -p secretive-bench` (pass). Local smoke: `./scripts/bench_smoke_gate.sh` (pass). | 46790ae | high | trusted
 - 2026-02-09 | Add machine-readable guardrail suggestions (`--suggest-queue-wait-json`/`--suggest-queue-wait-quiet`) | Gate scripts and CI should consume recommendations without parsing human prose; quiet output enables stable key/value ingestion. | Local: `cargo test -p secretive-agent` (pass). | 3b62a9f | high | trusted
 - 2026-02-09 | Prebuild Rust tools in gates + use suggestion helper in `bench_slo_gate.sh` | Running prebuilt binaries avoids Cargo noise interleaved with agent logs and reduces cold-start flake; consuming `--suggest-queue-wait-quiet` aligns tail envelopes to host hardware without bespoke parsing. | Local: `./scripts/check_shell.sh` (pass), `./scripts/bench_slo_gate.sh` (pass). | 657254c, 9ad7387 | high | trusted

## Mistakes And Fixes
- Template: YYYY-MM-DD | Issue | Root cause | Fix | Prevention rule | Commit | Confidence

## Known Risks

## Next Prioritized Tasks
 - Emit suggested queue-wait guardrails (tail_ns/ratio + profile) in agent metrics snapshots so dashboards can compare observed vs recommended envelopes without consulting CI logs.
 - Add Rust fmt/clippy CI on `push`/`pull_request` (`cargo fmt --check`, optional `cargo clippy`) for earlier signal on style/lint drift.
 - Prefer bench-provided `queue_wait` JSON in gate scripts (avoid parsing metrics snapshots with embedded python; keep verdict logic in one place).

## Verification Evidence
- Template: YYYY-MM-DD | Command | Key output | Status (pass/fail)
 - 2026-02-09 | `cargo test -p secretive-bench` | `8 passed` | pass
 - 2026-02-09 | `./scripts/check_shell.sh` | `checked 14 script(s)` | pass
 - 2026-02-09 | `./scripts/repo_sanity.sh` | `[repo-sanity] ok` | pass
 - 2026-02-09 | `xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme PackageTests test` | `TEST SUCCEEDED` | pass
 - 2026-02-09 | `xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme Secretive -configuration Debug build CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= DEVELOPMENT_TEAM= PROVISIONING_PROFILE_SPECIFIER=` | `BUILD SUCCEEDED` | pass
 - 2026-02-09 | `AGENT_STARTUP_TIMEOUT_SECS=90 ./scripts/bench_smoke_gate.sh` | `bench smoke gate passed` | pass
 - 2026-02-09 | `SLO_CONCURRENCY=64 SLO_DURATION_SECS=3 SLO_MIN_RPS=1 SLO_MAX_P95_US=10000000 SLO_MAX_FAILURE_RATE=1 AGENT_STARTUP_TIMEOUT_SECS=90 ./scripts/bench_slo_gate.sh` | `slo gate passed` | pass
 - 2026-02-09 | `cargo fmt` | `ok` | pass
 - 2026-02-09 | `cargo test -p secretive-bench` | `8 passed` | pass
 - 2026-02-09 | `cargo test -p secretive-agent` | `28 passed` | pass
 - 2026-02-09 | `./scripts/check_shell.sh` | `checked 14 script(s)` | pass
 - 2026-02-09 | `AGENT_STARTUP_TIMEOUT_SECS=90 BENCH_CONCURRENCY=32 BENCH_REQUESTS=4 MIN_RPS=1 ./scripts/bench_smoke_gate.sh` | `bench smoke gate passed` | pass
 - 2026-02-09 | `AGENT_STARTUP_TIMEOUT_SECS=90 SLO_CONCURRENCY=32 SLO_DURATION_SECS=2 SLO_MIN_RPS=1 SLO_MAX_P95_US=10000000 SLO_MAX_FAILURE_RATE=1 ./scripts/bench_slo_gate.sh` | `slo gate passed` | pass
 - 2026-02-09 | `./scripts/repo_sanity.sh` | `[repo-sanity] ok` | pass

## Historical Summary
- Keep compact summaries of older entries here when file compaction runs.
