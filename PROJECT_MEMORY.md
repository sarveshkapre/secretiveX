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
- 2026-02-10 (untrusted): “Approval/confirm” UX is a baseline expectation for hardened SSH agent setups.
  - OpenSSH `ssh-add -c` adds keys with a per-use confirmation constraint. Source: https://man.openbsd.org/ssh-add
  - OpenSSH `ssh-agent` supports lifetimes and locking patterns that map to “timeout/approval” expectations. Source: https://man.openbsd.org/ssh-agent
  - 1Password SSH agent supports `SSH_AUTH_SOCK`-compatible flows and is a common modern reference point for key UX. Source: https://developer.1password.com/docs/ssh/agent/
- 2026-02-10 (untrusted): A pragmatic cross-platform “confirm” baseline is an external prompt/approval helper: agent calls out to a helper and gates signing on its exit code.
  - GnuPG `gpg-agent` options around confirmations/constraints are a common reference point for SSH-agent confirmation workflows. Source: https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html
  - OpenSSH confirms via `ssh-add -c` constraints (agent-side confirmation behavior). Source: https://man.openbsd.org/ssh-add

## Open Problems
## Gap Map
- Missing: polished “approval UX” parity with password-manager agents (prompts/allowlists/UX), plus broader real-token integration testing for PKCS#11 and Windows ACL hardening validation on real hosts.
- Weak: CI gate ergonomics (machine-parseable outputs, clear failure diagnostics, flake resistance) and semantics alignment between bench JSON fields and gate scripts.
- Parity: drop-in SSH agent behavior (Unix socket/named pipe), basic key discovery/signing, and straightforward docs for setup.
- Differentiator: high-concurrency focus with queue-wait metrics + SLO gating, and macOS Secure Enclave-backed store support.

## Cycle 1 Session 2026-02-10 Task Scoring
- Selected (shipped this session):
  - Add `policy.confirm_command` (timeout + optional cache) + docs + smoke script (impact 5, effort 3, fit 5, diff 4, risk 3, confidence medium-high)
  - Fix framed request reads (remove unsafe + enforce exact-length reads) + add regression test after CI failure (impact 5, effort 2, fit 5, diff 2, risk 2, confidence high)
  - Add head-only Homebrew formula + README install docs for Rust CLIs (impact 4, effort 2, fit 5, diff 2, risk 1, confidence high)
  - Document `secretive-bench` JSON schema notes/versioning (schema v3) (impact 3, effort 1, fit 4, diff 2, risk 1, confidence high)
- Not selected (backlog):
  - Add OS-specific prompt helper examples for `confirm_command` (impact 3, effort 2, fit 4, diff 2, risk 2, confidence medium)
  - Add confirm/deny telemetry to metrics snapshots (impact 3, effort 2, fit 4, diff 2, risk 1, confidence medium)
  - Cut a tagged Rust CLI release + stable Homebrew `url`/`sha256` (impact 4, effort 3, fit 4, diff 2, risk 2, confidence medium)

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
 - 2026-02-10 | Consume bench-emitted queue-wait JSON in gate scripts (remove embedded python + stop scraping agent snapshots directly) | Avoiding ad-hoc snapshot parsing removes a runtime Python dependency, reduces drift between “what the gate enforces” and “what the bench reports”, and keeps verdict inputs in one place. | Local: `./scripts/check_shell.sh` (pass); `SLO_CONCURRENCY=32 SLO_DURATION_SECS=1 ... ./scripts/bench_slo_gate.sh` (pass); `SOAK_DURATION_SECS=1 ... ./scripts/soak_test.sh` (pass). | ac0a4a2 | high | trusted
 - 2026-02-10 | Remove uninitialized `Vec::set_len` buffer patterns in protocol/client parsing | Clippy correctly flags this as a footgun; eliminating unsafe uninitialized buffers reduces the risk of exposing stale memory and makes `cargo clippy` CI viable. | Local: `cargo test -p secretive-proto` (pass); `cargo test -p secretive-client` (pass); `cargo clippy --workspace --all-targets` (pass). | ac28203 | high | trusted
 - 2026-02-10 | Add Rust lint workflow (`cargo fmt --check` + `cargo clippy`) on push/PR | Formatting and clippy provide early signal and prevent unsafe regressions from landing silently. | Local: `cargo fmt --all -- --check` (pass); `cargo clippy --workspace --all-targets` (pass). | c05077c | high | trusted
 - 2026-02-10 | Emit `queue_wait_suggested` in agent metrics snapshots | Dashboards and ops reviews can compare observed queue-wait tails vs the recommended envelope without consulting CI logs or re-running `--suggest-queue-wait`. | Local: `cargo test -p secretive-agent` (pass). | 857a39f | medium | trusted
 - 2026-02-10 | Add `policy.confirm_command` (timeout + optional cache) as a minimal cross-platform approval hook | `ssh-add -c`-style confirmation is a baseline expectation; an external command hook enables CLI-only workflows now and leaves room for future GUI adapters without coupling the agent to UI frameworks. | Local: `cargo test -p secretive-agent` (pass). Smoke: temp key + agent `confirm_command=[/usr/bin/false]` makes `secretive-client --sign` fail; swapping to `/usr/bin/true` makes sign succeed (pass). | 7820b4c | high | trusted
 - 2026-02-10 | Add a head-only Homebrew formula for Rust CLIs | Provides a first-class install path for Rust tools before we cut a tagged release; stable `url`/`sha256` can land once we ship tags. | Local: `ruby -c packaging/homebrew/secretivex.rb` (pass). | 0fa78bb | medium | trusted
 - 2026-02-10 | For framed agent protocol reads, always read exactly the declared frame length | Buffered reads that can overrun frame boundaries desynchronize the stream under fan-out and surface as connect/write failures; correctness beats micro-optimizations here. | Local: `BENCH_CONCURRENCY=64 BENCH_REQUESTS=4 MIN_RPS=1 ./scripts/bench_smoke_gate.sh` (pass); unit test `read_request_does_not_consume_next_frame` (pass). | 32e1511, 67ed34c | high | trusted
 - 2026-02-10 | Add OS-specific `policy.confirm_command` prompt helper examples | Confirm UX is a baseline expectation; shipping minimal macOS/Linux/Windows helper scripts helps users adopt confirmations without writing their own prompt plumbing. | Local: `./scripts/check_shell.sh` (pass); `cargo test -p secretive-agent` (pass). | 2eb8f47 | medium | trusted

## Mistakes And Fixes
- Template: YYYY-MM-DD | Issue | Root cause | Fix | Prevention rule | Commit | Confidence
 - 2026-02-10 | CI `Rust Bench Smoke` failed with reconnect `connect_failures` | Agent framed read path used buffered reads that could overrun the declared frame length and consume bytes from the next request, desynchronizing the protocol stream under fan-out. | Read exactly `len` bytes (`resize` + `read_exact`) and add a regression test that writes two frames back-to-back and asserts both parse. | Never use buffered reads for framed protocols without bounding reads to remaining length; add multi-frame read tests to catch over-read regressions. | 32e1511, 67ed34c | high

## Known Risks

## Next Prioritized Tasks
 - Add confirm/deny telemetry (counters + audit outcomes) to metrics snapshots so dashboards can see prompt rates and denial reasons.
 - Cut a tagged Rust CLI release and extend the Homebrew formula with a stable `url` + `sha256` (keep `head` for dev installs).

## Verification Evidence
- Template: YYYY-MM-DD | Command | Key output | Status (pass/fail)
 - 2026-02-09 | `cargo test -p secretive-bench` | `8 passed` | pass
 - 2026-02-09 | `./scripts/check_shell.sh` | `checked 14 script(s)` | pass
 - 2026-02-09 | `./scripts/repo_sanity.sh` | `[repo-sanity] ok` | pass
 - 2026-02-10 | `./scripts/check_shell.sh` | `checked 14 script(s)` | pass
 - 2026-02-10 | `AGENT_STARTUP_TIMEOUT_SECS=90 SLO_CONCURRENCY=32 SLO_DURATION_SECS=1 SLO_MIN_RPS=1 SLO_MAX_P95_US=10000000 SLO_MAX_FAILURE_RATE=1 ./scripts/bench_slo_gate.sh` | `slo gate passed` | pass
 - 2026-02-10 | `AGENT_STARTUP_TIMEOUT_SECS=90 SOAK_DURATION_SECS=1 SOAK_CONCURRENCY=16 SOAK_MIN_RPS=0 SOAK_MAX_FAILURE_RATE=1 ./scripts/soak_test.sh` | `soak passed` | pass
 - 2026-02-10 | `cargo fmt --all -- --check` | `ok` | pass
 - 2026-02-10 | `cargo clippy --workspace --all-targets` | `Finished dev profile` | pass
 - 2026-02-10 | `cargo test -p secretive-proto` | `12 passed` | pass
 - 2026-02-10 | `cargo test -p secretive-client` | `13 passed` | pass
 - 2026-02-10 | `cargo test -p secretive-bench` | `8 passed` | pass
 - 2026-02-10 | `cargo test -p secretive-agent` | `28 passed` | pass
 - 2026-02-10 | `ruby -e "require 'yaml'; YAML.load_file('.github/workflows/rust-lint.yml')"` | `ok` | pass
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
 - 2026-02-10 | `cargo test -p secretive-agent` | `30 passed` | pass
 - 2026-02-10 | `BENCH_CONCURRENCY=64 BENCH_REQUESTS=4 MIN_RPS=1 ./scripts/bench_smoke_gate.sh` | `bench smoke gate passed` | pass
 - 2026-02-10 | `./scripts/confirm_command_smoke.sh` | `[confirm-smoke] ok` | pass
 - 2026-02-10 | `ruby -c packaging/homebrew/secretivex.rb` | `Syntax OK` | pass
 - 2026-02-10 | `./scripts/check_shell.sh` | `checked 17 script(s)` | pass

## Historical Summary
- Keep compact summaries of older entries here when file compaction runs.
