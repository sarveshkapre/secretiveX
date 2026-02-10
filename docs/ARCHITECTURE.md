# SecretiveX Architecture and Ownership

## System overview

SecretiveX is a cross-platform SSH agent platform with a Rust-first runtime.

Core components:
- `crates/secretive-proto`: SSH agent protocol codec (request/response framing).
- `crates/secretive-core`: key store abstractions and backend implementations.
- `crates/secretive-agent`: daemon runtime, concurrency controls, metrics, policy/audit.
- `crates/secretive-client`: diagnostics/debug client for list/sign/health checks.
- `crates/secretive-bench`: load generator and SLO/performance tooling.

Legacy Swift/macOS app code remains for compatibility while Rust reaches full production parity.

## Runtime flow

1. Agent accepts SSH-agent protocol connections (Unix socket or Windows named pipe).
2. `RequestIdentities` uses cache-first list handling with background refresh.
3. `SignRequest` enters concurrency limits (`max_signers`, optional timeout).
4. Policy checks and audit logging run before signing.
5. Optional confirmation/approval hook can gate sign requests (for example an external command prompt).
6. Signing dispatches to configured key stores, then returns SSH signature blobs.

## Performance model

- Bounded concurrent signing via semaphore.
- Optional connection cap and socket backlog tuning for fan-out bursts.
- Reusable protocol buffers and list cache to reduce allocations.
- Bench + soak tooling drive regressions and SLO checks.

## Ownership model

- The Rust runtime (`crates/*`) is the strategic system of record.
- Feature work should land in Rust first unless Swift-specific UX requires separate handling.
- Changes to protocol/store/runtime behavior require tests in the modified crate.
- Cross-cutting changes should update docs (`README.md`, `docs/*.md`) in the same commit.

## Decision process

- Significant design changes should include an Architecture Decision Record (ADR) under `docs/adr/`.
- ADRs should capture context, decision, alternatives, and migration impact.
- Performance-sensitive changes should include benchmark evidence (`secretive-bench` outputs).
