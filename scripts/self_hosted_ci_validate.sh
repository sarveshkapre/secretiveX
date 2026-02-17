#!/usr/bin/env bash
set -euo pipefail

echo "[self-hosted-ci] preflight"
./scripts/self_hosted_runner_preflight.sh all || {
  echo "[self-hosted-ci] preflight failed" >&2
  exit 1
}

echo "[self-hosted-ci] shell + repo sanity"
./scripts/check_shell.sh
./scripts/repo_sanity.sh

echo "[self-hosted-ci] rust lint + tests"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test -p secretive-core -p secretive-proto -p secretive-agent -p secretive-client -p secretive-bench

echo "[self-hosted-ci] rust smoke/gates (scaled local envelope)"
OPENSSH_KEY_TYPES=ed25519 ./scripts/openssh_compat_smoke.sh
AGENT_STARTUP_TIMEOUT_SECS=90 BENCH_CONCURRENCY=32 BENCH_REQUESTS=4 MIN_RPS=1 ./scripts/bench_smoke_gate.sh
AGENT_STARTUP_TIMEOUT_SECS=90 DURATION_SMOKE_CONCURRENCY=32 DURATION_SMOKE_DURATION_SECS=1 DURATION_SMOKE_MIN_RPS=1 DURATION_SMOKE_MAX_FAILURE_RATE=1 ./scripts/duration_reconnect_smoke.sh
AGENT_STARTUP_TIMEOUT_SECS=90 SLO_CONCURRENCY=32 SLO_DURATION_SECS=1 SLO_MIN_RPS=1 SLO_MAX_P95_US=10000000 SLO_MAX_FAILURE_RATE=1 ./scripts/bench_slo_gate.sh

if command -v softhsm2-util >/dev/null 2>&1 && command -v pkcs11-tool >/dev/null 2>&1; then
  echo "[self-hosted-ci] pkcs11 smoke"
  PKCS11_SMOKE_REQUIRE_TOOLS=1 ./scripts/pkcs11_smoke.sh
else
  echo "[self-hosted-ci] pkcs11 smoke skipped (missing softhsm2-util/pkcs11-tool)"
fi

if [ "$(uname -s)" = "Darwin" ]; then
  echo "[self-hosted-ci] macOS Swift tests"
  xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme PackageTests test
  swift test --build-system swiftbuild
else
  echo "[self-hosted-ci] macOS Swift tests skipped on $(uname -s)"
fi

echo "[self-hosted-ci] validation passed"
