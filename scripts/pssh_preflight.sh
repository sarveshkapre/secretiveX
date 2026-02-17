#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

PREFLIGHT_SOCKET="${PSSH_PREFLIGHT_SOCKET:-${SECRETIVE_SOCK:-}}"
PREFLIGHT_WAIT_TIMEOUT_MS="${PSSH_PREFLIGHT_WAIT_TIMEOUT_MS:-30000}"
PREFLIGHT_WAIT_INTERVAL_MS="${PSSH_PREFLIGHT_WAIT_INTERVAL_MS:-200}"
PREFLIGHT_METRICS_FILE="${PSSH_PREFLIGHT_METRICS_FILE:-}"
PREFLIGHT_QUEUE_WAIT_PROFILE="${PSSH_PREFLIGHT_QUEUE_WAIT_PROFILE:-pssh}"
PREFLIGHT_QUEUE_WAIT_MAX_AGE_MS="${PSSH_PREFLIGHT_QUEUE_WAIT_MAX_AGE_MS:-10000}"

echo "[pssh-preflight] building secretive-client"
cargo build -p secretive-client >/dev/null
client_bin="$repo_root/target/debug/secretive-client"

if [ ! -x "$client_bin" ]; then
  echo "secretive-client binary missing at $client_bin" >&2
  exit 1
fi

socket_args=""
if [ -n "$PREFLIGHT_SOCKET" ]; then
  socket_args="--socket $PREFLIGHT_SOCKET"
fi

echo "[pssh-preflight] waiting for agent readiness"
# shellcheck disable=SC2086
"$client_bin" $socket_args \
  --wait-ready \
  --wait-ready-timeout-ms "$PREFLIGHT_WAIT_TIMEOUT_MS" \
  --wait-ready-interval-ms "$PREFLIGHT_WAIT_INTERVAL_MS" >/dev/null

health_json="$(mktemp)"
cleanup() {
  rm -f "$health_json"
}
trap cleanup EXIT INT TERM

echo "[pssh-preflight] collecting key health snapshot"
# shellcheck disable=SC2086
"$client_bin" $socket_args --health --json-compact >"$health_json"

total_identities="$(grep -o '"total_identities":[0-9]*' "$health_json" | head -n1 | cut -d: -f2)"
valid_identities="$(grep -o '"valid_identities":[0-9]*' "$health_json" | head -n1 | cut -d: -f2)"

if [ -z "$total_identities" ] || [ -z "$valid_identities" ]; then
  echo "failed to parse health output" >&2
  cat "$health_json" >&2
  exit 1
fi

if [ "$total_identities" -eq 0 ] || [ "$valid_identities" -eq 0 ]; then
  echo "no usable identities available (total=$total_identities valid=$valid_identities)" >&2
  cat "$health_json" >&2
  exit 1
fi

if [ -n "$PREFLIGHT_METRICS_FILE" ]; then
  echo "[pssh-preflight] validating queue-wait envelope from metrics file"
  "$client_bin" \
    --metrics-file "$PREFLIGHT_METRICS_FILE" \
    --queue-wait-tail-profile "$PREFLIGHT_QUEUE_WAIT_PROFILE" \
    --queue-wait-max-age-ms "$PREFLIGHT_QUEUE_WAIT_MAX_AGE_MS" \
    --json-compact >/dev/null
fi

echo "[pssh-preflight] ready: total_identities=$total_identities valid_identities=$valid_identities"
echo "[pssh-preflight] high-fanout ssh hints:"
# shellcheck disable=SC2086
"$client_bin" $socket_args --pssh-hints
