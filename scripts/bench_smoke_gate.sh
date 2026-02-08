#!/usr/bin/env sh
set -eu

BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-128}"
BENCH_REQUESTS="${BENCH_REQUESTS:-8}"
BENCH_PAYLOAD_SIZE="${BENCH_PAYLOAD_SIZE:-64}"
BENCH_PROFILE="${BENCH_PROFILE:-fanout}"
MIN_RPS="${MIN_RPS:-25}"

workdir="$(pwd)"
tmpdir="$(mktemp -d)"
agent_pid=""

cleanup() {
  if [ -n "$agent_pid" ] && kill -0 "$agent_pid" >/dev/null 2>&1; then
    kill "$agent_pid" >/dev/null 2>&1 || true
    wait "$agent_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

key_path="$tmpdir/id_ed25519"
config_path="$tmpdir/agent.json"
socket_path="$tmpdir/agent.sock"
bench_json="$tmpdir/bench.json"

ssh-keygen -t ed25519 -N "" -f "$key_path" >/dev/null

cat > "$config_path" <<JSON
{
  "profile": "$BENCH_PROFILE",
  "stores": [
    {
      "type": "file",
      "paths": ["$key_path"],
      "scan_default_dir": false
    }
  ],
  "watch_files": false,
  "metrics_every": 0,
  "identity_cache_ms": 5000,
  "max_connections": 512,
  "max_signers": 64
}
JSON

cargo run -p secretive-agent -- \
  --config "$config_path" \
  --socket "$socket_path" \
  --no-watch \
  --metrics-every 0 >/dev/null 2>&1 &
agent_pid="$!"

ready=0
for _ in $(seq 1 100); do
  if [ -S "$socket_path" ]; then
    if cargo run -p secretive-client -- --socket "$socket_path" --list --raw >/dev/null 2>&1; then
      ready=1
      break
    fi
  fi
  sleep 0.1
done

if [ "$ready" -ne 1 ]; then
  echo "agent failed to become ready" >&2
  exit 1
fi

cargo run -p secretive-bench -- \
  --socket "$socket_path" \
  --reconnect \
  --concurrency "$BENCH_CONCURRENCY" \
  --requests "$BENCH_REQUESTS" \
  --payload-size "$BENCH_PAYLOAD_SIZE" \
  --fixed \
  --json-compact > "$bench_json"

rps="$(grep -o '"rps":[0-9.]*' "$bench_json" | head -n1 | cut -d: -f2)"
failures="$(grep -o '"failures":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"
ok="$(grep -o '"ok":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"

if [ -z "$rps" ] || [ -z "$failures" ] || [ -z "$ok" ]; then
  echo "failed to parse bench output" >&2
  cat "$bench_json" >&2
  exit 1
fi

if [ "$failures" -ne 0 ]; then
  echo "bench reported failures: $failures" >&2
  cat "$bench_json" >&2
  exit 1
fi

if ! awk -v rps="$rps" -v min="$MIN_RPS" 'BEGIN { exit (rps + 0 >= min + 0 ? 0 : 1) }'; then
  echo "bench rps below threshold: rps=$rps min=$MIN_RPS" >&2
  cat "$bench_json" >&2
  exit 1
fi

echo "bench smoke gate passed: ok=$ok rps=$rps min_rps=$MIN_RPS"
