#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AGENT_STARTUP_TIMEOUT_SECS="${AGENT_STARTUP_TIMEOUT_SECS:-90}"

BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-128}"
BENCH_REQUESTS="${BENCH_REQUESTS:-8}"
BENCH_PAYLOAD_SIZE="${BENCH_PAYLOAD_SIZE:-64}"
BENCH_PROFILE="${BENCH_PROFILE:-fanout}"
BENCH_CONNECT_TIMEOUT_MS="${BENCH_CONNECT_TIMEOUT_MS:-1500}"
MIN_RPS="${MIN_RPS:-25}"

repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

echo "[bench-smoke] building Rust tools" >&2
cargo build -p secretive-agent -p secretive-bench -p secretive-client

agent_bin="$repo_root/target/debug/secretive-agent"
bench_bin="$repo_root/target/debug/secretive-bench"
client_bin="$repo_root/target/debug/secretive-client"
export SECRETIVE_CLIENT_BIN="$client_bin"

workdir="$(pwd)"
tmpdir="$(mktemp -d)"
agent_pid=""
agent_log="$tmpdir/agent.log"

print_agent_log_tail() {
  if [ -f "$agent_log" ] && [ -s "$agent_log" ]; then
    echo "---- agent log (tail -n 120) ----" >&2
    tail -n 120 "$agent_log" >&2 || true
    echo "---- end agent log ----" >&2
  fi
}

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
  "sign_timeout_ms": 0,
  "identity_cache_ms": 5000,
  "max_connections": 512,
  "max_signers": 64
}
JSON

"$agent_bin" \
  --config "$config_path" \
  --socket "$socket_path" \
  --no-watch \
  --metrics-every 0 >"$agent_log" 2>&1 &
agent_pid="$!"

"$script_dir/wait_for_agent_ready.sh" \
  "$socket_path" \
  "$agent_pid" \
  "$agent_log" \
  "$AGENT_STARTUP_TIMEOUT_SECS"

"$bench_bin" \
  --socket "$socket_path" \
  --reconnect \
  --concurrency "$BENCH_CONCURRENCY" \
  --requests "$BENCH_REQUESTS" \
  --connect-timeout-ms "$BENCH_CONNECT_TIMEOUT_MS" \
  --payload-size "$BENCH_PAYLOAD_SIZE" \
  --fixed \
  --json-compact > "$bench_json"

rps="$(grep -o '"rps":[0-9.]*' "$bench_json" | head -n1 | cut -d: -f2)"
failures="$(grep -o '"failures":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"
ok="$(grep -o '"ok":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"

if [ -z "$rps" ] || [ -z "$failures" ] || [ -z "$ok" ]; then
  echo "failed to parse bench output" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

if [ "$failures" -ne 0 ]; then
  echo "bench reported failures: $failures" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

if ! awk -v rps="$rps" -v min="$MIN_RPS" 'BEGIN { exit (rps + 0 >= min + 0 ? 0 : 1) }'; then
  echo "bench rps below threshold: rps=$rps min=$MIN_RPS" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

echo "bench smoke gate passed: ok=$ok rps=$rps min_rps=$MIN_RPS"
