#!/usr/bin/env sh
set -eu

SLO_CONCURRENCY="${SLO_CONCURRENCY:-1000}"
SLO_DURATION_SECS="${SLO_DURATION_SECS:-20}"
SLO_PAYLOAD_SIZE="${SLO_PAYLOAD_SIZE:-64}"
SLO_WORKER_START_SPREAD_MS="${SLO_WORKER_START_SPREAD_MS:-1500}"
SLO_MIN_RPS="${SLO_MIN_RPS:-20}"
SLO_MAX_P95_US="${SLO_MAX_P95_US:-300000}"
SLO_MAX_FAILURE_RATE="${SLO_MAX_FAILURE_RATE:-0.01}"

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

ulimit -n 65535 >/dev/null 2>&1 || true

key_path="$tmpdir/id_ed25519"
config_path="$tmpdir/agent.json"
socket_path="$tmpdir/agent.sock"
bench_json="$tmpdir/bench.json"

ssh-keygen -t ed25519 -N "" -f "$key_path" >/dev/null

cat > "$config_path" <<JSON
{
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
  "socket_backlog": 4096,
  "max_connections": 4096,
  "max_signers": 128,
  "max_blocking_threads": 128
}
JSON

cargo run -p secretive-agent -- \
  --config "$config_path" \
  --socket "$socket_path" \
  --no-watch \
  --metrics-every 0 >/dev/null 2>&1 &
agent_pid="$!"

ready=0
for _ in $(seq 1 120); do
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
  --concurrency "$SLO_CONCURRENCY" \
  --duration "$SLO_DURATION_SECS" \
  --payload-size "$SLO_PAYLOAD_SIZE" \
  --worker-start-spread-ms "$SLO_WORKER_START_SPREAD_MS" \
  --fixed \
  --latency \
  --latency-max-samples 200000 \
  --json-compact > "$bench_json"

rps="$(grep -o '"rps":[0-9.]*' "$bench_json" | head -n1 | cut -d: -f2)"
ok="$(grep -o '"ok":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"
failures="$(grep -o '"failures":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"
p95_us="$(grep -o '"p95_us":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"

if [ -z "$rps" ] || [ -z "$ok" ] || [ -z "$failures" ] || [ -z "$p95_us" ]; then
  echo "failed to parse bench output" >&2
  cat "$bench_json" >&2
  exit 1
fi

total="$(awk -v ok="$ok" -v failures="$failures" 'BEGIN { print ok + failures }')"
failure_rate="$(awk -v failures="$failures" -v total="$total" 'BEGIN { if (total == 0) print 1; else print failures / total }')"

if ! awk -v rps="$rps" -v min="$SLO_MIN_RPS" 'BEGIN { exit (rps + 0 >= min + 0 ? 0 : 1) }'; then
  echo "SLO failure: throughput below minimum (rps=$rps min=$SLO_MIN_RPS)" >&2
  cat "$bench_json" >&2
  exit 1
fi

if ! awk -v p95="$p95_us" -v max="$SLO_MAX_P95_US" 'BEGIN { exit (p95 + 0 <= max + 0 ? 0 : 1) }'; then
  echo "SLO failure: p95 latency above maximum (p95_us=$p95_us max=$SLO_MAX_P95_US)" >&2
  cat "$bench_json" >&2
  exit 1
fi

if ! awk -v rate="$failure_rate" -v max="$SLO_MAX_FAILURE_RATE" 'BEGIN { exit (rate + 0 <= max + 0 ? 0 : 1) }'; then
  echo "SLO failure: failure rate above maximum (failure_rate=$failure_rate max=$SLO_MAX_FAILURE_RATE)" >&2
  cat "$bench_json" >&2
  exit 1
fi

echo "slo gate passed: concurrency=$SLO_CONCURRENCY duration=${SLO_DURATION_SECS}s spread_ms=$SLO_WORKER_START_SPREAD_MS rps=$rps p95_us=$p95_us failure_rate=$failure_rate"
