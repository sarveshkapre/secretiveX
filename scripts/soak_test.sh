#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AGENT_STARTUP_TIMEOUT_SECS="${AGENT_STARTUP_TIMEOUT_SECS:-90}"

repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

echo "[soak] building Rust tools" >&2
cargo build -p secretive-agent -p secretive-bench -p secretive-client

agent_bin="$repo_root/target/debug/secretive-agent"
bench_bin="$repo_root/target/debug/secretive-bench"
client_bin="$repo_root/target/debug/secretive-client"
export SECRETIVE_CLIENT_BIN="$client_bin"

SOAK_DURATION_SECS="${SOAK_DURATION_SECS:-1800}"
SOAK_CONCURRENCY="${SOAK_CONCURRENCY:-256}"
SOAK_PAYLOAD_SIZE="${SOAK_PAYLOAD_SIZE:-64}"
SOAK_RECONNECT="${SOAK_RECONNECT:-1}"
SOAK_PROFILE="${SOAK_PROFILE:-pssh}"
SOAK_WORKER_START_SPREAD_MS="${SOAK_WORKER_START_SPREAD_MS:-2000}"
SOAK_MIN_RPS="${SOAK_MIN_RPS:-0}"
SOAK_MAX_P95_US="${SOAK_MAX_P95_US:-0}"
SOAK_MAX_FAILURE_RATE="${SOAK_MAX_FAILURE_RATE:-0.01}"
SOAK_OUTPUT_JSON="${SOAK_OUTPUT_JSON:-}"
SOAK_OUTPUT_METRICS="${SOAK_OUTPUT_METRICS:-}"
SOAK_MAX_QUEUE_WAIT_AVG_NS="${SOAK_MAX_QUEUE_WAIT_AVG_NS:-0}"
SOAK_MAX_QUEUE_WAIT_MAX_NS="${SOAK_MAX_QUEUE_WAIT_MAX_NS:-0}"
SOAK_REQUIRE_QUEUE_WAIT_METRICS="${SOAK_REQUIRE_QUEUE_WAIT_METRICS:-0}"
SOAK_METRICS_FILE="${SOAK_METRICS_FILE:-}"

EXTERNAL_SOCKET="${SOAK_SOCKET:-}"

tmpdir="$(mktemp -d)"
agent_pid=""
agent_log="$tmpdir/agent.log"
agent_metrics_json="$tmpdir/agent-metrics.json"

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

socket_path=""
if [ -n "$EXTERNAL_SOCKET" ]; then
  socket_path="$EXTERNAL_SOCKET"
else
  key_path="$tmpdir/id_ed25519"
  config_path="$tmpdir/agent.json"
  socket_path="$tmpdir/agent.sock"

  ssh-keygen -t ed25519 -N "" -f "$key_path" >/dev/null

  cat > "$config_path" <<JSON
{
  "profile": "$SOAK_PROFILE",
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
  "metrics_interval_ms": 1000,
  "metrics_output_path": "$agent_metrics_json",
  "identity_cache_ms": 5000,
  "max_connections": 4096,
  "max_signers": 128,
  "max_blocking_threads": 128
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
fi

bench_json="$tmpdir/soak.json"

bench_args="--socket $socket_path --concurrency $SOAK_CONCURRENCY --duration $SOAK_DURATION_SECS --payload-size $SOAK_PAYLOAD_SIZE --worker-start-spread-ms $SOAK_WORKER_START_SPREAD_MS --fixed --latency --latency-max-samples 200000 --json-compact"
if [ -n "$agent_pid" ] && [ -n "$agent_metrics_json" ]; then
  bench_args="$bench_args --metrics-file $agent_metrics_json"
elif [ -n "$SOAK_METRICS_FILE" ]; then
  bench_args="$bench_args --metrics-file $SOAK_METRICS_FILE"
fi
if [ "$SOAK_RECONNECT" = "1" ]; then
  bench_args="$bench_args --reconnect"
fi

# shellcheck disable=SC2086
"$bench_bin" $bench_args > "$bench_json"

if [ -n "$SOAK_OUTPUT_JSON" ]; then
  output_dir="$(dirname "$SOAK_OUTPUT_JSON")"
  mkdir -p "$output_dir"
  cp "$bench_json" "$SOAK_OUTPUT_JSON"
fi
if [ -n "$SOAK_OUTPUT_METRICS" ] && [ -f "$agent_metrics_json" ]; then
  output_dir="$(dirname "$SOAK_OUTPUT_METRICS")"
  mkdir -p "$output_dir"
  cp "$agent_metrics_json" "$SOAK_OUTPUT_METRICS"
fi

rps="$(grep -o '"rps":[0-9.]*' "$bench_json" | head -n1 | cut -d: -f2)"
ok="$(grep -o '"ok":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"
failures="$(grep -o '"failures":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"
p95_us="$(grep -o '"p95_us":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"

if [ -z "$rps" ] || [ -z "$ok" ] || [ -z "$failures" ]; then
  echo "failed to parse soak output" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

total="$(awk -v ok="$ok" -v failures="$failures" 'BEGIN { print ok + failures }')"
failure_rate="$(awk -v failures="$failures" -v total="$total" 'BEGIN { if (total == 0) print 1; else print failures / total }')"
queue_wait_avg_ns=""
queue_wait_max_ns=""

metrics_source=""
if [ -f "$agent_metrics_json" ]; then
  metrics_source="$agent_metrics_json"
elif [ -n "$SOAK_METRICS_FILE" ] && [ -f "$SOAK_METRICS_FILE" ]; then
  metrics_source="$SOAK_METRICS_FILE"
fi

# Prefer bench-emitted queue wait report (single source of truth) to avoid parsing agent snapshots.
queue_wait_avg_ns="$(grep -o '"queue_wait_avg_ns":[0-9.]*' "$bench_json" | head -n1 | cut -d: -f2)"
queue_wait_max_ns="$(grep -o '"queue_wait_max_ns":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"

if ! awk -v rps="$rps" -v min="$SOAK_MIN_RPS" 'BEGIN { exit (rps + 0 >= min + 0 ? 0 : 1) }'; then
  echo "soak gate failed: throughput below minimum (rps=$rps min=$SOAK_MIN_RPS)" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

if ! awk -v rate="$failure_rate" -v max="$SOAK_MAX_FAILURE_RATE" 'BEGIN { exit (rate + 0 <= max + 0 ? 0 : 1) }'; then
  echo "soak gate failed: failure rate above max (failure_rate=$failure_rate max=$SOAK_MAX_FAILURE_RATE)" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

if [ "$SOAK_MAX_P95_US" != "0" ]; then
  if [ -z "$p95_us" ]; then
    echo "soak gate failed: latency stats missing (expected p95_us; ok=$ok failures=$failures rps=$rps)" >&2
    cat "$bench_json" >&2
    print_agent_log_tail
    exit 1
  fi
  if ! awk -v p95="$p95_us" -v max="$SOAK_MAX_P95_US" 'BEGIN { exit (p95 + 0 <= max + 0 ? 0 : 1) }'; then
    echo "soak gate failed: p95 latency above max (p95_us=$p95_us max=$SOAK_MAX_P95_US)" >&2
    cat "$bench_json" >&2
    print_agent_log_tail
    exit 1
  fi
fi

if [ "$SOAK_REQUIRE_QUEUE_WAIT_METRICS" = "1" ] || [ "$SOAK_MAX_QUEUE_WAIT_AVG_NS" != "0" ] || [ "$SOAK_MAX_QUEUE_WAIT_MAX_NS" != "0" ]; then
  if [ -z "$queue_wait_avg_ns" ] || [ -z "$queue_wait_max_ns" ]; then
    echo "soak gate failed: queue wait metrics are required but missing" >&2
    cat "$bench_json" >&2
    [ -n "$metrics_source" ] && cat "$metrics_source" >&2 || true
    print_agent_log_tail
    exit 1
  fi
fi

if [ -n "$queue_wait_avg_ns" ] && [ "$SOAK_MAX_QUEUE_WAIT_AVG_NS" != "0" ]; then
  if ! awk -v value="$queue_wait_avg_ns" -v max="$SOAK_MAX_QUEUE_WAIT_AVG_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
    echo "soak gate failed: queue wait avg above max (queue_wait_avg_ns=$queue_wait_avg_ns max=$SOAK_MAX_QUEUE_WAIT_AVG_NS)" >&2
    cat "$bench_json" >&2
    [ -n "$metrics_source" ] && cat "$metrics_source" >&2 || true
    print_agent_log_tail
    exit 1
  fi
fi

if [ -n "$queue_wait_max_ns" ] && [ "$SOAK_MAX_QUEUE_WAIT_MAX_NS" != "0" ]; then
  if ! awk -v value="$queue_wait_max_ns" -v max="$SOAK_MAX_QUEUE_WAIT_MAX_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
    echo "soak gate failed: queue wait max above max (queue_wait_max_ns=$queue_wait_max_ns max=$SOAK_MAX_QUEUE_WAIT_MAX_NS)" >&2
    cat "$bench_json" >&2
    [ -n "$metrics_source" ] && cat "$metrics_source" >&2 || true
    print_agent_log_tail
    exit 1
  fi
fi

echo "soak passed: duration=${SOAK_DURATION_SECS}s reconnect=$SOAK_RECONNECT concurrency=$SOAK_CONCURRENCY spread_ms=$SOAK_WORKER_START_SPREAD_MS rps=$rps p95_us=$p95_us failure_rate=$failure_rate queue_wait_avg_ns=${queue_wait_avg_ns:-n/a} queue_wait_max_ns=${queue_wait_max_ns:-n/a}"

echo "full benchmark result:"
cat "$bench_json"
