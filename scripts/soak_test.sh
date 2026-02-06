#!/usr/bin/env sh
set -eu

SOAK_DURATION_SECS="${SOAK_DURATION_SECS:-1800}"
SOAK_CONCURRENCY="${SOAK_CONCURRENCY:-256}"
SOAK_PAYLOAD_SIZE="${SOAK_PAYLOAD_SIZE:-64}"
SOAK_RECONNECT="${SOAK_RECONNECT:-1}"
SOAK_MIN_RPS="${SOAK_MIN_RPS:-0}"
SOAK_MAX_FAILURE_RATE="${SOAK_MAX_FAILURE_RATE:-0.01}"
SOAK_OUTPUT_JSON="${SOAK_OUTPUT_JSON:-}"
SOAK_OUTPUT_METRICS="${SOAK_OUTPUT_METRICS:-}"
SOAK_MAX_QUEUE_WAIT_AVG_NS="${SOAK_MAX_QUEUE_WAIT_AVG_NS:-0}"
SOAK_MAX_QUEUE_WAIT_MAX_NS="${SOAK_MAX_QUEUE_WAIT_MAX_NS:-0}"

EXTERNAL_SOCKET="${SOAK_SOCKET:-}"

tmpdir="$(mktemp -d)"
agent_pid=""
agent_metrics_json="$tmpdir/agent-metrics.json"

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
  "stores": [
    {
      "type": "file",
      "paths": ["$key_path"],
      "scan_default_dir": false
    }
  ],
  "watch_files": false,
  "metrics_every": 0,
  "metrics_interval_ms": 1000,
  "metrics_output_path": "$agent_metrics_json",
  "identity_cache_ms": 5000,
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
fi

bench_json="$tmpdir/soak.json"

bench_args="--socket $socket_path --concurrency $SOAK_CONCURRENCY --duration $SOAK_DURATION_SECS --payload-size $SOAK_PAYLOAD_SIZE --fixed --latency --latency-max-samples 200000 --json-compact"
if [ "$SOAK_RECONNECT" = "1" ]; then
  bench_args="$bench_args --reconnect"
fi

# shellcheck disable=SC2086
cargo run -p secretive-bench -- $bench_args > "$bench_json"

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

if [ -z "$rps" ] || [ -z "$ok" ] || [ -z "$failures" ] || [ -z "$p95_us" ]; then
  echo "failed to parse soak output" >&2
  cat "$bench_json" >&2
  exit 1
fi

total="$(awk -v ok="$ok" -v failures="$failures" 'BEGIN { print ok + failures }')"
failure_rate="$(awk -v failures="$failures" -v total="$total" 'BEGIN { if (total == 0) print 1; else print failures / total }')"
queue_wait_avg_ns=""
queue_wait_max_ns=""
if [ -f "$agent_metrics_json" ]; then
  queue_wait_avg_ns="$(grep -o '"queue_wait_avg_ns":[0-9.]*' "$agent_metrics_json" | head -n1 | cut -d: -f2)"
  queue_wait_max_ns="$(grep -o '"queue_wait_max_ns":[0-9]*' "$agent_metrics_json" | head -n1 | cut -d: -f2)"
fi

if ! awk -v rps="$rps" -v min="$SOAK_MIN_RPS" 'BEGIN { exit (rps + 0 >= min + 0 ? 0 : 1) }'; then
  echo "soak gate failed: throughput below minimum (rps=$rps min=$SOAK_MIN_RPS)" >&2
  cat "$bench_json" >&2
  exit 1
fi

if ! awk -v rate="$failure_rate" -v max="$SOAK_MAX_FAILURE_RATE" 'BEGIN { exit (rate + 0 <= max + 0 ? 0 : 1) }'; then
  echo "soak gate failed: failure rate above max (failure_rate=$failure_rate max=$SOAK_MAX_FAILURE_RATE)" >&2
  cat "$bench_json" >&2
  exit 1
fi

if [ -n "$queue_wait_avg_ns" ] && [ "$SOAK_MAX_QUEUE_WAIT_AVG_NS" != "0" ]; then
  if ! awk -v value="$queue_wait_avg_ns" -v max="$SOAK_MAX_QUEUE_WAIT_AVG_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
    echo "soak gate failed: queue wait avg above max (queue_wait_avg_ns=$queue_wait_avg_ns max=$SOAK_MAX_QUEUE_WAIT_AVG_NS)" >&2
    cat "$bench_json" >&2
    [ -f "$agent_metrics_json" ] && cat "$agent_metrics_json" >&2 || true
    exit 1
  fi
fi

if [ -n "$queue_wait_max_ns" ] && [ "$SOAK_MAX_QUEUE_WAIT_MAX_NS" != "0" ]; then
  if ! awk -v value="$queue_wait_max_ns" -v max="$SOAK_MAX_QUEUE_WAIT_MAX_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
    echo "soak gate failed: queue wait max above max (queue_wait_max_ns=$queue_wait_max_ns max=$SOAK_MAX_QUEUE_WAIT_MAX_NS)" >&2
    cat "$bench_json" >&2
    [ -f "$agent_metrics_json" ] && cat "$agent_metrics_json" >&2 || true
    exit 1
  fi
fi

echo "soak passed: duration=${SOAK_DURATION_SECS}s reconnect=$SOAK_RECONNECT concurrency=$SOAK_CONCURRENCY rps=$rps p95_us=$p95_us failure_rate=$failure_rate queue_wait_avg_ns=${queue_wait_avg_ns:-n/a} queue_wait_max_ns=${queue_wait_max_ns:-n/a}"

echo "full benchmark result:"
cat "$bench_json"
