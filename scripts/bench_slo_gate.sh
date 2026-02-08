#!/usr/bin/env sh
set -eu

SLO_CONCURRENCY="${SLO_CONCURRENCY:-1000}"
SLO_DURATION_SECS="${SLO_DURATION_SECS:-20}"
SLO_PAYLOAD_SIZE="${SLO_PAYLOAD_SIZE:-64}"
SLO_WORKER_START_SPREAD_MS="${SLO_WORKER_START_SPREAD_MS:-1500}"
SLO_PROFILE="${SLO_PROFILE:-pssh}"
SLO_MIN_RPS="${SLO_MIN_RPS:-20}"
SLO_MAX_P95_US="${SLO_MAX_P95_US:-300000}"
SLO_MAX_FAILURE_RATE="${SLO_MAX_FAILURE_RATE:-0.01}"
SLO_MAX_QUEUE_WAIT_AVG_NS="${SLO_MAX_QUEUE_WAIT_AVG_NS:-0}"
SLO_MAX_QUEUE_WAIT_MAX_NS="${SLO_MAX_QUEUE_WAIT_MAX_NS:-0}"
SLO_QUEUE_WAIT_TAIL_NS="${SLO_QUEUE_WAIT_TAIL_NS:-0}"
SLO_QUEUE_WAIT_TAIL_MAX_RATIO="${SLO_QUEUE_WAIT_TAIL_MAX_RATIO:-0}"

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
metrics_json="$tmpdir/agent-metrics.json"

ssh-keygen -t ed25519 -N "" -f "$key_path" >/dev/null

cat > "$config_path" <<JSON
{
  "profile": "$SLO_PROFILE",
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
  "metrics_output_path": "$metrics_json",
  "identity_cache_ms": 5000,
  "socket_backlog": 4096,
  "max_connections": 32768,
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

queue_wait_avg_ns=""
queue_wait_max_ns=""
queue_wait_tail_ratio=""
queue_wait_tail_count=""
queue_wait_tail_total=""
if [ -f "$metrics_json" ]; then
  queue_wait_avg_ns="$(grep -o '"queue_wait_avg_ns":[0-9.]*' "$metrics_json" | head -n1 | cut -d: -f2)"
  queue_wait_max_ns="$(grep -o '"queue_wait_max_ns":[0-9]*' "$metrics_json" | head -n1 | cut -d: -f2)"
  if [ "$SLO_QUEUE_WAIT_TAIL_NS" != "0" ] && [ "$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" != "0" ]; then
    tail_output="$(python3 <<'PY' "$metrics_json" "$SLO_QUEUE_WAIT_TAIL_NS"
import json
import sys

BOUNDS = [
    500,
    1000,
    2000,
    4000,
    8000,
    16000,
    32000,
    64000,
    128000,
    256000,
    512000,
    1000000,
    2000000,
    4000000,
    8000000,
    16000000,
    32000000,
    64000000,
    128000000,
    256000000,
    512000000,
    1000000000,
    2000000000,
    4000000000,
    8000000000,
]

def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: script <metrics_json> <threshold_ns>")
    metrics_path = sys.argv[1]
    threshold_ns = float(sys.argv[2])
    with open(metrics_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    histogram = data.get("queue_wait_histogram")
    if not isinstance(histogram, list) or not histogram:
        raise SystemExit("missing queue_wait_histogram")
    if len(histogram) != len(BOUNDS) + 1:
        raise SystemExit("unexpected bucket count")
    total = sum(int(value) for value in histogram)
    if total == 0:
        total = int(data.get("count") or 0)
    tail_started = threshold_ns <= 0
    tail = 0
    for idx, value in enumerate(histogram):
        upper = BOUNDS[idx] if idx < len(BOUNDS) else None
        if not tail_started:
            if upper is None or threshold_ns <= upper:
                tail_started = True
        if tail_started:
            tail += int(value)
    ratio = 0.0 if total == 0 else tail / total
    print(f"{ratio:.10f} {tail} {total}")


if __name__ == "__main__":
    main()
PY
)"
    if [ -z "$tail_output" ]; then
      echo "failed to compute queue wait tail ratio" >&2
      cat "$metrics_json" >&2
      exit 1
    fi
    queue_wait_tail_ratio="$(printf '%s' "$tail_output" | awk '{print $1}')"
    queue_wait_tail_count="$(printf '%s' "$tail_output" | awk '{print $2}')"
    queue_wait_tail_total="$(printf '%s' "$tail_output" | awk '{print $3}')"
  fi
fi

if [ -n "$queue_wait_avg_ns" ] && [ "$SLO_MAX_QUEUE_WAIT_AVG_NS" != "0" ]; then
  if ! awk -v value="$queue_wait_avg_ns" -v max="$SLO_MAX_QUEUE_WAIT_AVG_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
    echo "SLO failure: queue wait avg above maximum (queue_wait_avg_ns=$queue_wait_avg_ns max=$SLO_MAX_QUEUE_WAIT_AVG_NS)" >&2
    cat "$bench_json" >&2
    cat "$metrics_json" >&2
    exit 1
  fi
fi

if [ -n "$queue_wait_max_ns" ] && [ "$SLO_MAX_QUEUE_WAIT_MAX_NS" != "0" ]; then
  if ! awk -v value="$queue_wait_max_ns" -v max="$SLO_MAX_QUEUE_WAIT_MAX_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
    echo "SLO failure: queue wait max above maximum (queue_wait_max_ns=$queue_wait_max_ns max=$SLO_MAX_QUEUE_WAIT_MAX_NS)" >&2
    cat "$bench_json" >&2
    cat "$metrics_json" >&2
    exit 1
  fi
fi

if [ "$SLO_QUEUE_WAIT_TAIL_NS" != "0" ] && [ "$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" != "0" ]; then
  if [ -z "$queue_wait_tail_ratio" ] || [ -z "$queue_wait_tail_total" ]; then
    echo "SLO failure: queue wait tail thresholds require metrics histogram" >&2
    [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
    exit 1
  fi
  if ! awk -v ratio="$queue_wait_tail_ratio" -v max="$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" 'BEGIN { exit (ratio + 0 <= max + 0 ? 0 : 1) }'; then
    echo "SLO failure: queue wait tail ratio above maximum (threshold_ns=$SLO_QUEUE_WAIT_TAIL_NS tail_ratio=$queue_wait_tail_ratio count=$queue_wait_tail_count total=$queue_wait_tail_total max_ratio=$SLO_QUEUE_WAIT_TAIL_MAX_RATIO)" >&2
    cat "$bench_json" >&2
    cat "$metrics_json" >&2
    exit 1
  fi
fi

echo "slo gate passed: concurrency=$SLO_CONCURRENCY duration=${SLO_DURATION_SECS}s spread_ms=$SLO_WORKER_START_SPREAD_MS rps=$rps p95_us=$p95_us failure_rate=$failure_rate queue_wait_avg_ns=${queue_wait_avg_ns:-n/a} queue_wait_max_ns=${queue_wait_max_ns:-n/a} queue_wait_tail_ratio=${queue_wait_tail_ratio:-n/a}"
