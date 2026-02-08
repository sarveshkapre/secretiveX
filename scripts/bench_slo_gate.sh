#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AGENT_STARTUP_TIMEOUT_SECS="${AGENT_STARTUP_TIMEOUT_SECS:-90}"

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

auto_queue_wait_profile=""

set_queue_wait_defaults() {
  profile="$1"
  case "$profile" in
    pssh)
      SLO_QUEUE_WAIT_TAIL_NS="4000000"
      SLO_QUEUE_WAIT_TAIL_MAX_RATIO="0.03"
      ;;
    fanout)
      SLO_QUEUE_WAIT_TAIL_NS="6000000"
      SLO_QUEUE_WAIT_TAIL_MAX_RATIO="0.04"
      ;;
    balanced)
      SLO_QUEUE_WAIT_TAIL_NS="8000000"
      SLO_QUEUE_WAIT_TAIL_MAX_RATIO="0.05"
      ;;
    low-memory)
      SLO_QUEUE_WAIT_TAIL_NS="12000000"
      SLO_QUEUE_WAIT_TAIL_MAX_RATIO="0.07"
      ;;
    *)
      SLO_QUEUE_WAIT_TAIL_NS="8000000"
      SLO_QUEUE_WAIT_TAIL_MAX_RATIO="0.05"
      ;;
  esac
  auto_queue_wait_profile="$profile"
}

if [ "$SLO_QUEUE_WAIT_TAIL_NS" = "0" ] && [ "$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" = "0" ]; then
  set_queue_wait_defaults "$SLO_PROFILE"
fi

if [ -n "$auto_queue_wait_profile" ]; then
  echo "auto queue-wait guardrail: profile=$auto_queue_wait_profile tail_ns=$SLO_QUEUE_WAIT_TAIL_NS max_ratio=$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" >&2
fi

tmpdir="$(mktemp -d)"
agent_pid=""
agent_log="$tmpdir/agent.log"

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
  --metrics-every 0 >"$agent_log" 2>&1 &
agent_pid="$!"

"$script_dir/wait_for_agent_ready.sh" \
  "$socket_path" \
  "$agent_pid" \
  "$agent_log" \
  "$AGENT_STARTUP_TIMEOUT_SECS"

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
  --metrics-file "$metrics_json" \
  --queue-wait-tail-profile "$SLO_PROFILE" \
  --queue-wait-tail-ns "$SLO_QUEUE_WAIT_TAIL_NS" \
  --queue-wait-tail-max-ratio "$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" \
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
queue_wait_tail_mode=""
queue_wait_tail_percentile_label=""
queue_wait_tail_percentile_pct=""
queue_wait_tail_percentile_ns=""
if [ -f "$metrics_json" ]; then
  queue_wait_avg_ns="$(grep -o '"queue_wait_avg_ns":[0-9.]*' "$metrics_json" | head -n1 | cut -d: -f2)"
  queue_wait_max_ns="$(grep -o '"queue_wait_max_ns":[0-9]*' "$metrics_json" | head -n1 | cut -d: -f2)"
fi

queue_wait_tail_check_required=0
if [ "$SLO_QUEUE_WAIT_TAIL_NS" != "0" ] && [ "$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" != "0" ]; then
  queue_wait_tail_check_required=1
fi

if [ "$queue_wait_tail_check_required" -eq 1 ]; then
  if [ ! -f "$metrics_json" ]; then
    echo "SLO failure: queue wait tail thresholds require metrics snapshot" >&2
    exit 1
  fi
  tail_output="$(python3 - <<'PY' "$metrics_json" "$SLO_QUEUE_WAIT_TAIL_NS" "$SLO_QUEUE_WAIT_TAIL_MAX_RATIO"
import json
import math
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

PERCENTILES = [
    ("p50", 0.50),
    ("p90", 0.90),
    ("p95", 0.95),
    ("p99", 0.99),
]


def load_metrics(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def choose_percentile(metrics: dict, target_percentile: float):
    percentiles = metrics.get("queue_wait_percentiles")
    if not isinstance(percentiles, dict):
        return None
    for label, percentile_value in PERCENTILES:
        entry = percentiles.get(label)
        if not isinstance(entry, dict):
            continue
        if entry.get("open_ended"):
            continue
        ns_value = entry.get("ns")
        if ns_value is None:
            continue
        try:
            numeric_ns = float(ns_value)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(numeric_ns):
            continue
        if percentile_value + 1e-9 >= target_percentile:
            return label, percentile_value, int(numeric_ns)
    return None


def emit_histogram(metrics: dict, threshold_ns: float) -> bool:
    histogram = metrics.get("queue_wait_histogram")
    if not isinstance(histogram, list) or not histogram:
        return False
    if len(histogram) != len(BOUNDS) + 1:
        raise SystemExit("unexpected bucket count")
    total = sum(int(value) for value in histogram)
    if total == 0:
        total = int(metrics.get("count") or 0)
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
    print(f"hist {ratio:.10f} {tail} {total}")
    return True


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: script <metrics_json> <threshold_ns> <max_ratio>")
    metrics = load_metrics(sys.argv[1])
    threshold_ns = float(sys.argv[2])
    try:
        max_ratio = float(sys.argv[3])
    except ValueError:
        max_ratio = 0.0
    if max_ratio < 0.0:
        max_ratio = 0.0
    target_percentile = 1.0 - max_ratio if max_ratio < 1.0 else 1.0
    if target_percentile < 0.0:
        target_percentile = 0.0
    percentile = choose_percentile(metrics, target_percentile)
    if percentile:
        label, percentile_value, ns_value = percentile
        print(f"percentile {label} {percentile_value:.6f} {ns_value}")
        return
    if emit_histogram(metrics, threshold_ns):
        return
    raise SystemExit("queue wait histogram unavailable")


if __name__ == "__main__":
    main()
PY
)"
  if [ -z "$tail_output" ]; then
    echo "failed to parse queue wait tail metrics" >&2
    cat "$metrics_json" >&2
    exit 1
  fi
  queue_wait_tail_mode="$(printf '%s' "$tail_output" | awk '{print $1}')"
  if [ "$queue_wait_tail_mode" = "percentile" ]; then
    queue_wait_tail_percentile_label="$(printf '%s' "$tail_output" | awk '{print $2}')"
    queue_wait_tail_percentile_pct="$(printf '%s' "$tail_output" | awk '{print $3}')"
    queue_wait_tail_percentile_ns="$(printf '%s' "$tail_output" | awk '{print $4}')"
    queue_wait_tail_ratio="$(awk -v percentile="$queue_wait_tail_percentile_pct" 'BEGIN { printf "%.10f", 1 - percentile }')"
    queue_wait_tail_count="n/a"
    queue_wait_tail_total="n/a"
  elif [ "$queue_wait_tail_mode" = "hist" ]; then
    queue_wait_tail_ratio="$(printf '%s' "$tail_output" | awk '{print $2}')"
    queue_wait_tail_count="$(printf '%s' "$tail_output" | awk '{print $3}')"
    queue_wait_tail_total="$(printf '%s' "$tail_output" | awk '{print $4}')"
  else
    echo "SLO failure: unrecognized queue wait tail payload" >&2
    cat "$metrics_json" >&2
    exit 1
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

if [ "$queue_wait_tail_check_required" -eq 1 ]; then
  if [ "$queue_wait_tail_mode" = "percentile" ]; then
    if ! awk -v value="$queue_wait_tail_percentile_ns" -v max="$SLO_QUEUE_WAIT_TAIL_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
      echo "SLO failure: queue wait $queue_wait_tail_percentile_label exceeded tail threshold (value_ns=$queue_wait_tail_percentile_ns max_ns=$SLO_QUEUE_WAIT_TAIL_NS max_ratio=$SLO_QUEUE_WAIT_TAIL_MAX_RATIO)" >&2
      cat "$bench_json" >&2
      cat "$metrics_json" >&2
      exit 1
    fi
  elif [ "$queue_wait_tail_mode" = "hist" ]; then
    if [ -z "$queue_wait_tail_ratio" ] || [ -z "$queue_wait_tail_total" ]; then
      echo "SLO failure: queue wait tail thresholds require metrics histogram" >&2
      cat "$metrics_json" >&2
      exit 1
    fi
    if ! awk -v ratio="$queue_wait_tail_ratio" -v max="$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" 'BEGIN { exit (ratio + 0 <= max + 0 ? 0 : 1) }'; then
      echo "SLO failure: queue wait tail ratio above maximum (threshold_ns=$SLO_QUEUE_WAIT_TAIL_NS tail_ratio=$queue_wait_tail_ratio count=$queue_wait_tail_count total=$queue_wait_tail_total max_ratio=$SLO_QUEUE_WAIT_TAIL_MAX_RATIO)" >&2
      cat "$bench_json" >&2
      cat "$metrics_json" >&2
      exit 1
    fi
  else
    echo "SLO failure: queue wait tail metrics missing" >&2
    cat "$metrics_json" >&2
    exit 1
  fi
fi

queue_wait_tail_detail="n/a"
if [ "$queue_wait_tail_mode" = "percentile" ]; then
  queue_wait_tail_detail="$queue_wait_tail_percentile_label:$queue_wait_tail_percentile_ns"
elif [ "$queue_wait_tail_mode" = "hist" ]; then
  queue_wait_tail_detail="$queue_wait_tail_count/$queue_wait_tail_total"
fi

echo "slo gate passed: concurrency=$SLO_CONCURRENCY duration=${SLO_DURATION_SECS}s spread_ms=$SLO_WORKER_START_SPREAD_MS rps=$rps p95_us=$p95_us failure_rate=$failure_rate queue_wait_avg_ns=${queue_wait_avg_ns:-n/a} queue_wait_max_ns=${queue_wait_max_ns:-n/a} queue_wait_tail_ratio=${queue_wait_tail_ratio:-n/a} queue_wait_tail_source=${queue_wait_tail_mode:-n/a} queue_wait_tail_detail=$queue_wait_tail_detail"
