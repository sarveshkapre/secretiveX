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

repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

echo "[bench-slo] building Rust tools" >&2
cargo build -p secretive-agent -p secretive-bench -p secretive-client

agent_bin="$repo_root/target/debug/secretive-agent"
bench_bin="$repo_root/target/debug/secretive-bench"
client_bin="$repo_root/target/debug/secretive-client"
export SECRETIVE_CLIENT_BIN="$client_bin"

auto_queue_wait_source=""
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
  "sign_timeout_ms": 0,
  "metrics_interval_ms": 1000,
  "metrics_output_path": "$metrics_json",
  "identity_cache_ms": 5000,
  "socket_backlog": 4096,
  "max_connections": 32768,
  "max_signers": 128,
  "max_blocking_threads": 128
}
JSON

if [ "$SLO_QUEUE_WAIT_TAIL_NS" = "0" ] && [ "$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" = "0" ]; then
  suggest_out="$("$agent_bin" --config "$config_path" --suggest-queue-wait-quiet 2>/dev/null || true)"
  suggest_ns="$(printf '%s\n' "$suggest_out" | awk -F= '/^SLO_QUEUE_WAIT_TAIL_NS=/{print $2}' | tail -n1)"
  suggest_ratio="$(printf '%s\n' "$suggest_out" | awk -F= '/^SLO_QUEUE_WAIT_TAIL_MAX_RATIO=/{print $2}' | tail -n1)"
  if [ -n "$suggest_ns" ] && [ "$suggest_ns" != "0" ] && [ -n "$suggest_ratio" ] && [ "$suggest_ratio" != "0" ] && [ "$suggest_ratio" != "0.0000" ]; then
    SLO_QUEUE_WAIT_TAIL_NS="$suggest_ns"
    SLO_QUEUE_WAIT_TAIL_MAX_RATIO="$suggest_ratio"
    auto_queue_wait_source="secretive-agent"
    auto_queue_wait_profile="$SLO_PROFILE"
  fi

  if [ -z "$auto_queue_wait_source" ]; then
    set_queue_wait_defaults "$SLO_PROFILE"
    auto_queue_wait_source="profile-default"
  fi
fi

if [ -n "$auto_queue_wait_source" ]; then
  echo "auto queue-wait guardrail: source=$auto_queue_wait_source profile=$auto_queue_wait_profile tail_ns=$SLO_QUEUE_WAIT_TAIL_NS max_ratio=$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" >&2
fi

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

if [ -z "$rps" ] || [ -z "$ok" ] || [ -z "$failures" ]; then
  echo "failed to parse bench output" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

total="$(awk -v ok="$ok" -v failures="$failures" 'BEGIN { print ok + failures }')"
failure_rate="$(awk -v failures="$failures" -v total="$total" 'BEGIN { if (total == 0) print 1; else print failures / total }')"

if ! awk -v rps="$rps" -v min="$SLO_MIN_RPS" 'BEGIN { exit (rps + 0 >= min + 0 ? 0 : 1) }'; then
  echo "SLO failure: throughput below minimum (rps=$rps min=$SLO_MIN_RPS)" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

if [ "$SLO_MAX_P95_US" != "0" ]; then
  if [ -z "$p95_us" ]; then
    echo "SLO failure: latency stats missing (expected p95_us; ok=$ok failures=$failures rps=$rps)" >&2
    cat "$bench_json" >&2
    print_agent_log_tail
    exit 1
  fi
  if ! awk -v p95="$p95_us" -v max="$SLO_MAX_P95_US" 'BEGIN { exit (p95 + 0 <= max + 0 ? 0 : 1) }'; then
    echo "SLO failure: p95 latency above maximum (p95_us=$p95_us max=$SLO_MAX_P95_US)" >&2
    cat "$bench_json" >&2
    print_agent_log_tail
    exit 1
  fi
fi

if ! awk -v rate="$failure_rate" -v max="$SLO_MAX_FAILURE_RATE" 'BEGIN { exit (rate + 0 <= max + 0 ? 0 : 1) }'; then
  echo "SLO failure: failure rate above maximum (failure_rate=$failure_rate max=$SLO_MAX_FAILURE_RATE)" >&2
  cat "$bench_json" >&2
  print_agent_log_tail
  exit 1
fi

queue_wait_avg_ns=""
queue_wait_max_ns=""
queue_wait_tail_ratio=""
queue_wait_tail_count=""
queue_wait_tail_total=""
queue_wait_tail_mode=""
queue_wait_tail_percentile_label=""
queue_wait_tail_percentile_ns=""
queue_wait_tail_detail=""

# Prefer bench-emitted queue wait report (single source of truth) to avoid parsing agent snapshots.
queue_wait_avg_ns="$(grep -o '"queue_wait_avg_ns":[0-9.]*' "$bench_json" | head -n1 | cut -d: -f2)"
queue_wait_max_ns="$(grep -o '"queue_wait_max_ns":[0-9]*' "$bench_json" | head -n1 | cut -d: -f2)"

queue_wait_tail_check_required=0
if [ "$SLO_QUEUE_WAIT_TAIL_NS" != "0" ] && [ "$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" != "0" ]; then
  queue_wait_tail_check_required=1
fi

if [ "$queue_wait_tail_check_required" -eq 1 ]; then
  queue_wait_tail_mode="$(grep -Eo '"tail_mode":"[a-z_]+"' "$bench_json" | head -n1 | cut -d: -f2 | tr -d '"')"
  if [ -z "$queue_wait_tail_mode" ]; then
    echo "SLO failure: queue wait tail metrics missing (expected queue_wait.tail_mode)" >&2
    cat "$bench_json" >&2
    [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
    print_agent_log_tail
    exit 1
  fi

  if [ "$queue_wait_tail_mode" = "percentile" ]; then
    queue_wait_tail_percentile_label="$(
      grep -Eo '"tail_percentile":[{]"label":"[^"]+"' "$bench_json" | head -n1 | sed -E 's/.*"label":"([^"]+)".*/\1/'
    )"
    queue_wait_tail_percentile_ns="$(
      grep -Eo '"tail_percentile":[{][^}]*"ns":[0-9]+' "$bench_json" | head -n1 | sed -E 's/.*"ns":([0-9]+).*/\1/'
    )"
    queue_wait_tail_ratio="$(
      grep -Eo '"tail_percentile":[{][^}]*"derived_ratio":[0-9.]+' "$bench_json" | head -n1 | sed -E 's/.*"derived_ratio":([0-9.]+).*/\1/'
    )"
    queue_wait_tail_count="n/a"
    queue_wait_tail_total="n/a"
    queue_wait_tail_detail="${queue_wait_tail_percentile_label:-n/a}:${queue_wait_tail_percentile_ns:-n/a}"
  elif [ "$queue_wait_tail_mode" = "histogram" ]; then
    queue_wait_tail_ratio="$(
      grep -Eo '"tail_histogram":[{][^}]*"ratio":[0-9.]+' "$bench_json" | head -n1 | sed -E 's/.*"ratio":([0-9.]+).*/\1/'
    )"
    queue_wait_tail_count="$(
      grep -Eo '"tail_histogram":[{][^}]*"tail_count":[0-9]+' "$bench_json" | head -n1 | sed -E 's/.*"tail_count":([0-9]+).*/\1/'
    )"
    queue_wait_tail_total="$(
      grep -Eo '"tail_histogram":[{][^}]*"total":[0-9]+' "$bench_json" | head -n1 | sed -E 's/.*"total":([0-9]+).*/\1/'
    )"
    queue_wait_tail_detail="${queue_wait_tail_count:-n/a}/${queue_wait_tail_total:-n/a}"
  else
    echo "SLO failure: unrecognized queue wait tail mode (mode=$queue_wait_tail_mode)" >&2
    cat "$bench_json" >&2
    [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
    print_agent_log_tail
    exit 1
  fi
fi

if [ -n "$queue_wait_avg_ns" ] && [ "$SLO_MAX_QUEUE_WAIT_AVG_NS" != "0" ]; then
  if ! awk -v value="$queue_wait_avg_ns" -v max="$SLO_MAX_QUEUE_WAIT_AVG_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
    echo "SLO failure: queue wait avg above maximum (queue_wait_avg_ns=$queue_wait_avg_ns max=$SLO_MAX_QUEUE_WAIT_AVG_NS)" >&2
    cat "$bench_json" >&2
    [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
    print_agent_log_tail
    exit 1
  fi
fi

if [ -n "$queue_wait_max_ns" ] && [ "$SLO_MAX_QUEUE_WAIT_MAX_NS" != "0" ]; then
  if ! awk -v value="$queue_wait_max_ns" -v max="$SLO_MAX_QUEUE_WAIT_MAX_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
    echo "SLO failure: queue wait max above maximum (queue_wait_max_ns=$queue_wait_max_ns max=$SLO_MAX_QUEUE_WAIT_MAX_NS)" >&2
    cat "$bench_json" >&2
    [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
    print_agent_log_tail
    exit 1
  fi
fi

if [ "$queue_wait_tail_check_required" -eq 1 ]; then
  if [ "$queue_wait_tail_mode" = "percentile" ]; then
    if ! awk -v value="$queue_wait_tail_percentile_ns" -v max="$SLO_QUEUE_WAIT_TAIL_NS" 'BEGIN { exit (value + 0 <= max + 0 ? 0 : 1) }'; then
      echo "SLO failure: queue wait $queue_wait_tail_percentile_label exceeded tail threshold (value_ns=$queue_wait_tail_percentile_ns max_ns=$SLO_QUEUE_WAIT_TAIL_NS max_ratio=$SLO_QUEUE_WAIT_TAIL_MAX_RATIO)" >&2
      cat "$bench_json" >&2
      [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
      print_agent_log_tail
      exit 1
    fi
  elif [ "$queue_wait_tail_mode" = "histogram" ]; then
    if [ -z "$queue_wait_tail_ratio" ] || [ -z "$queue_wait_tail_total" ]; then
      echo "SLO failure: queue wait tail thresholds require metrics histogram" >&2
      [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
      print_agent_log_tail
      exit 1
    fi
    if ! awk -v ratio="$queue_wait_tail_ratio" -v max="$SLO_QUEUE_WAIT_TAIL_MAX_RATIO" 'BEGIN { exit (ratio + 0 <= max + 0 ? 0 : 1) }'; then
      echo "SLO failure: queue wait tail ratio above maximum (threshold_ns=$SLO_QUEUE_WAIT_TAIL_NS tail_ratio=$queue_wait_tail_ratio count=$queue_wait_tail_count total=$queue_wait_tail_total max_ratio=$SLO_QUEUE_WAIT_TAIL_MAX_RATIO)" >&2
      cat "$bench_json" >&2
      [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
      print_agent_log_tail
      exit 1
    fi
  else
    echo "SLO failure: queue wait tail metrics missing" >&2
    [ -f "$metrics_json" ] && cat "$metrics_json" >&2 || true
    print_agent_log_tail
    exit 1
  fi
fi

if [ -z "$queue_wait_tail_detail" ]; then
  queue_wait_tail_detail="n/a"
fi

echo "slo gate passed: concurrency=$SLO_CONCURRENCY duration=${SLO_DURATION_SECS}s spread_ms=$SLO_WORKER_START_SPREAD_MS rps=$rps p95_us=$p95_us failure_rate=$failure_rate queue_wait_avg_ns=${queue_wait_avg_ns:-n/a} queue_wait_max_ns=${queue_wait_max_ns:-n/a} queue_wait_tail_ratio=${queue_wait_tail_ratio:-n/a} queue_wait_tail_source=${queue_wait_tail_mode:-n/a} queue_wait_tail_detail=$queue_wait_tail_detail"
