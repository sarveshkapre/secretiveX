#!/usr/bin/env sh
set -eu

# Long-duration stress envelope over multiple host-load tiers.
# Each case runs soak_test with strict queue-wait requirements.

STRESS_CASES="${STRESS_CASES:-host512,host1024,host1536}"
STRESS_OUTPUT_DIR="${STRESS_OUTPUT_DIR:-$(pwd)/target/multi-host-stress}"

set_case_defaults() {
  case "$1" in
    host512)
      CASE_DURATION_SECS=1200
      CASE_CONCURRENCY=512
      CASE_WORKER_START_SPREAD_MS=2500
      CASE_MIN_RPS=20
      CASE_MAX_P95_US=280000
      CASE_MAX_FAILURE_RATE=0.005
      CASE_MAX_QUEUE_WAIT_AVG_NS=25000000
      CASE_MAX_QUEUE_WAIT_MAX_NS=250000000
      ;;
    host1024)
      CASE_DURATION_SECS=1200
      CASE_CONCURRENCY=1024
      CASE_WORKER_START_SPREAD_MS=4000
      CASE_MIN_RPS=14
      CASE_MAX_P95_US=330000
      CASE_MAX_FAILURE_RATE=0.01
      CASE_MAX_QUEUE_WAIT_AVG_NS=45000000
      CASE_MAX_QUEUE_WAIT_MAX_NS=450000000
      ;;
    host1536)
      CASE_DURATION_SECS=900
      CASE_CONCURRENCY=1536
      CASE_WORKER_START_SPREAD_MS=6000
      CASE_MIN_RPS=8
      CASE_MAX_P95_US=420000
      CASE_MAX_FAILURE_RATE=0.015
      CASE_MAX_QUEUE_WAIT_AVG_NS=70000000
      CASE_MAX_QUEUE_WAIT_MAX_NS=700000000
      ;;
    *)
      echo "unknown stress case: $1" >&2
      exit 2
      ;;
  esac
}

apply_overrides() {
  CASE_DURATION_SECS="${STRESS_DURATION_SECS:-$CASE_DURATION_SECS}"
  CASE_CONCURRENCY="${STRESS_CONCURRENCY:-$CASE_CONCURRENCY}"
  CASE_WORKER_START_SPREAD_MS="${STRESS_WORKER_START_SPREAD_MS:-$CASE_WORKER_START_SPREAD_MS}"
  CASE_MIN_RPS="${STRESS_MIN_RPS:-$CASE_MIN_RPS}"
  CASE_MAX_P95_US="${STRESS_MAX_P95_US:-$CASE_MAX_P95_US}"
  CASE_MAX_FAILURE_RATE="${STRESS_MAX_FAILURE_RATE:-$CASE_MAX_FAILURE_RATE}"
  CASE_MAX_QUEUE_WAIT_AVG_NS="${STRESS_MAX_QUEUE_WAIT_AVG_NS:-$CASE_MAX_QUEUE_WAIT_AVG_NS}"
  CASE_MAX_QUEUE_WAIT_MAX_NS="${STRESS_MAX_QUEUE_WAIT_MAX_NS:-$CASE_MAX_QUEUE_WAIT_MAX_NS}"
}

mkdir -p "$STRESS_OUTPUT_DIR"
summary_file="$STRESS_OUTPUT_DIR/summary.txt"
printf "" > "$summary_file"

echo "[multi-host-stress] output_dir=$STRESS_OUTPUT_DIR"

old_ifs="$IFS"
IFS=','
set -- $STRESS_CASES
IFS="$old_ifs"

for case_name in "$@"; do
  set_case_defaults "$case_name"
  apply_overrides

  case_output_json="$STRESS_OUTPUT_DIR/$case_name-soak.json"
  case_output_metrics="$STRESS_OUTPUT_DIR/$case_name-metrics.json"

  echo "[multi-host-stress] case=$case_name duration=${CASE_DURATION_SECS}s concurrency=$CASE_CONCURRENCY spread_ms=$CASE_WORKER_START_SPREAD_MS"

  SOAK_PROFILE="${SOAK_PROFILE:-pssh}" \
  SOAK_DURATION_SECS="$CASE_DURATION_SECS" \
  SOAK_CONCURRENCY="$CASE_CONCURRENCY" \
  SOAK_WORKER_START_SPREAD_MS="$CASE_WORKER_START_SPREAD_MS" \
  SOAK_MIN_RPS="$CASE_MIN_RPS" \
  SOAK_MAX_P95_US="$CASE_MAX_P95_US" \
  SOAK_MAX_FAILURE_RATE="$CASE_MAX_FAILURE_RATE" \
  SOAK_MAX_QUEUE_WAIT_AVG_NS="$CASE_MAX_QUEUE_WAIT_AVG_NS" \
  SOAK_MAX_QUEUE_WAIT_MAX_NS="$CASE_MAX_QUEUE_WAIT_MAX_NS" \
  SOAK_REQUIRE_QUEUE_WAIT_METRICS=1 \
  SOAK_OUTPUT_JSON="$case_output_json" \
  SOAK_OUTPUT_METRICS="$case_output_metrics" \
  ./scripts/soak_test.sh

  printf "%s %s %s %s %s %s\n" \
    "$case_name" \
    "duration=${CASE_DURATION_SECS}s" \
    "concurrency=$CASE_CONCURRENCY" \
    "queue_wait_avg_max_ns=$CASE_MAX_QUEUE_WAIT_AVG_NS" \
    "queue_wait_max_max_ns=$CASE_MAX_QUEUE_WAIT_MAX_NS" \
    "json=$case_output_json" >> "$summary_file"
done

echo "[multi-host-stress] all cases passed"
cat "$summary_file"
