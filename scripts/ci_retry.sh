#!/usr/bin/env sh
set -eu

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <attempts> <command> [args...]" >&2
  exit 2
fi

attempts="$1"
shift

case "$attempts" in
  ''|*[!0-9]*)
    echo "attempts must be a positive integer" >&2
    exit 2
    ;;
esac

if [ "$attempts" -lt 1 ]; then
  echo "attempts must be >= 1" >&2
  exit 2
fi

attempt=1
while [ "$attempt" -le "$attempts" ]; do
  echo "[ci-retry] attempt $attempt/$attempts: $*"
  if "$@"; then
    exit 0
  fi
  if [ "$attempt" -ge "$attempts" ]; then
    echo "[ci-retry] command failed after $attempts attempt(s)" >&2
    exit 1
  fi
  sleep_secs=$((attempt * 2))
  echo "[ci-retry] retrying after ${sleep_secs}s..."
  sleep "$sleep_secs"
  attempt=$((attempt + 1))
done
