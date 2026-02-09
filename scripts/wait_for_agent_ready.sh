#!/usr/bin/env sh
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <socket_path> <agent_pid> <agent_log_path> [timeout_secs]" >&2
  exit 2
fi

socket_path="$1"
agent_pid="$2"
agent_log_path="$3"
timeout_secs="${4:-${AGENT_STARTUP_TIMEOUT_SECS:-90}}"

case "$timeout_secs" in
  ''|*[!0-9]*)
    echo "invalid timeout_secs: $timeout_secs (expected non-negative integer)" >&2
    exit 2
    ;;
esac

print_agent_log_tail() {
  if [ -f "$agent_log_path" ] && [ -s "$agent_log_path" ]; then
    echo "---- agent startup log (tail -n 80) ----" >&2
    tail -n 80 "$agent_log_path" >&2 || true
    echo "---- end agent startup log ----" >&2
  else
    echo "agent startup log unavailable at: $agent_log_path" >&2
  fi
}

if [ -n "$agent_pid" ] && ! kill -0 "$agent_pid" >/dev/null 2>&1; then
  echo "agent process is not running (pid=$agent_pid)" >&2
  print_agent_log_tail
  exit 1
fi

deadline_epoch="$(($(date +%s) + timeout_secs))"
ready=0

while :; do
  if [ -n "$agent_pid" ] && ! kill -0 "$agent_pid" >/dev/null 2>&1; then
    echo "agent exited before becoming ready (pid=$agent_pid)" >&2
    print_agent_log_tail
    exit 1
  fi

  if [ -S "$socket_path" ]; then
    if [ -n "${SECRETIVE_CLIENT_BIN:-}" ] && [ -x "${SECRETIVE_CLIENT_BIN:-}" ]; then
      if "$SECRETIVE_CLIENT_BIN" --socket "$socket_path" --list --raw >/dev/null 2>&1; then
        ready=1
        break
      fi
    elif cargo run -p secretive-client -- --socket "$socket_path" --list --raw >/dev/null 2>&1; then
      ready=1
      break
    fi
  fi

  now_epoch="$(date +%s)"
  if [ "$now_epoch" -ge "$deadline_epoch" ]; then
    break
  fi
  sleep 0.2
done

if [ "$ready" -ne 1 ]; then
  echo "agent failed to become ready within ${timeout_secs}s (socket=$socket_path pid=$agent_pid)" >&2
  print_agent_log_tail
  exit 1
fi
