#!/usr/bin/env bash
set -euo pipefail

AGENT_BIN=${SECRETIVE_AGENT_BIN:-target/debug/secretive-agent}
CLIENT_BIN=${SECRETIVE_CLIENT_BIN:-target/debug/secretive-client}

if [[ ! -x "$AGENT_BIN" || ! -x "$CLIENT_BIN" ]]; then
  echo "[confirm-smoke] building Rust tools" >&2
  cargo build -p secretive-agent -p secretive-client >/dev/null
fi

if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "[confirm-smoke] ssh-keygen is required" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[confirm-smoke] python3 is required" >&2
  exit 2
fi

TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t secretivex-confirm-smoke)
cleanup() {
  if [[ -n "${AGENT_PID:-}" ]]; then
    kill "$AGENT_PID" >/dev/null 2>&1 || true
    wait "$AGENT_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMPDIR" || true
}
trap cleanup EXIT

KEY="$TMPDIR/id_ed25519"
SOCK="$TMPDIR/agent.sock"
CFG="$TMPDIR/agent.json"
LOG="$TMPDIR/agent.log"

ssh-keygen -t ed25519 -N "" -f "$KEY" >/dev/null 2>&1

cat >"$CFG" <<JSON
{
  "socket_path": "$SOCK",
  "stores": [
    {"type": "file", "paths": ["$KEY"], "scan_default_dir": false}
  ],
  "policy": {
    "confirm_command": ["/usr/bin/false"],
    "confirm_timeout_ms": 2000,
    "confirm_cache_ms": 0
  },
  "metrics_every": 0
}
JSON

"$AGENT_BIN" --check-config --config "$CFG" >/dev/null
"$AGENT_BIN" --config "$CFG" >"$LOG" 2>&1 &
AGENT_PID=$!

sleep 0.5

BLOB_HEX=$("$CLIENT_BIN" --socket "$SOCK" --list --json-compact | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["key_blob_hex"])')

set +e
echo -n hello | "$CLIENT_BIN" --socket "$SOCK" --sign "$BLOB_HEX" --json-compact >/dev/null 2>&1
RC=$?
set -e

if [[ "$RC" -eq 0 ]]; then
  echo "[confirm-smoke] expected deny (non-zero), but sign succeeded" >&2
  exit 1
fi

kill "$AGENT_PID" >/dev/null 2>&1 || true
wait "$AGENT_PID" >/dev/null 2>&1 || true
unset AGENT_PID

# Swap deny -> allow and verify sign succeeds.
perl -0pe 's#"/usr/bin/false"#"/usr/bin/true"#' -i "$CFG"

"$AGENT_BIN" --check-config --config "$CFG" >/dev/null
"$AGENT_BIN" --config "$CFG" >"$LOG" 2>&1 &
AGENT_PID=$!

sleep 0.5

echo -n hello | "$CLIENT_BIN" --socket "$SOCK" --sign "$BLOB_HEX" --json-compact >/dev/null

echo "[confirm-smoke] ok" >&2
