#!/usr/bin/env sh
set -eu

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

command -v ssh-add >/dev/null 2>&1 || {
  echo "ssh-add is required" >&2
  exit 1
}

command -v ssh-keygen >/dev/null 2>&1 || {
  echo "ssh-keygen is required" >&2
  exit 1
}

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
  "identity_cache_ms": 1000
}
JSON

cargo run -p secretive-agent -- \
  --config "$config_path" \
  --socket "$socket_path" \
  --no-watch \
  --metrics-every 0 >/dev/null 2>&1 &
agent_pid="$!"

ready=0
for _ in $(seq 1 100); do
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

export SSH_AUTH_SOCK="$socket_path"

# List flow: OpenSSH client should list agent identities.
list_out="$tmpdir/list.txt"
if ! ssh-add -L > "$list_out" 2>&1; then
  echo "ssh-add -L failed" >&2
  cat "$list_out" >&2
  exit 1
fi
if ! grep -q '^ssh-ed25519 ' "$list_out"; then
  echo "ssh-add -L did not return expected ed25519 identity" >&2
  cat "$list_out" >&2
  exit 1
fi

# Sign flow: OpenSSH client challenge-sign/verify through the agent.
sign_out="$tmpdir/sign.txt"
if ! ssh-add -T "$key_path.pub" > "$sign_out" 2>&1; then
  echo "ssh-add -T failed" >&2
  cat "$sign_out" >&2
  exit 1
fi

# Error flow: remove is intentionally unsupported; OpenSSH should surface failure.
remove_out="$tmpdir/remove.txt"
if ssh-add -d "$key_path" > "$remove_out" 2>&1; then
  echo "ssh-add -d unexpectedly succeeded; expected unsupported operation" >&2
  cat "$remove_out" >&2
  exit 1
fi

echo "openssh compatibility smoke passed"
