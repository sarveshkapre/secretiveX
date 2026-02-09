#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AGENT_STARTUP_TIMEOUT_SECS="${AGENT_STARTUP_TIMEOUT_SECS:-90}"

repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

echo "[openssh-compat] building Rust tools" >&2
cargo build -p secretive-agent -p secretive-client

agent_bin="$repo_root/target/debug/secretive-agent"
client_bin="$repo_root/target/debug/secretive-client"
export SECRETIVE_CLIENT_BIN="$client_bin"

tmpdir="$(mktemp -d)"
agent_pid=""
agent_log="$tmpdir/agent.log"
OPENSSH_KEY_TYPES="${OPENSSH_KEY_TYPES:-ed25519,rsa,ecdsa}"
OPENSSH_RSA_BITS="${OPENSSH_RSA_BITS:-3072}"
OPENSSH_SIGN_KEY_TYPES="${OPENSSH_SIGN_KEY_TYPES:-ed25519,ecdsa}"

contains_csv() {
  csv="$1"
  needle="$2"
  case ",$csv," in
    *,"$needle",*) return 0 ;;
    *) return 1 ;;
  esac
}

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
key_paths=""
first_key_path=""

old_ifs="$IFS"
IFS=','
sign_key_types="$(echo "$OPENSSH_SIGN_KEY_TYPES" | tr -d '[:space:]')"
for key_type in $OPENSSH_KEY_TYPES; do
  key_type="$(echo "$key_type" | tr -d '[:space:]')"
  [ -n "$key_type" ] || continue
  key_path="$tmpdir/id_${key_type}"
  case "$key_type" in
    ed25519)
      ssh-keygen -t ed25519 -N "" -f "$key_path" >/dev/null
      ;;
    rsa)
      ssh-keygen -t rsa -b "$OPENSSH_RSA_BITS" -N "" -f "$key_path" >/dev/null
      ;;
    ecdsa)
      ssh-keygen -t ecdsa -b 256 -N "" -f "$key_path" >/dev/null
      ;;
    *)
      echo "unsupported key type: $key_type" >&2
      exit 1
      ;;
  esac
  if [ -n "$key_paths" ]; then
    key_paths="$key_paths, "
  fi
  key_paths="$key_paths\"$key_path\""
  if [ -z "$first_key_path" ]; then
    first_key_path="$key_path"
  fi
done
IFS="$old_ifs"

if [ -z "$key_paths" ]; then
  echo "no key types requested" >&2
  exit 1
fi

cat > "$config_path" <<JSON
{
  "stores": [
    {
      "type": "file",
      "paths": [$key_paths],
      "scan_default_dir": false
    }
  ],
  "watch_files": false,
  "metrics_every": 0,
  "identity_cache_ms": 1000
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

export SSH_AUTH_SOCK="$socket_path"

# List flow: OpenSSH client should list agent identities.
list_out="$tmpdir/list.txt"
if ! ssh-add -L > "$list_out" 2>&1; then
  echo "ssh-add -L failed" >&2
  cat "$list_out" >&2
  exit 1
fi
old_ifs="$IFS"
IFS=','
for key_type in $OPENSSH_KEY_TYPES; do
  key_type="$(echo "$key_type" | tr -d '[:space:]')"
  [ -n "$key_type" ] || continue
  case "$key_type" in
    ed25519)
      pattern='^ssh-ed25519 '
      ;;
    rsa)
      pattern='^ssh-rsa '
      ;;
    ecdsa)
      pattern='^ecdsa-sha2-nistp256 '
      ;;
    *)
      echo "unsupported key type in list/sign verification: $key_type" >&2
      exit 1
      ;;
  esac
  if ! grep -q "$pattern" "$list_out"; then
    echo "ssh-add -L missing expected identity type: $key_type" >&2
    cat "$list_out" >&2
    exit 1
  fi

  if contains_csv "$sign_key_types" "$key_type"; then
    key_path="$tmpdir/id_${key_type}"
    sign_out="$tmpdir/sign_${key_type}.txt"
    if ! ssh-add -T "$key_path.pub" > "$sign_out" 2>&1; then
      echo "ssh-add -T failed for key type: $key_type" >&2
      cat "$sign_out" >&2
      exit 1
    fi
  else
    echo "skipping sign flow for key type: $key_type"
  fi
done
IFS="$old_ifs"

# Error flow: remove is intentionally unsupported; OpenSSH should surface failure.
remove_out="$tmpdir/remove.txt"
if ssh-add -d "$first_key_path" > "$remove_out" 2>&1; then
  echo "ssh-add -d unexpectedly succeeded; expected unsupported operation" >&2
  cat "$remove_out" >&2
  exit 1
fi

echo "openssh compatibility smoke passed: key_types=$OPENSSH_KEY_TYPES"
