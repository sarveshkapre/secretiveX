#!/usr/bin/env sh
set -eu

PKCS11_SMOKE_REQUIRE_TOOLS="${PKCS11_SMOKE_REQUIRE_TOOLS:-0}"
PKCS11_TOKEN_LABEL="${PKCS11_TOKEN_LABEL:-secretivex-smoke}"
PKCS11_LABEL="${PKCS11_LABEL:-secretivex-smoke-key}"
PKCS11_PIN="${PKCS11_PIN:-123456}"
PKCS11_SO_PIN="${PKCS11_SO_PIN:-123456}"

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

need_cmd() {
  cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  if [ "$PKCS11_SMOKE_REQUIRE_TOOLS" = "1" ]; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
  echo "pkcs11 smoke skipped: missing command: $cmd"
  exit 0
}

need_cmd softhsm2-util
need_cmd pkcs11-tool
need_cmd ssh-keygen

module_path=""
for candidate in \
  /usr/lib/softhsm/libsofthsm2.so \
  /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  /opt/homebrew/lib/softhsm/libsofthsm2.so \
  /usr/local/lib/softhsm/libsofthsm2.so
do
  if [ -f "$candidate" ]; then
    module_path="$candidate"
    break
  fi
done

if [ -z "$module_path" ]; then
  if [ "$PKCS11_SMOKE_REQUIRE_TOOLS" = "1" ]; then
    echo "pkcs11 module not found (libsofthsm2.so)" >&2
    exit 1
  fi
  echo "pkcs11 smoke skipped: module not found"
  exit 0
fi

token_dir="$tmpdir/tokens"
mkdir -p "$token_dir"

softhsm_conf="$tmpdir/softhsm2.conf"
cat > "$softhsm_conf" <<CONF
directories.tokendir = $token_dir
objectstore.backend = file
slots.removable = false
CONF

export SOFTHSM2_CONF="$softhsm_conf"
export PKCS11_PIN

softhsm2-util --init-token --free \
  --label "$PKCS11_TOKEN_LABEL" \
  --pin "$PKCS11_PIN" \
  --so-pin "$PKCS11_SO_PIN" >/dev/null

slot="$(
  softhsm2-util --show-slots | awk -v label="$PKCS11_TOKEN_LABEL" '
    /^Slot[[:space:]]+[0-9]+/ { current=$2 }
    /Label:[[:space:]]*/ {
      value=$0
      sub(/^.*Label:[[:space:]]*/, "", value)
      gsub(/[[:space:]]+$/, "", value)
      if (value == label) {
        print current
        exit
      }
    }
  '
)"

if [ -z "$slot" ]; then
  echo "failed to resolve SoftHSM slot for token: $PKCS11_TOKEN_LABEL" >&2
  exit 1
fi

pkcs11-tool \
  --module "$module_path" \
  --slot "$slot" \
  --login --pin "$PKCS11_PIN" \
  --keypairgen --key-type rsa:2048 \
  --id 01 \
  --label "$PKCS11_LABEL" >/dev/null

config_path="$tmpdir/agent.json"
socket_path="$tmpdir/agent.sock"
payload_path="$tmpdir/payload.bin"

cat > "$config_path" <<JSON
{
  "stores": [
    {
      "type": "pkcs11",
      "module_path": "$module_path",
      "slot": $slot,
      "pin_env": "PKCS11_PIN",
      "refresh_min_interval_ms": 0
    }
  ],
  "watch_files": false,
  "metrics_every": 0,
  "metrics_interval_ms": 1000
}
JSON

cargo run -p secretive-agent --features pkcs11 -- \
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
  echo "pkcs11 smoke: agent failed to become ready" >&2
  exit 1
fi

if ! cargo run -p secretive-client -- --socket "$socket_path" --list --raw | grep -q "$PKCS11_LABEL"; then
  echo "pkcs11 smoke: expected key label not found in identity list" >&2
  cargo run -p secretive-client -- --socket "$socket_path" --list --raw >&2 || true
  exit 1
fi

printf "pkcs11-smoke-payload\n" > "$payload_path"
cargo run -p secretive-client -- \
  --socket "$socket_path" \
  --comment "$PKCS11_LABEL" \
  --data "$payload_path" \
  --flags sha256 >/dev/null

echo "pkcs11 smoke passed: slot=$slot module=$module_path label=$PKCS11_LABEL"
