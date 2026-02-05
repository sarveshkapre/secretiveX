#!/usr/bin/env sh
set -eu

usage() {
  cat <<USAGE
Usage: install_systemd_user_service.sh [options]

Options:
  --binary <path>        Path to secretive-agent binary (default: from PATH)
  --config <path>        Agent config path (default: ~/.config/secretive/agent.json)
  --service-name <name>  systemd user unit filename (default: secretivex-agent.service)
  --no-start             Install unit but do not enable/start it
  --help                 Show this help
USAGE
}

binary_path=""
config_path="${HOME}/.config/secretive/agent.json"
service_name="secretivex-agent.service"
start_service=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary)
      shift
      [ "$#" -gt 0 ] || { echo "missing value for --binary" >&2; exit 1; }
      binary_path="$1"
      ;;
    --config)
      shift
      [ "$#" -gt 0 ] || { echo "missing value for --config" >&2; exit 1; }
      config_path="$1"
      ;;
    --service-name)
      shift
      [ "$#" -gt 0 ] || { echo "missing value for --service-name" >&2; exit 1; }
      service_name="$1"
      ;;
    --no-start)
      start_service=0
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

command -v systemctl >/dev/null 2>&1 || {
  echo "systemctl is required" >&2
  exit 1
}

if [ -z "$binary_path" ]; then
  binary_path="$(command -v secretive-agent || true)"
fi

[ -n "$binary_path" ] || {
  echo "secretive-agent binary not found; pass --binary" >&2
  exit 1
}

[ -x "$binary_path" ] || {
  echo "binary is not executable: $binary_path" >&2
  exit 1
}

case "$binary_path" in
  *" "*)
    echo "binary path with spaces is not supported: $binary_path" >&2
    exit 1
    ;;
esac

case "$config_path" in
  *" "*)
    echo "config path with spaces is not supported: $config_path" >&2
    exit 1
    ;;
esac

template_path="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/packaging/systemd/secretivex-agent.service.tmpl"
[ -f "$template_path" ] || {
  echo "missing service template: $template_path" >&2
  exit 1
}

systemd_user_dir="${HOME}/.config/systemd/user"
service_path="${systemd_user_dir}/${service_name}"
config_dir="$(dirname "$config_path")"

mkdir -p "$systemd_user_dir" "$config_dir"

if [ ! -f "$config_path" ]; then
  cat > "$config_path" <<'JSON'
{
  "stores": [
    {
      "type": "file",
      "scan_default_dir": true
    }
  ],
  "watch_files": true,
  "identity_cache_ms": 1000
}
JSON
  echo "created default config: $config_path"
fi

"$binary_path" --check-config --config "$config_path"

sed \
  -e "s#__BINARY__#${binary_path}#g" \
  -e "s#__CONFIG__#${config_path}#g" \
  "$template_path" > "$service_path"

systemctl --user daemon-reload

if [ "$start_service" -eq 1 ]; then
  systemctl --user enable --now "$service_name"
else
  echo "installed unit: $service_path"
  echo "to enable now: systemctl --user enable --now $service_name"
fi

echo ""
echo "set SSH_AUTH_SOCK in your shell profile:"
echo "  export SSH_AUTH_SOCK=\"\$XDG_RUNTIME_DIR/secretive/agent.sock\""
echo ""
echo "check status:"
echo "  systemctl --user status $service_name"
