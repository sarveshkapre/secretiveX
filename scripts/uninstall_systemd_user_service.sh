#!/usr/bin/env sh
set -eu

service_name="secretivex-agent.service"

if [ "${1:-}" = "--service-name" ]; then
  [ "${2:-}" ] || { echo "missing value for --service-name" >&2; exit 1; }
  service_name="$2"
fi

command -v systemctl >/dev/null 2>&1 || {
  echo "systemctl is required" >&2
  exit 1
}

service_path="${HOME}/.config/systemd/user/${service_name}"

if systemctl --user is-enabled "$service_name" >/dev/null 2>&1; then
  systemctl --user disable --now "$service_name"
else
  systemctl --user stop "$service_name" >/dev/null 2>&1 || true
fi

rm -f "$service_path"
systemctl --user daemon-reload

echo "removed: $service_path"
