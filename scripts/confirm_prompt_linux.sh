#!/usr/bin/env sh
set -eu

# Example Linux GUI prompt for `policy.confirm_command`.
#
# Requirements (pick one):
# - zenity (GNOME/GTK)
# - kdialog (KDE/Qt)
#
# Behavior:
# - Exit 0 to allow signing
# - Exit 1 to deny signing (including if no prompt tool is installed)

key_id="${SECRETIVE_CONFIRM_KEY_ID:-}"
fingerprint="${SECRETIVE_CONFIRM_KEY_FINGERPRINT:-}"
comment="${SECRETIVE_CONFIRM_KEY_COMMENT:-}"
flags="${SECRETIVE_CONFIRM_FLAGS:-}"
data_len="${SECRETIVE_CONFIRM_DATA_LEN:-}"

message="$(printf '%s\n\n%s\n%s\n%s\n%s\n%s\n' \
  'Allow SSH signing request?' \
  "Key: ${key_id}" \
  "Fingerprint: ${fingerprint}" \
  "Comment: ${comment}" \
  "Flags: ${flags}" \
  "Data length: ${data_len}")"

title="SecretiveX"

if command -v zenity >/dev/null 2>&1; then
  if zenity --question --title="$title" --text="$message" --ok-label="Allow" --cancel-label="Deny"; then
    exit 0
  fi
  exit 1
fi

if command -v kdialog >/dev/null 2>&1; then
  if kdialog --title "$title" --yesno "$message" --yes-label "Allow" --no-label "Deny"; then
    exit 0
  fi
  exit 1
fi

echo "[confirm-prompt] need zenity or kdialog; denying" >&2
exit 1

