#!/usr/bin/env sh
set -eu

# Example macOS GUI prompt for `policy.confirm_command`.
#
# Requirements:
# - A logged-in GUI session (osascript needs access to WindowServer).
#
# Behavior:
# - Exit 0 to allow signing
# - Exit 1 to deny signing (including on prompt errors/cancel)

if ! command -v osascript >/dev/null 2>&1; then
  echo "[confirm-prompt] osascript not found; denying" >&2
  exit 1
fi

result="$(
  osascript <<'APPLESCRIPT'
on getenv(name)
  try
    return system attribute name
  on error
    return ""
  end try
end getenv

on run
  set titleText to "SecretiveX"
  set keyId to getenv("SECRETIVE_CONFIRM_KEY_ID")
  set fingerprint to getenv("SECRETIVE_CONFIRM_KEY_FINGERPRINT")
  set commentText to getenv("SECRETIVE_CONFIRM_KEY_COMMENT")
  set flagsText to getenv("SECRETIVE_CONFIRM_FLAGS")
  set dataLenText to getenv("SECRETIVE_CONFIRM_DATA_LEN")

  set msg to "Allow SSH signing request?"
  if keyId is not "" then set msg to msg & return & return & "Key: " & keyId
  if fingerprint is not "" then set msg to msg & return & "Fingerprint: " & fingerprint
  if commentText is not "" then set msg to msg & return & "Comment: " & commentText
  if flagsText is not "" then set msg to msg & return & "Flags: " & flagsText
  if dataLenText is not "" then set msg to msg & return & "Data length: " & dataLenText

  display dialog msg with title titleText buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" with icon caution
  return button returned of result
end run
APPLESCRIPT
)" || {
  echo "[confirm-prompt] osascript prompt failed; denying" >&2
  exit 1
}

if [ "$result" = "Allow" ]; then
  exit 0
fi

exit 1

