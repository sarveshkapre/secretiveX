#!/usr/bin/env sh
set -eu

UPDATER_FILE="Sources/SecretiveUpdater/SecretiveUpdater.swift"
EXPECTED_UPDATER_URL="https://api.github.com/repos/sarveshkapre/secretiveX/releases"

if [ ! -f "$UPDATER_FILE" ]; then
  echo "[repo-sanity] missing $UPDATER_FILE" >&2
  exit 1
fi

if ! grep -q "$EXPECTED_UPDATER_URL" "$UPDATER_FILE"; then
  echo "[repo-sanity] expected updater URL not found in $UPDATER_FILE" >&2
  echo "[repo-sanity] expected: $EXPECTED_UPDATER_URL" >&2
  exit 1
fi

# Prevent accidental regressions to upstream repo URLs in code/workflows/scripts.
# Note: we deliberately ignore docs/trackers where this string may appear as commentary.
if rg -n --pcre2 "sarveshkapre/secretive([^X]|$)" --hidden --glob '!.git/*' --glob '!**/*.md' --glob '!scripts/repo_sanity.sh' >/dev/null 2>&1; then
  echo "[repo-sanity] found stale repo reference(s):" >&2
  rg -n --pcre2 "sarveshkapre/secretive([^X]|$)" --hidden --glob '!.git/*' --glob '!**/*.md' --glob '!scripts/repo_sanity.sh' >&2 || true
  exit 1
fi

echo "[repo-sanity] ok"
