#!/bin/bash

set -euo pipefail

missing=()
for v in SIGNING_DATA SIGNING_PASSWORD HOST_PROFILE_DATA AGENT_PROFILE_DATA APPLE_API_KEY_DATA APPLE_API_KEY_ID; do
  if [[ -z "${!v:-}" ]]; then
    missing+=("$v")
  fi
done

signing_enabled=false
if ((${#missing[@]} > 0)); then
  echo "Signing not configured (missing: ${missing[*]}). Skipping signing setup."
else
  signing_enabled=true

  # Import certificate and private key
  printf '%s' "$SIGNING_DATA" | base64 -d -o Signing.p12
  security create-keychain -p ci ci.keychain
  security default-keychain -s ci.keychain
  security list-keychains -s ci.keychain
  security import ./Signing.p12 -k ci.keychain -P "$SIGNING_PASSWORD" -A
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k ci ci.keychain

  # Import Profiles
  mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
  printf '%s' "$HOST_PROFILE_DATA" | base64 -d -o Host.provisionprofile
  HOST_UUID=$(grep UUID -A1 -a Host.provisionprofile | grep -io "[-A-F0-9]\\{36\\}" | head -n 1)
  cp Host.provisionprofile ~/Library/MobileDevice/Provisioning\ Profiles/"$HOST_UUID".provisionprofile
  printf '%s' "$AGENT_PROFILE_DATA" | base64 -d -o Agent.provisionprofile
  AGENT_UUID=$(grep UUID -A1 -a Agent.provisionprofile | grep -io "[-A-F0-9]\\{36\\}" | head -n 1)
  cp Agent.provisionprofile ~/Library/MobileDevice/Provisioning\ Profiles/"$AGENT_UUID".provisionprofile

  # Create directories for ASC key
  mkdir -p ~/.private_keys
  printf '%s' "$APPLE_API_KEY_DATA" > ~/.private_keys/AuthKey_"$APPLE_API_KEY_ID".p8
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "signing_enabled=$signing_enabled" >> "$GITHUB_OUTPUT"
fi
