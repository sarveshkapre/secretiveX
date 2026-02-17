#!/usr/bin/env bash
set -euo pipefail

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if has_cmd softhsm2-util && has_cmd pkcs11-tool; then
  echo "[pkcs11-deps] SoftHSM and OpenSC already present"
  exit 0
fi

os="$(uname -s)"
case "$os" in
  Linux)
    if has_cmd apt-get; then
      if has_cmd sudo; then
        sudo apt-get update
        sudo apt-get install -y softhsm2 opensc
      elif [ "$(id -u)" -eq 0 ]; then
        apt-get update
        apt-get install -y softhsm2 opensc
      else
        echo "[pkcs11-deps] apt-get available but no sudo/root privileges" >&2
        exit 1
      fi
    else
      echo "[pkcs11-deps] unsupported Linux distro: please install softhsm2 + opensc manually" >&2
      exit 1
    fi
    ;;
  Darwin)
    if has_cmd brew; then
      brew update
      brew install softhsm opensc
    else
      echo "[pkcs11-deps] Homebrew is required on macOS for CI pkcs11 smoke" >&2
      exit 1
    fi
    ;;
  *)
    echo "[pkcs11-deps] unsupported OS: $os" >&2
    exit 1
    ;;
esac

if ! has_cmd softhsm2-util || ! has_cmd pkcs11-tool; then
  echo "[pkcs11-deps] install step finished but tools are still missing" >&2
  exit 1
fi

echo "[pkcs11-deps] installed successfully"
