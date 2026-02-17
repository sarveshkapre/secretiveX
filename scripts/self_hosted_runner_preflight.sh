#!/usr/bin/env sh
set -eu

profile="${1:-all}"
os="$(uname -s)"
missing=0

need_cmd() {
  cmd="$1"
  note="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[missing] $cmd ($note)" >&2
    missing=1
  else
    echo "[ok] $cmd"
  fi
}

check_common() {
  need_cmd git "source checkout"
  need_cmd cargo "Rust build/test"
  need_cmd ssh-keygen "OpenSSH smoke and gate scripts"
  need_cmd awk "gate script parsing"
  need_cmd sed "gate script parsing"
}

check_macos() {
  need_cmd xcrun "Xcode command tools"
  need_cmd xcodebuild "Swift/macOS jobs"
  if xcrun --find notarytool >/dev/null 2>&1; then
    echo "[ok] notarytool (via xcrun)"
  else
    echo "[missing] notarytool (release/nightly notarization)" >&2
    missing=1
  fi
  need_cmd gh "release publishing"
}

check_linux() {
  need_cmd sh "shell workflows"
  need_cmd softhsm2-util "PKCS#11 smoke"
  need_cmd pkcs11-tool "PKCS#11 smoke"
}

check_windows_hint() {
  echo "[info] Windows runner should have: pwsh, ssh-keygen (OpenSSH), Rust toolchain"
}

echo "self-hosted runner preflight: os=$os profile=$profile"

check_common

case "$profile" in
  all)
    case "$os" in
      Darwin) check_macos ;;
      Linux) check_linux ;;
      *) echo "[info] no OS-specific checks for $os" ;;
    esac
    ;;
  macos)
    check_macos
    ;;
  linux)
    check_linux
    ;;
  windows)
    check_windows_hint
    ;;
  *)
    echo "usage: $0 [all|macos|linux|windows]" >&2
    exit 2
    ;;
esac

if [ "$missing" -ne 0 ]; then
  echo "preflight failed: missing dependencies" >&2
  exit 1
fi

echo "preflight ok"
