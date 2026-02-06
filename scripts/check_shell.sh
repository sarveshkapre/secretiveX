#!/usr/bin/env sh
set -eu

checked=0

for script in scripts/*.sh; do
  if [ ! -f "$script" ]; then
    continue
  fi
  echo "[shell-check] $script"
  sh -n "$script"
  checked=$((checked + 1))
done

if [ "$checked" -eq 0 ]; then
  echo "[shell-check] no scripts checked"
  exit 1
fi

echo "[shell-check] checked $checked script(s)"
