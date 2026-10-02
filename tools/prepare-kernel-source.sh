#!/bin/bash
set -euo pipefail
ROOT=/srv/android
AUDIT="$ROOT/source-audit/kernel-gta3xlwifi"
SRC="$ROOT/src/kernel-gta3xlwifi"
TC="$ROOT/toolchains/aarch64-linux-android-4.9"
mkdir -p "$ROOT/source-audit" "$ROOT/src" "$ROOT/toolchains"
if [[ ! -d "$AUDIT/.git" ]]; then
  git clone --depth 1 -b main https://github.com/gta3xlwifi-dev/android_kernel_gta3xlwifi.git "$AUDIT"
fi
test "$(git -C "$AUDIT" rev-parse HEAD)" = 00e4b9481434f9b0b644925a9bb2feaf3940219d
if [[ ! -d "$TC/.git" ]]; then
  git clone --depth 1 -b android-9.0.0_r61 https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9 "$TC"
fi
test "$(git -C "$TC" rev-parse HEAD)" = 961622e926a1b21382dba4dd9fe0e5fb3ee5ab7c
if [[ ! -e "$SRC/.git" ]]; then
  git -C "$AUDIT" worktree add --detach "$SRC" HEAD
  # The upstream repository tracks generated files from an earlier build.
  # Keep the audit checkout intact and clean only this build worktree.
  make -C "$SRC" ARCH=arm64 mrproper
fi
