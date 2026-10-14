#!/usr/bin/env bash
set -euo pipefail
recipe=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
src=${KERNEL_SRC:-/srv/android/src/kernel-gta3xlwifi-dt2w}
out=${KERNEL_OUT:-/srv/android/out/kernel-dt2w}
artifacts=${KERNEL_ARTIFACTS:-/srv/android/artifacts/kernel-dt2w}
test "$(git -C "$src" rev-parse HEAD)" = efbdbfa3e216b0c300d381c340b0a22b24e15c13
git -C "$src" apply --reverse --check "$recipe/kernel-double-tap-wake.patch"
mkdir -p "$out/init" "$out/firmware" "$artifacts"
cp "$src/init/uh.elf" "$out/init/uh.elf"
cp "$src/firmware/exynos7885_acpm_fvp.fw" "$out/firmware/exynos7885_acpm_fvp.fw"
cp "$recipe/kernel.config" "$out/.config"
export ARCH=arm64
export CROSS_COMPILE=${CROSS_COMPILE:-/srv/android/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-}
export PLATFORM_VERSION=11 ANDROID_VERSION=110000 ANDROID_MAJOR_VERSION=r
export KCFLAGS=-DANDROID_VERSION=110000
export KBUILD_BUILD_USER=oddhap KBUILD_BUILD_HOST=lineage-builder
export KBUILD_BUILD_VERSION=2
export KBUILD_BUILD_TIMESTAMP='Wed Oct 14 18:00:00 UTC 2026'
make -C "$src" O="$out" olddefconfig
make -C "$src" O="$out" silentoldconfig
make -C "$src" O="$out" -j12 Image
cp "$out/arch/arm64/boot/Image" "$artifacts/Image"
cp "$out/.config" "$artifacts/kernel.config"
sha256sum "$artifacts/Image" "$artifacts/kernel.config" > "$artifacts/SHA256SUMS"
