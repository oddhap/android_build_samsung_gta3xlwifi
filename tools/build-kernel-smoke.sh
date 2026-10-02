#!/bin/bash
set -euo pipefail
ROOT=/srv/android
SRC="$ROOT/src/kernel-gta3xlwifi"
OUT="$ROOT/out/kernel-smoke"
export ARCH=arm64
export CROSS_COMPILE="$ROOT/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-"
export PLATFORM_VERSION=11
export ANDROID_VERSION=110000
export KCFLAGS="-DANDROID_VERSION=110000"
export ANDROID_MAJOR_VERSION=r
mkdir -p "$OUT" "$ROOT/artifacts/kernel-smoke"
mkdir -p "$OUT/init"
cp "$SRC/init/uh.elf" "$OUT/init/uh.elf"
mkdir -p "$OUT/firmware"
cp "$SRC/firmware/exynos7885_acpm_fvp.fw" "$OUT/firmware/exynos7885_acpm_fvp.fw"
cd "$SRC"
if [[ ${SMT510_POWER_BOOST:-1} == 1 ]]; then
  python3 "$ROOT/tools/apply-kernel-power.py"
fi
sed -i 's/^YYLTYPE yylloc;$/extern YYLTYPE yylloc;/' scripts/dtc/dtc-lexer.l scripts/dtc/dtc-lexer.lex.c_shipped
git diff -- scripts/dtc/dtc-lexer.l scripts/dtc/dtc-lexer.lex.c_shipped > "$ROOT/artifacts/kernel-smoke/dtc-host-compat.patch"
python3 - <<'PY'
from pathlib import Path
changes = {
    'drivers/media/platform/exynos/fimc-is2/fimc-is-resourcemgr.c':
        ('static int __init fimc_is_heap_mem_map(', 'static int fimc_is_heap_mem_map('),
    'drivers/media/platform/exynos/fimc-is2/sensor/module_framework/modules/fimc-is-device-module-5e9.c':
        ('static int __init sensor_module_5e9_probe(', 'static int sensor_module_5e9_probe('),
}
for name, (before, after) in changes.items():
    path = Path(name)
    data = path.read_text()
    assert data.count(before) == 1 or data.count(after) == 1, name
    if before in data:
        path.write_text(data.replace(before, after))
PY
git diff -- drivers/media/platform/exynos/fimc-is2/fimc-is-resourcemgr.c drivers/media/platform/exynos/fimc-is2/sensor/module_framework/modules/fimc-is-device-module-5e9.c > "$ROOT/artifacts/kernel-smoke/camera-section-lifetime.patch"
git rev-parse HEAD > "$ROOT/artifacts/kernel-smoke/source-commit.txt"
"${CROSS_COMPILE}gcc" --version | head -1
make O="$OUT" exynos7885-gta3xlwifi_defconfig
make O="$OUT" olddefconfig
make O="$OUT" silentoldconfig
make O="$OUT" -j12 Image dtbs
cp "$OUT/arch/arm64/boot/Image" "$ROOT/artifacts/kernel-smoke/Image"
cp "$OUT/.config" "$ROOT/artifacts/kernel-smoke/config"
mkdir -p "$ROOT/artifacts/kernel-smoke/dts"
cd "$OUT/arch/arm64/boot/dts"
find . -type f \( -name '*.dtb' -o -name '*.dtbo' \) -exec cp --parents {} "$ROOT/artifacts/kernel-smoke/dts/" \;
cd "$ROOT/artifacts/kernel-smoke"
sha256sum Image config > SHA256SUMS
find dts -type f -print0 | sort -z | xargs -0 sha256sum >> SHA256SUMS
date -u +%FT%TZ > BUILD_COMPLETE
