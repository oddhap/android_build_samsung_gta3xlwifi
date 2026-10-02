#!/bin/bash
set -euo pipefail
ROOT=/srv/android/vendor-stock
ZIP="$ROOT/firmware/SM-T510_2_20230111191720_hnttj7k1k2_fac.zip"
mkdir -p "$ROOT/packages" "$ROOT/images" "$ROOT/extracted/vendor"
if [[ ${1:-} != --resume-extraction ]]; then
  unzip -t "$ZIP"
  sha256sum "$ZIP" > "$ROOT/firmware/SHA256SUMS"
  unzip -o "$ZIP" -d "$ROOT/packages"
fi
/srv/android/tools/samloader/samloader verify-md5 "$ROOT"/packages/*.tar.md5
AP=("$ROOT"/packages/AP_T510XXU5CWA1_*.tar.md5)
tar -tf "${AP[0]}" > "$ROOT/packages/ap-file-list.txt"
tar -xf "${AP[0]}" -C "$ROOT/images" boot.img.lz4 recovery.img.lz4 vendor.img.lz4 dt.img.lz4 dtbo.img.lz4 vbmeta.img.lz4
for name in boot recovery vendor dt dtbo vbmeta; do
  lz4 -d -f "$ROOT/images/$name.img.lz4" "$ROOT/images/$name.img"
done
simg2img "$ROOT/images/vendor.img" "$ROOT/images/vendor.raw.img"
VENDOR_DUMP=$(mktemp -d "$ROOT/extracted/vendor-XXXXXX")
sudo debugfs -R "rdump / $VENDOR_DUMP" "$ROOT/images/vendor.raw.img"
sudo chown -R builder:builder "$VENDOR_DUMP"
if [[ -d "$ROOT/extracted/vendor" ]]; then
  mv "$ROOT/extracted/vendor" "$ROOT/extracted/vendor-previous-$(date +%s)"
fi
mv "$VENDOR_DUMP" "$ROOT/extracted/vendor"
find "$ROOT/extracted/vendor" -type f | sort > "$ROOT/vendor-file-list.txt"
date -u +%FT%TZ > "$ROOT/STOCK_EXTRACTION_COMPLETE"
