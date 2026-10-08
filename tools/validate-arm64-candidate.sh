#!/usr/bin/env bash
set -euo pipefail
port=/srv/android/ports/lineage-21-arm64/lineage-21
artifacts=/srv/android/artifacts/lineage-21-arm64
logs=/srv/android/logs/lineage-21-arm64
release="$artifacts/release"
rm -f "$release/offline-validation.json"
original=/srv/android/src/lineage-21.0-arm64/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
test "$(cat "$logs/full-build.exit")" = 0
test -s "$release/signed-target-files.zip"
# Select the OTA by the actual signed product version, not a guessed date.
ota=$(python3 - "$release" <<'PY'
import sys, zipfile
from pathlib import Path
release = Path(sys.argv[1])
with zipfile.ZipFile(release/'signed-target-files.zip') as archive:
    props = dict(line.split('=', 1) for line in archive.read('SYSTEM/build.prop').decode().splitlines()
                 if '=' in line and not line.startswith('#'))
print(release/('lineage-'+props['ro.lineage.version']+'-arm64-privatekeys.zip'))
PY
)
test -s "$ota"
check() {
    local name=$1
    shift
    if "$@" > "$logs/$name.log" 2>&1; then
        printf '%s: PASS\n' "$name"
    else
        tail -n 50 "$logs/$name.log"
        return 1
    fi
}
check release-verification python3 "$port/tools/verify-release.py" "$original"
check native-images python3 "$port/tools/verify-native-images.py" --package "$ota"
# Inspect the signed physical filesystems and actual signed package contents.
check native-layout python3 "$port/tools/verify-native-layout.py" --report-dir "$release"
check port-package python3 "$port/tools/verify-port-package.py" --report-dir "$release" --target-files "$release/verified-target-files"
check usage-compat python3 "$port/tools/verify-usage-compat.py"
check signed-multilib python3 "$port/tools/verify-arm64-multilib.py" "$release/signed-target-files.zip" --report "$release/multilib-check.json"
check signed-donor python3 "$port/tools/verify-built-donor.py" "$release/signed-target-files.zip"
check signing-inputs python3 /srv/android/ports/lineage-21-arm64/check-signing-inputs.py /srv/android/signing/arm64-baseline-sha256.json
python3 - "$release" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path
release = Path(sys.argv[1])
checks = json.loads((release/'release-signature-check.json').read_text())
assert checks['passed']
result = {'passed': True, 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
          'rom_zip_sha256': checks['rom_zip_sha256'],
          'build_incremental': checks['build_incremental'],
          'signed_filesystems_checked': True, 'hardware_tested': False,
          'checks': ['signatures', 'physical_image_bounds', 'signed_system_layout',
                     'packaged_platform_fixes', 'usage_compatibility',
                     'signed_multilib', 'signed_donor_dependencies', 'unchanged_keys']}
(release/'offline-validation.json').write_text(json.dumps(result, indent=2)+'\n')
PY
printf 'All offline candidate checks passed: %s\n' "$ota"
