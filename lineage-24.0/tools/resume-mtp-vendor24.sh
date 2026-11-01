#!/usr/bin/env bash
# Resume a stopped initial setup with the owner's reviewed MTP vendor input.
set -euo pipefail
export PATH="$HOME/bin:$PATH"
port=/srv/android/ports/lineage-24.0-arm64
top=/srv/android/src/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
trap 'rc=$?; echo "$rc" > "$logs/migration.exit"; echo "$rc" > "$logs/setup.exit"' EXIT
exec 9>"$logs/setup.lock"
flock -n 9 || { echo 'Setup is active'; exit 1; }
exec 8>"$logs/build.lock"
flock -n 8 || { echo 'Build is active'; exit 1; }
for path in /srv/android/src/lineage-23.2-arm64 /srv/android/ports/lineage-23.2-arm64 /srv/android/artifacts/lineage-23.2-arm64 /srv/android/logs/lineage-23.2-arm64 /srv/android/ccache-lineage-23.2; do
 [[ ! -e $path ]] || { echo "Cleanup incomplete: $path"; exit 1; }
done
cd "$top"
cp "$port/tools/gta3xlwifi.xml" .repo/local_manifests/gta3xlwifi.xml
# Fetch only the reviewed device commit. Other 1242 locked projects stay put.
repo sync -c -j1 --no-clone-bundle --no-tags --optimized-fetch --fail-fast device/samsung/gta3xlwifi
repo manifest -r -o "$artifacts/platform-manifest.xml.tmp"
python3 "$port/tools/audit.py" "$top" "$artifacts/platform-manifest.xml.tmp" "$artifacts/source-audit.json"
mv "$artifacts/platform-manifest.xml.tmp" "$artifacts/platform-manifest.xml"
flock -u 8
exec 8>&-
flock -u 9
exec 9>&-
bash "$port/tools/setup.sh" --resume-inputs
