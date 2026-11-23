#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Owner-approved release signing (2026-11-22): re-sign a fully checked test-OTA build
# with the owner keys and prove the result. Every step stops the chain on failure.
#   run-release-ota24.sh RELEASE_LABEL CHECKED_OTA_BUILD_LABEL
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
K=/srv/android/keys/lineage-24.0-gta3xlwifi
label=${1:?RELEASE_LABEL}; base=${2:?CHECKED_OTA_BUILD_LABEL}
[[ $label =~ ^release-[0-9]{8}-[0-9]{2}$ && $base =~ ^runtime[0-9]+-ota-build-[0-9]{8}-[0-9]{2}$ ]] || exit 2
orch=$label-orchestrator
[[ ! -e $L/$orch.exit ]] || exit 2
exec >"$L/$orch.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$orch.exit"; exit "$rc"' EXIT
n=${base#runtime}; n=${n%%-*}; day=${base#runtime$n-ota-build-}; day=${day%-*}
checks=$A/runtime$n-product-checks-$day-01
[[ $(cat "$L/runtime$n-ota-checks-$day-01.exit") == 0 ]]
# Reuse a completed signing run of the same label (checks are re-run on it).
if [[ ! -f $L/$label.exit ]]; then bash "$P/tools/sign-release-ota24.sh" "$label" "$base" --i-approve-release-signing; fi
[[ $(cat "$L/$label.exit") == 0 ]]
O=$A/$label
ota=$(ls "$O"/lineage-24.0-20??????-UNOFFICIAL-gta3xlwifi.zip); [[ -f $ota ]]
cert=$O/releasekey.x509.pem
cmp "$cert" "$K/releasekey.x509.pem"
exec 9>"$L/build.lock"; flock -n 9 || exit 75
python3 "$P/tools/check-release-signed-target-files24.py" --top "$T" --readiness "$A/$base/readiness-report.json" \
  --unsigned "$A/$base/target-files.zip" --signed "$O/signed-target-files.zip" --geometry "$checks/geometry-policy.json" \
  --certs "$K" --output "$O/checks/target"
upd=check-runtime46-updater-target24.py; (( n >= 53 )) && upd=check-runtime53-updater-target24.py  # snapshot53 kernel-digest chain
python3 "$P/tools/$upd" "$T" "$O/signed-target-files.zip" "$O/checks/target/geometry-policy.json" "$O/checks/updater.json" "$cert"
python3 "$P/tools/check-runtime45-test-ota-container24.py" --ota "$ota" --target-files "$O/signed-target-files.zip" --geometry "$O/checks/target/geometry-policy.json" --certificate "$cert" --output "$O/checks/container"
python3 "$P/tools/check-runtime40-ota-block-streams24.py" --top "$T" --ota "$ota" --target-files "$O/signed-target-files.zip" --container "$O/checks/container/report.json" --geometry "$O/checks/target/geometry-policy.json" --vendor-report "$A/updion-vendor-20261122-01/report.json" --output "$O/checks/blocks"
python3 - "$A/$base/readiness-report.json" "$O" "$ota" <<'PY'
import hashlib,json,sys,zipfile
from pathlib import Path
base,O,ota=Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3])
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
b=json.loads(base.read_text());assert b['technical_package_checks_passed']
rep={k:json.loads((O/'checks'/k/'report.json').read_text()) if k!='updater' else json.loads((O/'checks/updater.json').read_text()) for k in ['target','container','blocks','updater']}
assert all(v['passed'] for v in rep.values())
assert rep['container']['ota_sha256']==rep['blocks']['ota_sha256']==sha(ota)
assert rep['target']['signed_sha256']==rep['container']['target_files_sha256']==sha(O/'signed-target-files.zip')
meta=dict(l.split('=',1) for l in zipfile.ZipFile(ota).read('META-INF/com/android/metadata').decode().splitlines() if '=' in l)
assert 'release-keys' in meta['post-build'] and 'test-keys' not in meta['post-build']
r=dict(technical_package_checks_passed=True,release_signed=True,ota_filename=ota.name,ota_bytes=ota.stat().st_size,ota_sha256=sha(ota),
 ota_post_timestamp=int(meta['post-timestamp']),target_files_sha256=sha(O/'signed-target-files.zip'),
 base_checked_build_readiness_sha256=sha(base),base_checked_build=b['ROM_source_snapshot'],release_certificate_sha256=rep['target']['release_certificate_sha256'],
 proof_reports_sha256={k:sha(O/'checks'/k/'report.json') if k!='updater' else sha(O/'checks/updater.json') for k in rep},
 apk_apex_resigned=rep['target']['apk_apex_resigned'],physical_switch_required='first release-signed build must be sideloaded (device otacerts = test key until then)',
 flash_ready=False)
(O/'readiness-report.json').write_text(json.dumps(r,indent=2)+'\n');print('PASS release readiness',ota.name,r['ota_sha256'])
PY
