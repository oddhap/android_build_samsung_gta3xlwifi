#!/usr/bin/env bash
# Strict failure remains failure; init-style binary is diagnostic data only.
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=policy-binary-20261104-01
art=/srv/android/artifacts/lineage-24.0-arm64/$label
exec 9>"$logs/build.lock"
flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; exit "$result"' EXIT
test ! -e "$art"
mkdir "$art"
printf '%s\n' 'DIAGNOSTIC ONLY. Neverallow-disabled binary is NOT a strict pass, installation policy or enforcement approval.' >"$art/NOT_READY_FOR_FLASHING.txt"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$art/source-before.json"
set +e
python3 "$port/tools/check-vendor-policy.py" --top "$top" \
 --vendor /srv/android/artifacts/lineage-24.0-arm64/vendor-check-20261101-01/vendor \
 --out-dir out-policy-user-20261101-01 --output "$art/policy" --runtime-diagnostic
strict_rc=$?
set -e
printf '%s\n' "$strict_rc" >"$art/strict-checker.exit"
# This expected failure is kept in report.json and strict-checker.exit.
test "$strict_rc" = 1
python3 - "$art/policy/report.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]));assert not p['passed_strict'];assert p['results'][0]['exit_code']!=0;assert p['results'][1]['exit_code']==0
PY
lib="$top/out/soong/.intermediates/external/selinux/libsepol/libsepol/linux_glibc_x86_64_static/libsepol.a"
clang -std=gnu11 -O2 -Wall -Wextra -Werror \
 -I"$top/external/selinux/libsepol/include" \
 "$port/tools/inspect-policy-xperms.c" "$lib" -o "$art/inspect-policy-xperms"
"$art/inspect-policy-xperms" "$art/policy/init-runtime-diagnostic.policy" >"$art/binary-inspection.json"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$art/source-after.json"
python3 - "$top" "$port" "$art" "$lib" <<'PY'
import hashlib,json,sys,subprocess
from pathlib import Path
top,port,art,lib=map(Path,sys.argv[1:]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
a=json.loads((art/'source-before.json').read_text());b=json.loads((art/'source-after.json').read_text());assert a==b
paths=[port/'tools/inspect-policy-xperms.c',lib,art/'inspect-policy-xperms',art/'binary-inspection.json',art/'policy/init-runtime-diagnostic.policy',art/'policy/report.json',art/'source-before.json',art/'source-after.json']
paths += [top/'external/selinux/libsepol'/x for x in ['include/sepol/policydb/polcaps.h','src/polcaps.c','src/policydb.c','src/ebitmap.c']]
r={'scope':'Read-only Android17 diagnostic policy binary inspection using actual Android17 libsepol. Strict neverallow gate still fails. No kernel execution or approval.', 'sha256':{str(p):sha(p) for p in paths},'libsepol_revision':subprocess.check_output(['git','-C',str(top/'external/selinux'),'rev-parse','HEAD'],text=True).strip(),'strict_passed':False,'flash_ready':False}
(art/'evidence-lock.json').write_text(json.dumps(r,indent=2)+'\n')
print((art/'binary-inspection.json').read_text())
PY
