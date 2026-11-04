#!/usr/bin/env bash
# Resume after host GNU ld rejected Android compressed debug sections.
# No stripping or library changes; use the pinned platform Clang/LLD instead.
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=policy-binary-finish-20261104-01
art=/srv/android/artifacts/lineage-24.0-arm64/policy-binary-20261104-01
exec 9>"$logs/build.lock"
flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; exit "$result"' EXIT
test "$(cat "$logs/policy-binary-20261104-01.exit")" = 1
test ! -e "$art/binary-inspection.json"
test "$(cat "$art/strict-checker.exit")" = 1
lib="$top/out/soong/.intermediates/external/selinux/libsepol/libsepol/linux_glibc_x86_64_static/libsepol.a"
"$top/prebuilts/clang/host/linux-x86/clang-r584948/bin/clang" -fuse-ld=lld -std=gnu11 -O2 -Wall -Wextra -Werror \
 -I"$top/external/selinux/libsepol/include" \
 "$port/tools/inspect-policy-xperms.c" "$lib" -o "$art/inspect-policy-xperms"
"$art/inspect-policy-xperms" "$art/policy/init-runtime-diagnostic.policy" >"$art/binary-inspection.json"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$art/source-after.json"
python3 - "$top" "$port" "$art" "$lib" <<'PY'
import hashlib,json,sys,subprocess
from pathlib import Path
top,port,art,lib=map(Path,sys.argv[1:]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
a=json.loads((art/'source-before.json').read_text());b=json.loads((art/'source-after.json').read_text());a.pop('checked_at_utc');b.pop('checked_at_utc');assert a==b
paths=[port/'tools/inspect-policy-xperms.c',lib,art/'inspect-policy-xperms',art/'binary-inspection.json',art/'policy/init-runtime-diagnostic.policy',art/'policy/report.json',art/'source-before.json',art/'source-after.json']
paths += [top/'external/selinux/libsepol'/x for x in ['include/sepol/policydb/polcaps.h','src/polcaps.c','src/policydb.c','src/ebitmap.c']]
r={'scope':'Read-only Android17 diagnostic policy binary inspection using actual Android17 libsepol. Strict neverallow gate still fails. No kernel execution or approval.', 'sha256':{str(p):sha(p) for p in paths},'libsepol_revision':subprocess.check_output(['git','-C',str(top/'external/selinux'),'rev-parse','HEAD'],text=True).strip(),'strict_passed':False,'flash_ready':False}
(art/'evidence-lock.json').write_text(json.dumps(r,indent=2)+'\n')
print((art/'binary-inspection.json').read_text())
PY
