#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot45: unattended TWRP install from the LineageOS Updater (parent: snapshot44).

TWRP's init mounts /vendor read-only at post-fs and runs its FBE helper daemons
(mobicore, keymaster, gatekeeper, keystore2) from it. For a manual sideload the
host preflight stops exactly these services and unmounts vendor before the
install; with the Updater, TWRP runs the install itself at startup
(--update_package=@/cache/recovery/block.map, no decryption), so the OTA's
vendor-unmounted guard would stop the install before any write.

Changes (releasetools.py only), after the read-only recovery preflight:
- recovery-vendor-quiesce.sh: stop those services, plain umount of /vendor (up
  to 10 attempts). Its result is not trusted: the unchanged vendor-unmounted
  guard must still pass before anything else happens. No lazy unmount.
- recovery-product-link.sh (asserted): backuptool.sh checks ro.lineage.version
  in $P/etc/build.prop with P=/product unless /product is a symlink. Product is
  folded into system (system/product) and TWRP's /product is an empty ramdisk
  directory, so build 44 logged "Incompatible ROM version: 24" and skipped the
  addon.d backup/restore. The empty, unmounted directory is replaced by a
  symlink to /system_root/system/product (backuptool's system mount; TWRP RAM
  only, gone at reboot). Anything else makes the install stop before writes.
  The link mirrors backuptool's own system mount (/mnt/system if TWRP has it,
  else /system_root); TWRP 3.7.1 creates /mnt/system at runtime.
- addon-vendor-guard.sh replaced: blockdev --setro does NOT stop an rw mount on
  this kernel (measured in TWRP). protect now mounts vendor read-only at /vendor
  (backuptool's mount_extra skips existing mount points) and refuses when a
  pre-v3 addon.d script sorts before a v3 script; release unmounts it and
  requires vendor and product unmounted. Tested physically with the real
  backuptool backup: vendor stayed byte-identical.
No change to any guard, image, policy, vendor, kernel or prebuilt."""
import hashlib, json, subprocess
from pathlib import Path
src = Path('/srv/android/src/lineage-24.0-arm64')
art = Path('/srv/android/artifacts/lineage-24.0-arm64')
port = Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0')
before, after = port/'snapshots/port-20261121-44', port/'snapshots/port-20261121-45'
work = art/'runtime45-source-selection-20261121-01'
work.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
audit = port/'tools/audit-port.py'
subprocess.run(['python3', audit, src, before, work/'source-before.json'], check=True)
assert not after.exists()
D = src/'device/samsung/gta3xlwifi'
prev = json.loads((art/'runtime44-source-selection-20261121-01/edits.json').read_text())
for name, rec in prev.items():
    assert sha(Path(name)) == rec['after_sha256'], name
QUIESCE = '#!/sbin/sh\n# TWRP runs its FBE helper daemons from the read-only /vendor mount. Stop the\n# services the manual sideload preflight stops, then unmount vendor (no lazy\n# unmount). The OTA\'s vendor-unmounted guard decides afterwards.\nfor s in keystore2 recovery-gatekeeper recovery-keymaster recovery-mobicore recovery-crypto-props; do\n    /system/bin/stop "$s"\ndone\ni=0\nwhile [ $i -lt 10 ]; do\n    busy=0\n    while read source mountpoint rest; do\n        case "$mountpoint" in /vendor|/vendor/*) busy=1 ;; esac\n    done < /proc/mounts\n    [ $busy = 0 ] && exit 0\n    /system/bin/umount /vendor\n    /system/bin/sleep 1\n    i=$((i + 1))\ndone\nexit 1\n'
# Physically tested in TWRP 33875693 (reports/.../runtime45-recovery-script-test).
PRODUCT_LINK = '#!/sbin/sh\n# backuptool.sh reads ro.lineage.version from /product/etc/build.prop unless\n# /product is a symlink. Product lives in system; point TWRP\'s empty /product\n# directory at backuptool\'s own system mount (rootfs RAM only).\nif [ -d /mnt/system ]; then target=/mnt/system/system/product\nelif [ -d /system_root ]; then target=/system_root/system/product\nelse exit 2; fi\nif [ -L /product ]; then\n    [ "$(readlink /product)" = "$target" ] && exit 0\n    exit 1\nfi\n[ -d /product ] || exit 1\nwhile read source mountpoint rest; do\n    case "$mountpoint" in /product|/product/*) exit 1 ;; esac\ndone < /proc/mounts\nrmdir /product && ln -s "$target" /product && [ "$(readlink /product)" = "$target" ]\n'
ADDON_GUARD = '#!/sbin/sh\n# addon.d v3 scripts make backuptool mount /vendor read-write unless /vendor is\n# already a mount point (blockdev --setro does not stop that on this kernel).\n# protect: mount vendor read-only at /vendor first; refuse when a pre-v3 script\n# sorts before a v3 script in /tmp/addon.d (backuptool would lazily unmount it\n# and the next v3 script would mount vendor read-write).\n# release: vendor and product must not stay mounted.\nv=/dev/block/platform/13500000.dwmmc0/by-name/vendor\n[ -b "$v" ] && [ -r /proc/mounts ] || exit 2\nmounted() {\n    while read source mountpoint rest; do\n        case "$mountpoint" in "$1"|"$1"/*) return 0 ;; esac\n    done < /proc/mounts\n    return 1\n}\ncase "$1" in\nprotect)\n    if [ -d /tmp/addon.d ]; then\n        older=0\n        for f in $(find /tmp/addon.d/ -name \'*.sh\' | sort -n); do\n            ver=$(grep "^# ADDOND_VERSION=" "$f" | cut -d= -f2)\n            [ -z "$ver" ] && ver=1\n            if [ "$ver" -ge 3 ]; then [ $older = 0 ] || exit 1; else older=1; fi\n        done\n    fi\n    mounted /vendor && exit 1\n    mkdir -p /vendor && mount -t ext4 -o ro "$v" /vendor || exit 1\n    grep -q " /vendor ext4 ro[ ,]" /proc/mounts || exit 1 ;;\nrelease)\n    if mounted /vendor; then umount /vendor || exit 1; fi\n    mounted /vendor && exit 1\n    mounted /product && exit 1 ;;\n*) exit 2 ;;\nesac\nexit 0\n'
OLD_ADDON_GUARD = (art/'runtime44-source-selection-20261121-01/addon-vendor-guard.sh').read_text()
edits = {}
def edit(path, pairs):
    o = path.read_text(); u = o
    for a, b in pairs:
        assert u.count(a) == 1, (path, a)
        u = u.replace(a, b)
    edits[path] = (o, u)
edit(D/'releasetools.py', [
    ('_ADDON_GUARD = ' + repr(OLD_ADDON_GUARD.encode()) + '\n', '_ADDON_GUARD = ' + repr(ADDON_GUARD.encode()) + '\n'),
    ('_SYSTEM_DEVICE = "/dev/block/platform/13500000.dwmmc0/by-name/system"\n',
     '_VENDOR_QUIESCE = ' + repr(QUIESCE.encode()) + '\n'
     '_PRODUCT_LINK = ' + repr(PRODUCT_LINK.encode()) + '\n'
     '_SYSTEM_DEVICE = "/dev/block/platform/13500000.dwmmc0/by-name/system"\n'),
    ("    # TWRP uses vendor for decryption. Refuse all image writes while mounted.\n",
     "    # TWRP mounts vendor read-only at boot and runs its FBE helper daemons from it.\n"
     "    # An Updater install runs unattended: stop exactly the services the manual\n"
     "    # sideload preflight stops and unmount vendor. Not trusted: the\n"
     "    # vendor-unmounted guard below must still pass.\n"
     "    common.ZipWriteStr(info.output_zip, \"recovery-vendor-quiesce.sh\", _VENDOR_QUIESCE)\n"
     "    info.script.AppendExtra('package_extract_file(\"recovery-vendor-quiesce.sh\", \"/tmp/recovery-vendor-quiesce.sh\");')\n"
     "    info.script.AppendExtra('run_program(\"/sbin/sh\", \"/tmp/recovery-vendor-quiesce.sh\");')\n"
     "    # backuptool needs /product -> system/product (product folded into system).\n"
     "    common.ZipWriteStr(info.output_zip, \"recovery-product-link.sh\", _PRODUCT_LINK)\n"
     "    info.script.AppendExtra('package_extract_file(\"recovery-product-link.sh\", \"/tmp/recovery-product-link.sh\");')\n"
     "    info.script.AppendExtra('assert(run_program(\"/sbin/sh\", \"/tmp/recovery-product-link.sh\") == \"0\" || '\n"
     "                            'abort(\"Cannot link /product to system/product for the addon.d backup. Installation stopped before image writes.\"));')\n"
     "    # TWRP uses vendor for decryption. Refuse all image writes while mounted.\n"),
])
compile(edits[D/'releasetools.py'][1], 'releasetools.py', 'exec')
originals = work/'originals'
originals.mkdir()
for path, (o, u) in edits.items():
    (originals/(path.name + '.original')).write_text(o)
(work/'recovery-vendor-quiesce.sh').write_text(QUIESCE)
(work/'recovery-product-link.sh').write_text(PRODUCT_LINK)
(work/'addon-vendor-guard.sh').write_text(ADDON_GUARD)
(work/'edits.json').write_text(json.dumps({str(p): {'before_sha256': hashlib.sha256(o.encode()).hexdigest(),
    'after_sha256': hashlib.sha256(u.encode()).hexdigest()} for p, (o, u) in edits.items()}, indent=2)+'\n')
(work/'quiesce.json').write_text(json.dumps({'recovery_vendor_quiesce_sha256': hashlib.sha256(QUIESCE.encode()).hexdigest(),
    'recovery_product_link_sha256': hashlib.sha256(PRODUCT_LINK.encode()).hexdigest(),
    'addon_vendor_guard_sha256': hashlib.sha256(ADDON_GUARD.encode()).hexdigest()}, indent=2)+'\n')
projects = [r['project'] for r in json.loads((before/'source-lock.json').read_text())]
try:
    for path, (o, u) in edits.items():
        path.write_text(u)
    subprocess.run(['python3', port/'tools/capture-port.py', '--parent-snapshot', before, src, after, *projects], check=True)
    subprocess.run(['python3', audit, src, after, after/'port-audit.json'], check=True)
except BaseException:
    for path, (o, u) in edits.items():
        path.write_text(o)
    if after.exists():
        after.rename(work/'failed-snapshot')
    raise
p = art/'runtime44-inputs-20261121-01/report.json'
r = json.loads(p.read_text())
assert r['passed'] and r['source_snapshot'] == str(before)
r.update(source_snapshot=str(after), inherited_runtime_selection_sha256=sha(p), runtime_prebuilts_changed=False)
out = art/'runtime45-inputs-20261121-01'
out.mkdir()
(out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
print('PASS staged snapshot45 TWRP vendor quiesce, /product link and read-only vendor guard:', after)
