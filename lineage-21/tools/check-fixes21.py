#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the LineageOS 21 fixes ported from LineageOS 24 in a target-files zip.

ART: PRODUCT_ENABLE_UFFD_GC=false and every boot image / odex compiled for the
concurrent-copying GC (the 4.4 kernel has no userfaultfd).
Power: the boost backend retries after a control failure (strings in
libandroid_servers, host test result supplied separately).
SD card: adoptable crypto options + force_on, exFAT kernel alias, exfatprogs.
OTA: Updater index URI, changelog link, and TWRP vendor quiesce in releasetools.
With --ota, also checks the order of the quiesce, guard and writes in the OTA.
"""
import argparse, hashlib, json, re, struct, sys, zipfile

URI = 'lineage.updater.uri=https://raw.githubusercontent.com/oddhap/lineageos21_gta3xlwifi/ota/{device}.json'
CHANGELOG = 'https://github.com/oddhap/lineageos21_gta3xlwifi/releases'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def cc_value(data):
    m = re.search(rb'concurrent-copying\x00(true|false)\x00', data)
    return m.group(1).decode() if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target_files')
    ap.add_argument('--kernel-sha256', required=True)
    ap.add_argument('--vendor-sha256', required=True)
    ap.add_argument('--quiesce-sha256', required=True)
    ap.add_argument('--ota')
    ap.add_argument('--report', required=True)
    a = ap.parse_args()
    r = {}
    z = zipfile.ZipFile(a.target_files)
    names = set(z.namelist())
    # Kernel inside boot.img (header v1, page size 2048).
    boot = z.read('IMAGES/boot.img')
    ksize = struct.unpack_from('<I', boot, 8)[0]
    page = struct.unpack_from('<I', boot, 36)[0]
    assert boot[:8] == b'ANDROID!' and page == 2048
    r['boot_kernel_sha256'] = sha(boot[page:page + ksize])
    assert r['boot_kernel_sha256'] == a.kernel_sha256, 'boot.img kernel is not the exFAT candidate'
    r['vendor_image_sha256'] = sha(z.read('IMAGES/vendor.img'))
    assert r['vendor_image_sha256'] == a.vendor_sha256, 'vendor image changed'
    # Properties.
    system = z.read('SYSTEM/build.prop').decode()
    for line in ['ro.crypto.volume.options=aes-256-xts:aes-256-cts:v1', 'persist.sys.adoptable=force_on', URI]:
        n = system.splitlines().count(line)
        assert n == 1, (line, n)
    r['system_props'] = ['ro.crypto.volume.options', 'persist.sys.adoptable', 'lineage.updater.uri']
    product = z.read('PRODUCT/etc/build.prop').decode()
    uffd = re.findall(r'^ro\.dalvik\.vm\.enable_uffd_gc=(.*)$', product, re.M)
    assert uffd == ['false'], uffd
    r['product_enable_uffd_gc'] = 'false'
    # ART compiled code: every oat/odex must be concurrent-copying=true.
    counts = {'true': 0, 'false': 0, 'none': 0}
    bad = []
    for n in sorted(names):
        if n.endswith(('.oat', '.odex')) and not n.startswith('IMAGES/'):
            v = cc_value(z.read(n))
            counts[v or 'none'] += 1
            # Multi-component boot image: only the primary boot.oat carries the
            # key/value store; boot-*.oat extensions have none. 'false' is never allowed.
            component = re.fullmatch(r'SYSTEM/framework/(arm|arm64)/boot-[^/]+\.oat', n)
            if v == 'false' or (v is None and not component):
                bad.append(n)
    for boot_oat in ['SYSTEM/framework/arm64/boot.oat', 'SYSTEM/framework/arm/boot.oat']:
        assert boot_oat in names and cc_value(z.read(boot_oat)) == 'true', boot_oat
    assert counts['true'] > 50 and not bad, (counts, bad[:10])
    r['art_oat_odex_concurrent_copying'] = counts
    # Power retry compiled into system_server's JNI library.
    lib = z.read('SYSTEM/lib64/libandroid_servers.so')
    for s in [b'Power boost suspended: %s %s failed errno=%d', b'Power boost recovered (%s)']:
        assert s in lib, s
    assert b'disabling boost' not in lib
    r['power_retry_in_libandroid_servers'] = True
    # exfatprogs for vold Exfat::IsSupported.
    for tool in ['SYSTEM/bin/mkfs.exfat', 'SYSTEM/bin/fsck.exfat']:
        assert tool in names, tool
    r['exfatprogs'] = True
    # Updater changelog overlay (string stored in resources.arsc).
    apk = [n for n in names if re.fullmatch(r'SYSTEM/(system_ext/)?priv-app/Updater/Updater\.apk', n)]
    assert len(apk) == 1, apk
    import io
    arsc = zipfile.ZipFile(io.BytesIO(z.read(apk[0]))).read('resources.arsc')
    assert CHANGELOG.encode() in arsc or CHANGELOG.encode('utf-16-le') in arsc
    assert b'download.lineageos.org/%1$s/changes' not in arsc
    r['updater_changelog_url'] = CHANGELOG
    # releasetools carries the quiesce script.
    rt = z.read('META/releasetools.py').decode()
    import ast
    defs = {t.id: ast.literal_eval(node.value) for node in ast.parse(rt).body if isinstance(node, ast.Assign)
            for t in node.targets if isinstance(t, ast.Name) and t.id.startswith('_V')}
    assert sha(defs['_VENDOR_QUIESCE']) == a.quiesce_sha256, 'quiesce script differs from LineageOS 24'
    r['releasetools_quiesce_sha256'] = a.quiesce_sha256
    if a.ota:
        o = zipfile.ZipFile(a.ota)
        script = o.read('META-INF/com/google/android/updater-script').decode()
        assert sha(o.read('recovery-vendor-quiesce.sh')) == a.quiesce_sha256
        q = script.index('run_program("/sbin/sh", "/tmp/recovery-vendor-quiesce.sh");')
        g = script.index('run_program("/sbin/sh", "/tmp/vendor-unmounted-check.sh")')
        pre = script.index('"--preflight"')
        w = script.index('block_image_update(')
        assert pre < q < g < w
        r['ota_order_preflight_quiesce_guard_writes'] = True
    r['passed'] = True
    with open(a.report, 'w') as f:
        json.dump(r, f, indent=2)
        f.write('\n')
    print(json.dumps(r, indent=2))


if __name__ == '__main__':
    sys.exit(main())
