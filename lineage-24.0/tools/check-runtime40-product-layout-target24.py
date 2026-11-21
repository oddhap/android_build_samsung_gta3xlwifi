#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Snapshot40: verify /product is folded into the actual system image and that the
official MindTheGapps 17 ZIP fits with its own space rule.

Checks, read-only:
- target-files ROOT/product is a symlink to /system/product, no product image;
- the real expanded system.img contains /product -> /system/product and a real
  /system/product directory (debugfs on the image, not build metadata only);
- the installer's own size rule (du of every payload file in 4 KiB blocks plus
  directories, Velvet variant selection as for a non-tangorpro device, plus its
  10240 KiB buffer) against the ext4 superblock's available blocks
  (free - reserved), i.e. the value its `df` check sees. The complete package is
  required to fit, so the installer's low-resource removals are not needed.
The GApps ZIP is only read (hash-pinned), never extracted to the device or ROM.
"""
import argparse, hashlib, json, shutil, stat, struct, subprocess, sys, tempfile, zipfile
from pathlib import Path, PurePosixPath

p = argparse.ArgumentParser(description=__doc__)
for n in ['top', 'archive', 'geometry', 'gapps', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
p.add_argument('--gapps-sha256', required=True)
a = p.parse_args()
assert not a.output.exists()
def sha(f):
    h = hashlib.sha256()
    with f.open('rb') as s:
        for b in iter(lambda: s.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()
g = json.loads(a.geometry.read_text())
assert g['artifact_checks_passed'] and sha(a.archive) == g['archive_sha256']
assert g['ota_layout']['product_folded_into_system']
assert sha(a.gapps) == a.gapps_sha256
host = a.top/'out/host/linux-x86/bin'
sys.path.insert(0, str(a.top/'build/make/tools/releasetools')); sys.dont_write_bytecode = True
import sparse_img

# Installer size rule (MindTheGapps update-binary compute_apps_size), computed
# from the pinned ZIP: every regular file rounded up to 4 KiB, every directory
# 4 KiB, VelvetTitan removed (non-tangorpro), plus STORAGE_BUFFER=10240 KiB.
files, dirs = {}, set()
with zipfile.ZipFile(a.gapps) as z:
    script = z.read('META-INF/com/google/android/update-binary').decode()
    assert 'STORAGE_BUFFER=10240' in script and 'rm -rf product/priv-app/VelvetTitan' in script
    assert '[ -L "${SYSTEM_MNT}/product" ]' in script and 'PRODUCT_BLOCK=""' in script
    props = dict(l.split('=', 1) for l in z.read('build.prop').decode().splitlines() if '=' in l)
    assert props['arch'] == 'arm64' and props['version'] == '37'
    for i in z.infolist():
        if not i.filename.startswith('system/') or i.is_dir():
            continue
        rel = PurePosixPath(i.filename).relative_to('system')
        if rel.parts[:3] == ('product', 'priv-app', 'VelvetTitan'):
            continue
        files[str(rel)] = i.file_size
        for parent in list(rel.parents)[:-1]:
            dirs.add(str(parent))
blocks = sum((s + 4095)//4096 for s in files.values()) + len(dirs)
# The installer later writes one generated addon.d script (list of all paths).
addon_kib = (sum(len(f)+1 for f in files)+4096+4095)//4096*4
needed_kib = blocks*4 + 10240 + addon_kib

with zipfile.ZipFile(a.archive) as z, tempfile.TemporaryDirectory(dir=a.output.parent, prefix='layout40-') as td:
    i = z.getinfo('ROOT/product')
    assert stat.S_ISLNK(i.external_attr >> 16) and z.read('ROOT/product') == b'/system/product'
    assert 'IMAGES/product.img' not in z.namelist()
    simg = Path(td)/'system.img'
    with z.open('IMAGES/system.img') as s, simg.open('wb') as d:
        shutil.copyfileobj(s, d, 1 << 20)
    assert sha(simg) == g['images']['system.img']['sha256']
    raw = Path(td)/'system.raw'
    subprocess.run([str(host/'simg2img'), str(simg), str(raw)], check=True)
    simg.unlink()
    with raw.open('rb') as f:
        f.seek(1024); sb = f.read(1024)
    assert struct.unpack_from('<H', sb, 0x38)[0] == 0xef53
    bsize = 1024 << struct.unpack_from('<I', sb, 0x18)[0]
    incompat = struct.unpack_from('<I', sb, 0x60)[0]
    hi = (lambda off: struct.unpack_from('<I', sb, off)[0] << 32) if incompat & 0x80 else (lambda off: 0)
    total = struct.unpack_from('<I', sb, 0x04)[0] + hi(0x150)
    reserved = struct.unpack_from('<I', sb, 0x08)[0] + hi(0x154)
    free = struct.unpack_from('<I', sb, 0x0c)[0] + hi(0x158)
    available_kib = (free - reserved) * bsize // 1024
    assert total * bsize == g['images']['system.img']['expanded_bytes']
    dbg = lambda cmd: subprocess.run([str(host/'debugfs_static'), '-R', cmd, str(raw)],
                                     capture_output=True, text=True, check=True).stdout
    link = dbg('stat /product')
    assert 'Type: symlink' in link and 'Fast link dest: "/system/product"' in link, link
    d = dbg('stat /system/product')
    assert 'Type: directory' in d, d
    listing = dbg('ls -p /system/product')
    for name in ['app', 'priv-app', 'etc', 'overlay']:
        assert '/'+name+'/' in listing, (name, listing)
    raw.unlink()
assert available_kib > needed_kib, ('Complete MindTheGapps payload does not fit', available_kib, needed_kib)
report = {'passed': True, 'scope': __doc__, 'archive_sha256': g['archive_sha256'],
          'gapps_zip': a.gapps.name, 'gapps_zip_sha256': a.gapps_sha256, 'gapps_sdk': props['version'],
          'gapps_payload_files': len(files), 'gapps_needed_kib_complete_incl_buffer': needed_kib,
          'system_block_size': bsize, 'system_total_blocks': total, 'system_free_blocks': free,
          'system_reserved_blocks': reserved, 'system_available_kib': available_kib,
          'headroom_after_complete_gapps_kib': available_kib - needed_kib,
          'root_product_symlink': '/system/product', 'product_image_present': False,
          'physical_product_partition_written': False, 'gapps_installed_or_tested': False, 'flash_ready': False}
a.output.write_text(json.dumps(report, indent=2)+'\n')
print('PASS product folded into system; complete MindTheGapps fits:', available_kib, '>', needed_kib, 'KiB')
