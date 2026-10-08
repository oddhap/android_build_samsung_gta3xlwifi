#!/usr/bin/env python3
"""Add the audited ARM64 subset to an independent stock vendor image."""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path('/srv/android')
OUT = ROOT/'artifacts/lineage-21-arm64'
DONOR = ROOT/'vendor-donor/a305gt/vendor'
IMAGE = OUT/'vendor-hybrid-arm64.raw.img'
MOUNT = OUT/'vendor-hybrid-mount'
STOCK_MOUNT = OUT/'stock-vendor-mount'
summary = json.loads((OUT/'donor-summary.json').read_text())
selected = summary['selected_donor_files']
if os.geteuid() != 0: raise SystemExit('Run with sudo to preserve original ownership and SELinux xattrs')
if IMAGE.exists(): raise SystemExit('Refusing to overwrite an existing hybrid candidate')

def run(*args): subprocess.run(args, check=True)
def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(8*1024*1024), b''): digest.update(block)
    return digest.hexdigest()
def contents(root):
    result = {}
    for p in sorted(root.rglob('*')):
        relative = str(p.relative_to(root))
        if p.is_symlink(): result[relative] = {'link': str(p.readlink()), 'label': os.getxattr(p, 'security.selinux', follow_symlinks=False).decode().rstrip('\0')}
        elif p.is_file(): result[relative] = {'sha256': sha(p), 'mode': p.stat().st_mode & 0o7777, 'uid': p.stat().st_uid, 'gid': p.stat().st_gid, 'label': os.getxattr(p, 'security.selinux').decode().rstrip('\0')}
    return result

run('simg2img', str(ROOT/'vendor-stock/images/vendor.img'), str(IMAGE))
if IMAGE.stat().st_size != 343932928: raise SystemExit('Unexpected physical vendor size')
for path in (MOUNT, STOCK_MOUNT): path.mkdir(exist_ok=True)
run('mount', '-o', 'loop,ro,noload', str(ROOT/'vendor-stock/images/vendor.raw.img'), str(STOCK_MOUNT))
try:
    baseline = contents(STOCK_MOUNT)
finally:
    run('umount', str(STOCK_MOUNT))
run('mount', '-o', 'loop,rw', str(IMAGE), str(MOUNT))
try:
    for relative, record in selected.items():
        source, dest = DONOR/relative, MOUNT/relative
        for ancestor in reversed(dest.parent.parents):
            if ancestor == MOUNT or MOUNT not in ancestor.parents: continue
            if not ancestor.exists():
                ancestor.mkdir()
                srcdir = DONOR/ancestor.relative_to(MOUNT)
                shutil.copystat(srcdir, ancestor)
                os.chown(ancestor, srcdir.stat().st_uid, srcdir.stat().st_gid)
        if not dest.parent.exists():
            dest.parent.mkdir()
            shutil.copystat(source.parent, dest.parent)
            os.chown(dest.parent, source.parent.stat().st_uid, source.parent.stat().st_gid)
        run('cp', '-a', '--preserve=all', str(source), str(dest))
        if record['symlink_target']:
            if str(dest.readlink()) != record['symlink_target']: raise SystemExit('Donor alias changed')
        elif sha(dest) != record['sha256']: raise SystemExit('Donor copy checksum mismatch')
    public = MOUNT/'etc/public.libraries.txt'
    original = public.read_text()
    if original != 'libMcClient.so\nlibOpenCL.so\n': raise SystemExit('Unexpected stock public library list')
    # Samsung TEE stays ARM32. Android's public-library parser supports ABI qualifiers.
    public.write_text('libMcClient.so 32\nlibOpenCL.so\n')
    default = MOUNT/'default.prop'
    text = default.read_text()
    updates = {'ro.zygote': ('zygote32', 'zygote64_32'), 'ro.bionic.arch': ('arm', 'arm64'), 'ro.bionic.2nd_arch': ('', 'arm'), 'ro.bionic.2nd_cpu_variant': ('', 'cortex-a53')}
    for key, (old, new) in updates.items():
        before = key + '=' + old + '\n'
        if text.count(before) != 1: raise SystemExit(f'Unexpected stock property: {key}')
        text = text.replace(before, key + '=' + new + '\n')
    text += 'dalvik.vm.isa.arm64.variant=cortex-a53\ndalvik.vm.isa.arm64.features=default\n'
    default.write_text(text)
    buildprop = MOUNT/'build.prop'
    text = buildprop.read_text()
    for key, old, new in [('ro.vendor.product.cpu.abilist', 'armeabi-v7a,armeabi', 'arm64-v8a,armeabi-v7a,armeabi'), ('ro.vendor.product.cpu.abilist64', '', 'arm64-v8a')]:
        before = key + '=' + old + '\n'
        if text.count(before) != 1: raise SystemExit(f'Unexpected stock property: {key}')
        text = text.replace(before, key + '=' + new + '\n')
    buildprop.write_text(text)
    current = contents(MOUNT)
    changed = {name: {'before': item, 'after': current.get(name)} for name,item in baseline.items() if current.get(name) != item}
    if set(changed) != {'etc/public.libraries.txt', 'default.prop', 'build.prop'}: raise SystemExit(f'Unexpected stock mutations: {list(changed)}')
    added = {name: item for name,item in current.items() if name not in baseline}
    if set(added) != set(selected): raise SystemExit('Added files differ from audited selection')
    usage = shutil.disk_usage(MOUNT)
    if usage.free < 32*1024*1024: raise SystemExit('Less than 32 MiB vendor filesystem margin')
    report = {'image_path': str(IMAGE), 'image_bytes': IMAGE.stat().st_size, 'physical_limit_bytes': 343932928, 'filesystem_total_bytes': usage.total, 'filesystem_used_bytes': usage.used, 'filesystem_free_bytes': usage.free, 'donor_bytes': summary['selected_donor_bytes'], 'stock_files_checked': len(baseline), 'changed_stock_files': changed, 'added_files': added, 'all_other_stock_bytes_modes_owners_labels_preserved': True, 'hardware_tested': False}
finally:
    run('umount', str(MOUNT))
check = subprocess.run(['e2fsck', '-f', '-n', str(IMAGE)], capture_output=True, text=True)
report['e2fsck_returncode'] = check.returncode
report['e2fsck_output'] = check.stdout + check.stderr
if check.returncode != 0: raise SystemExit(report['e2fsck_output'])
report['raw_sha256'] = sha(IMAGE)
run('img2simg', str(IMAGE), str(OUT/'vendor-hybrid-arm64.img'))
report['sparse_sha256'] = sha(OUT/'vendor-hybrid-arm64.img')
report['sparse_bytes'] = (OUT/'vendor-hybrid-arm64.img').stat().st_size
(OUT/'vendor-image-report.json').write_text(json.dumps(report, indent=2)+'\n')
run('chown', 'builder:builder', str(IMAGE), str(OUT/'vendor-hybrid-arm64.img'), str(OUT/'vendor-image-report.json'))
print(json.dumps({k:v for k,v in report.items() if k not in ('changed_stock_files','added_files')}, indent=2))
