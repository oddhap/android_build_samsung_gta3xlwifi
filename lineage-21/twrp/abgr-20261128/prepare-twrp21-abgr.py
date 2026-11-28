#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""LineageOS 21 TWRP with the correct (blue) accent colour, nothing else changed.

Offline only; no device access. Input: the published LineageOS 21 ARM64 TWRP
twrp-3.7.1_12-gta3xlwifi-arm64-20261015.img (10c2c2ee..., os_version 0x1c0001aa).
Changes exactly two ramdisk files:
  1. system/lib64/libminuitwrp.so: 14a17810... -> 24a239bf..., the library built
     from the same twrp-12.1-pinfree tree with only TARGET_RECOVERY_PIXEL_FORMAT :=
     "ABGR_8888" (adds -DRECOVERY_ABGR: R/B swap for the decon fbdev, whose panel
     shows red/blue swapped; accent #0090CA appeared as amber). The unchanged-config
     rebuild in the same OUT_DIR reproduced 14a17810... byte for byte. The same
     library is in the LineageOS 24 TWRP 33875693..., where the owner confirmed the
     blue accent on 2026-11-21.
  2. ramdisk-files.sha256sum: the library line gets its new hash.
fstab files (with /product), the crypto scripts, kernel, recovery DTBO, board,
cmdline, os_version and the SEANDROIDENFORCE trailer are unchanged. Only
ramdisk_size, recovery_dtbo_offset and the SHA1 id are recomputed (method of the
LineageOS 24 twrp-fstab-abgr-20261121 rewrite). Also rebuilds the Odin AP tar with
the same member layout and the unchanged vbmeta.img.
"""
import hashlib, io, json, lzma, struct, subprocess, tarfile
from pathlib import Path

A = Path('/srv/android/artifacts/lineage21-twrp-20261128')
SRC_IMG = Path('/srv/android/artifacts/lineage21-bt-20261124/public-assets/twrp-3.7.1_12-gta3xlwifi-arm64-20261015.img')
SRC_TAR = SRC_IMG.with_name('twrp-3.7.1_12-gta3xlwifi-arm64-20261015-ap.tar')
LIB = Path('/srv/android/work/twrp-abgr-20261121/abgr/libminuitwrp.so')
OUT_IMG = A / 'twrp-3.7.1_12-gta3xlwifi-arm64-20261128.img'
OUT_TAR = A / 'twrp-3.7.1_12-gta3xlwifi-arm64-20261128-ap.tar'
P = 2048
SIZE = 47185920
LIBNAME = 'system/lib64/libminuitwrp.so'
OLD_LIB, NEW_LIB = ('14a178104c617f37767af5ada84e4c72bb8f3b3cec17cc6b05f254b8a4a41124',
                    '24a239bf02102f04ddaf67633c9d57e4180f9c11380922c1c6f2f01484ef4a11')
sha = lambda b: hashlib.sha256(b).hexdigest()
pg = lambda n: (n + P - 1) // P * P


def parse(b):
    f = struct.unpack_from('<8s10I', b, 0)
    assert f[0] == b'ANDROID!' and f[8] == P and f[9] == 1
    rsize, roff, hsize = struct.unpack_from('<IQI', b, 1632)
    k, r = P, P + pg(f[1]); s = r + pg(f[3]); o = s + pg(f[5]); end = o + pg(rsize)
    assert roff == o and f[5] == 0 and b[end:end + 16] == b'SEANDROIDENFORCE' and not any(b[end + 16:])
    return dict(kernel=b[k:k + f[1]], ramdisk=b[r:r + f[3]], dtbo=b[o:o + rsize], dtbo_off=o, end=end,
                header=b[:P], os_version=f[10])


def image_id(kernel, ramdisk, dtbo):
    h = hashlib.sha1()
    for part in (kernel, ramdisk, b'', dtbo):
        h.update(part); h.update(struct.pack('<I', len(part)))
    return h.digest() + bytes(12)


def entries(cp):
    i, out = 0, []
    while True:
        h = cp[i:i + 110]; assert h[:6] == b'070701'
        f = [int(h[6 + 8 * j:14 + 8 * j], 16) for j in range(13)]
        name = cp[i + 110:i + 110 + f[11] - 1].decode(); ds = (i + 110 + f[11] + 3) // 4 * 4
        nxt = (ds + f[6] + 3) // 4 * 4
        out.append((name, i, ds, f[6], nxt))
        if name == 'TRAILER!!!':
            assert not any(cp[nxt:])
            return out
        i = nxt


def identity(body):
    b = bytearray(body); b[44:48] = bytes(4)
    return sha(bytes(b))


A.mkdir(parents=True, exist_ok=True)
assert not OUT_IMG.exists() and not OUT_TAR.exists()
img = SRC_IMG.read_bytes()
assert sha(img) == '10c2c2ee77ee593ace840a12fb90145809e4521942b681bcee6e9c3b364370ed' and len(img) == 40275984
assert identity(img) == '5eb6d0f8fbb75f08d7156d3de1118fc429eff44543fd61e6a7c1b8c99dc21239'
lib = LIB.read_bytes()
assert sha(lib) == NEW_LIB
old = parse(img)
assert old['end'] + 16 == len(img)
assert old['os_version'] == 0x1c0001aa and old['header'][576:608] == image_id(old['kernel'], old['ramdisk'], old['dtbo'])
cpio = lzma.decompress(old['ramdisk'])
ents = entries(cpio)
data = {n: cpio[ds:ds + fs] for n, _, ds, fs, _ in ents}
assert sha(data[LIBNAME]) == OLD_LIB
MANIFEST = 'ramdisk-files.sha256sum'
ol = OLD_LIB.encode() + b'  ./' + LIBNAME.encode() + b'\n'
nl = NEW_LIB.encode() + b'  ./' + LIBNAME.encode() + b'\n'
assert data[MANIFEST].count(ol) == 1
repl = {LIBNAME: lib, MANIFEST: data[MANIFEST].replace(ol, nl)}

parts = []
for name, i, ds, fs, nxt in ents:
    if name not in repl:
        parts.append(cpio[i:nxt]); continue
    hdr = bytearray(cpio[i:ds])
    hdr[54:62] = b'%08X' % len(repl[name])  # c_filesize
    body = repl[name]
    parts.append(bytes(hdr) + body + bytes((-len(body)) % 4))
new_cpio = b''.join(parts)
assert len(cpio) % 256 == 0 and len(cpio) - ents[-1][4] < 256
new_cpio += bytes((-len(new_cpio)) % 256)
nents = entries(new_cpio)
assert [e[0] for e in nents] == [e[0] for e in ents]
ndata = {n: new_cpio[ds:ds + fs] for n, _, ds, fs, _ in nents}
for (name, i, ds, fs, nxt), (_, ni, nds, nfs, nnxt) in zip(ents, nents):
    oh, nh = bytearray(cpio[i:ds]), bytearray(new_cpio[ni:nds])
    if name in repl:
        assert ndata[name] == repl[name]; oh[54:62] = nh[54:62]
    else:
        assert ndata[name] == data[name]
    assert oh == nh, name
changed = sorted(n for n in data if data[n] != ndata[n])
assert changed == sorted(repl), changed
for n in ('system/etc/recovery.fstab', 'system/etc/twrp.fstab'):
    assert b'by-name/product ' in ndata[n] and ndata[n] == data[n]

# Same xz stream structure as the input (one block, CRC32, LZMA2 dict 32 MiB).
xz = subprocess.run(['xz', '--format=xz', '--check=crc32', '--lzma2=preset=9,dict=32MiB', '-T1', '-c'],
                    input=new_cpio, capture_output=True, check=True).stdout
assert lzma.decompress(xz) == new_cpio and xz[6:8] == old['ramdisk'][6:8] == b'\x00\x01'

hdr = bytearray(old['header'])
struct.pack_into('<I', hdr, 16, len(xz))
dtbo_off = P + pg(len(old['kernel'])) + pg(len(xz))
struct.pack_into('<Q', hdr, 1636, dtbo_off)
hdr[576:608] = image_id(old['kernel'], xz, old['dtbo'])
pad = lambda b: b + bytes((-len(b)) % P)
new = bytes(hdr) + pad(old['kernel']) + pad(xz) + pad(old['dtbo']) + b'SEANDROIDENFORCE'
assert len(new) <= SIZE
n = parse(new)
assert n['kernel'] == old['kernel'] and n['dtbo'] == old['dtbo'] and n['os_version'] == 0x1c0001aa
assert lzma.decompress(n['ramdisk']) == new_cpio
diff_hdr = [i for i in range(P) if hdr[i] != old['header'][i]]
assert all(16 <= i < 20 or 1636 <= i < 1644 or 576 <= i < 608 for i in diff_hdr), diff_hdr
OUT_IMG.write_bytes(new)

# Odin AP tar: same member names/order/metadata, new recovery.img, same vbmeta.img.
with tarfile.open(SRC_TAR) as src:
    members = src.getmembers()
    assert [m.name for m in members] == ['recovery.img', 'vbmeta.img']
    assert src.extractfile('recovery.img').read() == img
    vbmeta = src.extractfile('vbmeta.img').read()
    fmt = src.format
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w', format=fmt) as t:
    for m, payload in zip(members, (new, vbmeta)):
        info = tarfile.TarInfo(m.name)
        info.size, info.mode, info.uid, info.gid = len(payload), m.mode, m.uid, m.gid
        info.uname, info.gname = m.uname, m.gname
        info.mtime = 1795824000 if m.name == 'recovery.img' else m.mtime  # 2026-11-28 00:00 UTC
        t.addfile(info, io.BytesIO(payload))
OUT_TAR.write_bytes(buf.getvalue())
with tarfile.open(OUT_TAR) as t:
    assert t.extractfile('recovery.img').read() == new and t.extractfile('vbmeta.img').read() == vbmeta

rep = dict(passed=True, scope=__doc__, input_image_sha256=sha(img), output_image_sha256=sha(new),
           output_bytes=len(new), os_version_word='0x%08x' % n['os_version'],
           kernel_sha256=sha(n['kernel']), kernel_identical=True, recovery_dtbo_identical=True,
           fstab_unchanged_with_product=True,
           ramdisk_old=dict(xz_bytes=len(old['ramdisk']), cpio_bytes=len(cpio), cpio_sha256=sha(cpio)),
           ramdisk_new=dict(xz_bytes=len(xz), cpio_bytes=len(new_cpio), cpio_sha256=sha(new_cpio)),
           cpio_entries=len(ents), changed_cpio_entries=changed,
           file_sha256_old={k: sha(data[k]) for k in changed}, file_sha256_new={k: sha(ndata[k]) for k in changed},
           header_fields_changed=['ramdisk_size', 'recovery_dtbo_offset', 'id'],
           recovery_dtbo_offset_old=old['dtbo_off'], recovery_dtbo_offset_new=dtbo_off,
           ota_preflight_identity=dict(length=len(new), sha256_bytes44_47_zeroed=identity(new)),
           ap_tar=dict(name=OUT_TAR.name, sha256=sha(OUT_TAR.read_bytes()), bytes=OUT_TAR.stat().st_size,
                       vbmeta_sha256=sha(vbmeta)),
           device_written=False, physically_tested=False)
(A / 'twrp21-abgr-report.json').write_text(json.dumps(rep, indent=2) + '\n')
print(json.dumps({k: v for k, v in rep.items() if k != 'scope'}, indent=2))
