#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owner request 2026-11-21: TWRP without /product and with the correct (blue) accent colour.

Offline only; no device access. Input: the installed recovery partition image
96b3de24... (choice (a) crypto-script image). Changes exactly these ramdisk files:
  1. system/etc/recovery.fstab: the /product line is removed (build 40+ ROM has
     no product partition; /product -> /system/product). NikGapps otherwise picks
     the old, unused product partition.
  2. system/etc/twrp.fstab: /product and /product_image are removed (TWRP UI no
     longer offers mounting, wiping, flashing or backing up the unused partition).
  3. system/lib64/libminuitwrp.so: rebuilt from twrp-12.1-pinfree with only
     TARGET_RECOVERY_PIXEL_FORMAT := "ABGR_8888" added to BoardConfig.mk. The decon
     fbdev reports BGRA (red offset 16) but the panel shows red/blue swapped, so
     the theme accent #0090CA appeared as amber #CA9000. The flag adds exactly
     -DRECOVERY_ABGR to libminuitwrp (gr_color R/B swap, png_set_bgr, JPEG swap).
     The unchanged-config rebuild in the same separate OUT_DIR reproduced the
     installed library byte-for-byte (14a17810...).
  4. ramdisk-files.sha256sum: the three lines get their new hashes.
All other cpio entries are copied byte-for-byte; kernel, recovery DTBO, board,
cmdline, os_version 0x220001ab, addresses and the SEANDROIDENFORCE trailer are
unchanged. Only ramdisk_size, recovery_dtbo_offset and the SHA1 id are recomputed.
"""
import hashlib, json, lzma, struct, subprocess
from pathlib import Path

W = Path(__file__).resolve().parent
I = W/'inputs'
SIZE, P = 47185920, 2048
sha = lambda b: hashlib.sha256(b).hexdigest()
img = (W.parent/'twrp-crypto-script-a-20261121'/'recovery-a-partition.img').read_bytes()
BEFORE = '96b3de24d7c36b8abe390db35e8a098e1c4d69500105f0a127ea09beaccb5e61'
assert len(img) == SIZE and sha(img) == BEFORE
out_img, out_rep = W/'recovery-fstab-abgr-partition.img', W/'report.json'
assert not out_img.exists() and not out_rep.exists()
pg = lambda n: (n + P - 1)//P*P

def parse(b):
    f = struct.unpack_from('<8s10I', b, 0)
    assert f[0] == b'ANDROID!' and f[8] == P and f[9] == 1
    rsize, roff, hsize = struct.unpack_from('<IQI', b, 1632)
    k, r = P, P + pg(f[1]); s = r + pg(f[3]); o = s + pg(f[5]); end = o + pg(rsize)
    assert roff == o and f[5] == 0 and b[end:end+16] == b'SEANDROIDENFORCE' and not any(b[end+16:])
    return dict(kernel=b[k:k+f[1]], ramdisk=b[r:r+f[3]], dtbo=b[o:o+rsize], dtbo_off=o, end=end,
                header=b[:P], os_version=f[10], hsize=hsize)

def image_id(kernel, ramdisk, dtbo):
    h = hashlib.sha1()
    for part in (kernel, ramdisk, b'', dtbo):
        h.update(part); h.update(struct.pack('<I', len(part)))
    return h.digest() + bytes(12)

def entries(cp):
    i, out = 0, []
    while True:
        h = cp[i:i+110]; assert h[:6] == b'070701'
        f = [int(h[6+8*j:14+8*j], 16) for j in range(13)]
        name = cp[i+110:i+110+f[11]-1].decode(); ds = (i+110+f[11]+3)//4*4
        nxt = (ds+f[6]+3)//4*4
        out.append((name, i, ds, f[6], nxt))
        if name == 'TRAILER!!!':
            assert not any(cp[nxt:])
            return out
        i = nxt

old = parse(img)
assert old['os_version'] == 0x220001ab and old['header'][576:608] == image_id(old['kernel'], old['ramdisk'], old['dtbo'])
cpio = lzma.decompress(old['ramdisk'])
ents = entries(cpio)
data = {n: cpio[ds:ds+fs] for n, _, ds, fs, _ in ents}

EXPECT_OLD = {
    'system/etc/recovery.fstab': '3b3394475c26bf2f032a0a5a07718d25c003cf9417fede9259b45c2e2f64a60e',
    'system/etc/twrp.fstab': '6678fbcd9a26bc5be6c70e50ed7055a70a6b0b3c01032a45a173c02c0ab33033',
    'system/lib64/libminuitwrp.so': '14a178104c617f37767af5ada84e4c72bb8f3b3cec17cc6b05f254b8a4a41124',
}
EXPECT_NEW = {
    'system/etc/recovery.fstab': '8808cee591110126b81087d8143dd7bfa350db3ef54feaf96cbbc84bbe7e05b2',
    'system/etc/twrp.fstab': '2d7d4df50ff534c767bba92f8c87e80b9d58b1cdd037acd4d1781521c99efa70',
    'system/lib64/libminuitwrp.so': '24a239bf02102f04ddaf67633c9d57e4180f9c11380922c1c6f2f01484ef4a11',
}
repl = {}
for name, h in EXPECT_OLD.items():
    assert sha(data[name]) == h, name
    new = (I/Path(name).name).read_bytes()
    assert sha(new) == EXPECT_NEW[name], name
    repl[name] = new
# fstab: exactly the product lines removed, nothing else.
for name in ('system/etc/recovery.fstab', 'system/etc/twrp.fstab'):
    o, n = data[name].decode().splitlines(True), repl[name].decode().splitlines(True)
    removed = [l for l in o if l not in n]
    assert [l for l in o if l not in removed] == n and removed and all('by-name/product ' in l for l in removed), name
    assert 'product' not in repl[name].decode()
MANIFEST = 'ramdisk-files.sha256sum'
m = data[MANIFEST]
for name in EXPECT_OLD:
    ol = data[name] and (sha(data[name]).encode() + b'  ./' + name.encode() + b'\n')
    nl = sha(repl[name]).encode() + b'  ./' + name.encode() + b'\n'
    assert m.count(ol) == 1, name
    m = m.replace(ol, nl)
repl[MANIFEST] = m

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
ndata = {n: new_cpio[ds:ds+fs] for n, _, ds, fs, _ in nents}
for (name, i, ds, fs, nxt), (_, ni, nds, nfs, nnxt) in zip(ents, nents):
    oh, nh = bytearray(cpio[i:ds]), bytearray(new_cpio[ni:nds])
    if name in repl:
        assert ndata[name] == repl[name]; oh[54:62] = nh[54:62]
    else:
        assert ndata[name] == data[name]
    assert oh == nh, name
changed = sorted(n for n in data if data[n] != ndata[n])
assert changed == sorted(repl), changed

xz = subprocess.run(['xz', '--format=xz', '--check=crc32', '--lzma2=preset=9,dict=32MiB', '-T1', '-c'],
                    input=new_cpio, capture_output=True, check=True).stdout
assert lzma.decompress(xz) == new_cpio and xz[6:8] == b'\x00\x01'

hdr = bytearray(old['header'])
struct.pack_into('<I', hdr, 16, len(xz))
dtbo_off = P + pg(len(old['kernel'])) + pg(len(xz))
struct.pack_into('<Q', hdr, 1636, dtbo_off)
hdr[576:608] = image_id(old['kernel'], xz, old['dtbo'])
pad = lambda b: b + bytes((-len(b)) % P)
body = bytes(hdr) + pad(old['kernel']) + pad(xz) + pad(old['dtbo']) + b'SEANDROIDENFORCE'
assert len(body) <= SIZE
new = body + bytes(SIZE - len(body))
n = parse(new)
assert n['kernel'] == old['kernel'] and n['dtbo'] == old['dtbo'] and n['os_version'] == 0x220001ab
assert lzma.decompress(n['ramdisk']) == new_cpio
diff_hdr = [i for i in range(P) if hdr[i] != old['header'][i]]
assert all(16 <= i < 20 or 1636 <= i < 1644 or 576 <= i < 608 for i in diff_hdr), diff_hdr
assert hdr[44:48] == old['header'][44:48] and hdr[48:64] == old['header'][48:64] and hdr[64:576] == old['header'][64:576]
# OTA preflight identity (recovery_header_sync.cpp): SHA256 of the first N bytes
# (header..trailer) with bytes 44..47 zeroed; N = used bytes incl. trailer.
ident = bytearray(body); ident[44:48] = bytes(4)
out_img.write_bytes(new)
rep = dict(passed=True, scope=__doc__, input_partition_sha256=sha(img), output_partition_sha256=sha(new),
           output_bytes=len(new), used_bytes=len(body), os_version_word='0x%08x' % n['os_version'],
           kernel_sha256=sha(n['kernel']), kernel_identical=True, recovery_dtbo_identical=True,
           ramdisk_old=dict(xz_bytes=len(old['ramdisk']), cpio_bytes=len(cpio), cpio_sha256=sha(cpio)),
           ramdisk_new=dict(xz_bytes=len(xz), cpio_bytes=len(new_cpio), cpio_sha256=sha(new_cpio)),
           cpio_entries=len(ents), changed_cpio_entries=changed,
           file_sha256_old={k: sha(data[k]) for k in changed}, file_sha256_new={k: sha(ndata[k]) for k in changed},
           header_bytes_changed=diff_hdr and [min(diff_hdr), max(diff_hdr)], header_fields_changed=['ramdisk_size', 'recovery_dtbo_offset', 'id'],
           recovery_dtbo_offset_old=old['dtbo_off'], recovery_dtbo_offset_new=dtbo_off,
           ota_preflight_identity=dict(length=len(body), sha256_bytes44_47_zeroed=sha(bytes(ident))),
           device_written=False)
out_rep.write_text(json.dumps(rep, indent=2)+'\n')
print(json.dumps({k: v for k, v in rep.items() if k != 'scope'}, indent=2))
