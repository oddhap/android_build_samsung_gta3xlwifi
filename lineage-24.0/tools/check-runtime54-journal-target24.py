#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged service-connectivity.jar to the snapshot54 boot_id descriptor close.

Usage: check-runtime54-journal-target24.py TOP ARCHIVE GEOMETRY EDITS OUTPUT

Background (2026-11-27, build 53): Gta3xlwifiStatsJournal.readKernelBootId() wrapped an
Os.open() descriptor in new FileInputStream(fd), which on Android does not own the
descriptor, so every journal operation leaked one fd in system_server until EMFILE.
Snapshot54 closes it with Os.close(fd) in finally.

Requires: the staged journal source equals its after-hash; SYSTEM/apex/com.android.tethering.capex
-> original_apex -> javalib/service-connectivity.jar (built deapexer) disassembled with the
built dexdump has Gta3xlwifiStatsJournal.readKernelBootId() calling both Os.open and
Os.close(FileDescriptor) (prebuilt SDK dexdump; build 53 negative control: Os.open + FileInputStream.close,
no Os.close). Package check only; the device probe is runtime54-fdleak.
"""
import hashlib, io, json, re, subprocess, sys, tempfile, zipfile
from pathlib import Path

top, archive, geometry, edits, output = map(Path, sys.argv[1:])
assert not output.exists()
g = json.loads(geometry.read_text())
assert g['artifact_checks_passed']
h = hashlib.sha256()
with archive.open('rb') as f:
    for block in iter(lambda: f.read(1 << 20), b''):
        h.update(block)
assert h.hexdigest() == g['archive_sha256'], 'Archive differs from the checked geometry report'
e = json.loads(edits.read_text())
journal = top/'packages/modules/Connectivity/service/src/com/android/server/Gta3xlwifiStatsJournal.java'
assert list(e) == [str(journal)]
assert hashlib.sha256(journal.read_bytes()).hexdigest() == e[str(journal)]['after_sha256']
with zipfile.ZipFile(archive) as z:
    capex = z.read('SYSTEM/apex/com.android.tethering.capex')
with zipfile.ZipFile(io.BytesIO(capex)) as c:
    apex = c.read('original_apex')
bin_ = top/'out/host/linux-x86/bin'
method = None
with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    (d/'t.apex').write_bytes(apex)
    subprocess.run([str(bin_/'deapexer'), '--debugfs_path', str(bin_/'debugfs_static'), '--fsckerofs_path',
                    str(bin_/'fsck.erofs'), 'extract', str(d/'t.apex'), str(d/'x')],
                   check=True, capture_output=True)
    jar = (d/'x/javalib/service-connectivity.jar').read_bytes()
    dexdump = top/'prebuilts/sdk/tools/linux/bin/dexdump'
    # service-connectivity is jarjar-repackaged (android.net.connectivity.com.android.server).
    head = re.compile(r'\|\[[0-9a-f]+\] (?:android\.net\.connectivity\.)?com\.android\.server\.'
                      r'Gta3xlwifiStatsJournal\.readKernelBootId:\(\)Ljava/lang/String;')
    with zipfile.ZipFile(io.BytesIO(jar)) as j:
        for n in j.namelist():
            if not n.endswith('.dex'):
                continue
            (d/n).write_bytes(j.read(n))
            text = subprocess.run([str(dexdump), '-d', str(d/n)], check=True,
                                  capture_output=True).stdout.decode('utf-8', 'replace')
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if head.search(line):
                    assert method is None, 'readKernelBootId found twice'
                    body = []
                    for nxt in lines[i+1:]:
                        if re.search(r'\|\[[0-9a-f]+\] ', nxt):
                            break
                        body.append(nxt)
                    method = '\n'.join(body)
assert method is not None, 'readKernelBootId not in packaged dex'
assert 'Landroid/system/Os;.open:(Ljava/lang/String;II)Ljava/io/FileDescriptor;' in method
closes = method.count('Landroid/system/Os;.close:(Ljava/io/FileDescriptor;)V')
assert closes >= 1, 'packaged readKernelBootId never closes the boot_id descriptor'
output.write_text(json.dumps({'passed': True,
                              'tethering_capex_sha256': hashlib.sha256(capex).hexdigest(),
                              'service_connectivity_jar_sha256': hashlib.sha256(jar).hexdigest(),
                              'journal_after_sha256': e[str(journal)]['after_sha256'],
                              'readKernelBootId_os_close_call_sites': closes,
                              'runtime_tested': False}, indent=2)+'\n')
print('PASS journal boot_id close packaged:', output, 'Os.close sites:', closes)
