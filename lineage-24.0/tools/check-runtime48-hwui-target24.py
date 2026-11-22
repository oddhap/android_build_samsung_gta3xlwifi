#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind the packaged libhwui to the reviewed snapshot48 Bitmap.cpp change.

Usage: check-runtime48-hwui-target24.py TOP ARCHIVE GEOMETRY EDITS REFERENCE OUTPUT

Requires: the source Bitmap.cpp equals the staged after-hash; both 32- and 64-bit
libhwui.so are ELF for the right machine, carry the fallback log string and differ
from build 47. This is a package check, not a runtime proof (the physical F-Droid install is).
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

top, archive, geometry, edits, reference, output = map(Path, sys.argv[1:])
assert not output.exists()
g = json.loads(geometry.read_text())
assert g['artifact_checks_passed']
sha = lambda b: hashlib.sha256(b).hexdigest()
h = hashlib.sha256()
with archive.open('rb') as f:
    for block in iter(lambda: f.read(1 << 20), b''):
        h.update(block)
assert h.hexdigest() == g['archive_sha256'], 'Archive differs from the checked geometry report'
e = json.loads(edits.read_text())
source = top/'frameworks/base/libs/hwui/jni/Bitmap.cpp'
assert list(e) == [str(source)]
assert sha(source.read_bytes()) == e[str(source)]['after_sha256'], 'Bitmap.cpp is not the staged snapshot48 text'
text = source.read_text()
for needle in ['writeImmutableAshmemBlob(ashmemId.c_str(), data, size)', 'ashmem_set_prot_region(fd.get(), PROT_READ)',
               'if (!immutable || errno != EINVAL)', '| (immutable ? F_SEAL_FUTURE_WRITE : 0)']:
    assert text.count(needle) == 1, needle
marker = b'parceling immutable bitmaps through read-only ashmem'
result = {'passed': False, 'bitmap_cpp_sha256': e[str(source)]['after_sha256'], 'libs': {}}
with zipfile.ZipFile(archive) as z, zipfile.ZipFile(reference) as old:
    for directory, elf_class, machine in [('lib', 1, 40), ('lib64', 2, 183)]:
        name = f'SYSTEM/{directory}/libhwui.so'
        data = z.read(name)
        assert data[:4] == b'\x7fELF' and data[4] == elf_class and struct.unpack_from('<H', data, 18)[0] == machine, name
        assert data.count(marker) >= 1, 'Fallback not compiled into '+name
        before = old.read(name)
        assert marker not in before and sha(before) != sha(data)
        result['libs'][name] = {'sha256': sha(data), 'build47_sha256': sha(before)}
result['passed'] = True
result['runtime_tested'] = False
output.write_text(json.dumps(result, indent=2)+'\n')
print('PASS hwui bitmap parcel fallback packaged:', output)
