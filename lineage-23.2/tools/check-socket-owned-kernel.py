#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate isolated socket-owned kernel binary/provenance, NOT runtime/flash approval.
Uses an exact experiment source lock, ELF symbol/fops inspection, disassembly,
and reconstructs Image in NEW scratch outside preserved source/output.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def fops_probe(elf):
    with elf.open('rb') as f:
        header = f.read(64)
        if header[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', header, 18)[0] != 183:
            raise ValueError('Not ELF64 little-endian AARCH64')
        shoff = struct.unpack_from('<Q', header, 40)[0]
        entsize, count = struct.unpack_from('<HH', header, 58)
        if entsize != 64 or not 1 < count < 10000:
            raise ValueError('Unexpected ELF section table')
        f.seek(shoff)
        sections = [struct.unpack('<IIQQQQIIQQ', f.read(64)) for _ in range(count)]
        symbols = {}
        for sec in sections:
            if sec[1] != 2:
                continue
            strings = sections[sec[6]]
            f.seek(strings[4]); names = f.read(strings[5])
            f.seek(sec[4]); table = f.read(sec[5])
            if sec[9] != 24:
                raise ValueError('Unexpected symbol size')
            for off in range(0, len(table), 24):
                name, info, other, ndx, value, size = struct.unpack_from('<IBBHQQ', table, off)
                end = names.index(b'\0', name)
                label = names[name:end].decode('utf8')
                if label in ('qtudev_ioctl', 'qtudev_fops'):
                    symbols[label] = (ndx, value, size)
        if set(symbols) != {'qtudev_ioctl','qtudev_fops'}:
            raise ValueError('Missing linked private ioctl/fops')
        ndx, addr, size = symbols['qtudev_fops']
        section = sections[ndx]
        f.seek(section[4] + addr-section[3]); data = f.read(size)
        pointer = struct.pack('<Q', symbols['qtudev_ioctl'][1])
        offsets = [o for o in range(0,len(data)-7,8) if data[o:o+8] == pointer]
        if len(offsets) != 2:
            raise ValueError('Expected both native and compat fops pointers to real ioctl')
        return {'ioctl_address':hex(symbols['qtudev_ioctl'][1]),
                'fops_address':hex(addr), 'ioctl_pointer_offsets':offsets}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--objdump', type=Path, required=True)
    p.add_argument('--objcopy', type=Path, required=True)
    for n in ('source','kernel_output','image','experiment','output'):
        p.add_argument(n,type=Path)
    a = p.parse_args()
    src,kout,image,experiment,out = (getattr(a,n).resolve() for n in
                                    ('source','kernel_output','image','experiment','output'))
    if any(out == protected or protected in out.parents for protected in (src,kout)):
        p.error('Output must be outside kernel source/output, including aliases')
    out.mkdir(parents=True,exist_ok=False)
    r={'passed':False,'started_at_utc':datetime.now(timezone.utc).isoformat(),
       'scope':'source/protocol/ELF/link proof only, not kernel execution',
       'physical_lifecycle_tested':False,'flash_approved':False}
    try:
        lock=json.loads((experiment/'staging-lock.json').read_text())
        kernel=next(q for q in lock['projects'] if q['path']=='kernel/samsung/gta3xlwifi')
        for item in kernel['files']:
            if sha(src/item['path']) != item['staged_sha256']:
                raise ValueError('Built source differs from experimental lock: '+item['path'])
        r['source_revision']=subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()
        if (src/'.git/objects/info/alternates').exists():
            raise ValueError('External object alternate in isolated kernel')
        r['source_sha256']={x['path']:sha(src/x['path']) for x in kernel['files']}
        r['kernel_config_sha256']=sha(kout/'.config')
        r['vmlinux_sha256']=sha(kout/'vmlinux')
        r['image_sha256']=sha(image)
        if sha(kout/'arch/arm64/boot/Image') != r['image_sha256']:
            raise ValueError('Archived Image is not built output')
        config=(kout/'.config').read_text().splitlines()
        for flag in ('CONFIG_NETFILTER_XT_MATCH_QTAGUID=y','CONFIG_COMPAT=y','CONFIG_IPV6=y'):
            if flag not in config:raise ValueError('Missing '+flag)
        if image.stat().st_size >= 33554432 or image.read_bytes()[56:60]!=b'ARM\x64':
            raise ValueError('Invalid/oversize raw ARM64 Image')
        command=[str(a.objcopy.resolve()),'-O','binary','-R','.note','-R','.note.gnu.build-id',
                 '-R','.comment','-S',str(kout/'vmlinux'),str(out/'Image')]
        subprocess.run(command,check=True)
        if sha(out/'Image')!=r['image_sha256']:raise ValueError('ELF reconstruction does not match Image')
        r['reconstructed_image_sha256']=sha(out/'Image')
        r['fops']=fops_probe(kout/'vmlinux')
        dump=subprocess.check_output([str(a.objdump.resolve()),'-d',
            '--disassemble-symbols=qtudev_ioctl,inet_release,inet6_release',str(kout/'vmlinux')],text=True)
        (out/'disassembly.txt').write_text(dump)
        r['disassembly_sha256']=sha(out/'disassembly.txt')
        match=re.search(r'<qtudev_ioctl>:\n(.*?)(?=^[0-9a-f]+ <|\Z)',dump,re.M|re.S)
        if not match or '#0x7151' not in match.group(1) or '<capable>' not in match.group(1):
            raise ValueError('Private request/capability gate missing in actual linked ioctl')
        if '<qtaguid_untag>' not in dump or not re.search(r'\bbl\s+0x[0-9a-f]+ <inet_release>',dump):
            raise ValueError('Existing IPv4/IPv6 final-release path missing')
        r.update(passed=True,native_compat_ioctl_linked=True,private_command_and_capability_gate_linked=True,
                 existing_release_hooks_retained=True,image_bytes=image.stat().st_size)
    finally:
        r['finished_at_utc']=datetime.now(timezone.utc).isoformat()
        (out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
    print('PASS: linked native/compat private ioctl and exact Image reconstruction; NOT execution or flash approval')


if __name__=='__main__':main()
