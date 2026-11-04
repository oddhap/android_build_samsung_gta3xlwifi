#!/usr/bin/env python3
"""Static ARM64 module/version audit; no loading, signing or device access."""
import argparse, hashlib, json, re, struct
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def symbols(p):
    result = {}
    for line in p.read_text().splitlines():
        crc, name, owner, *_ = line.split()
        assert name not in result, name
        result[name] = (int(crc, 16) & 0xffffffff, owner)
    return result


def module(p, sym, release):
    data = p.read_bytes()
    assert data[:7] == b'\x7fELF\x02\x01\x01', p
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    assert h[1:4] == (1, 183, 1), (p, h[1:4])  # ET_REL, AArch64
    shoff, entsize, count, stridx = h[6], h[11], h[12], h[13]
    assert entsize == 64 and 0 < stridx < count
    assert shoff + count * entsize <= len(data)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * entsize) for i in range(count)]
    def section(hdr):
        off, size = hdr[4:6]
        assert off + size <= len(data)
        return data[off:off + size]
    names = section(headers[stridx])
    sections = {names[x[0]:].split(b'\0', 1)[0].decode(): section(x)
                for x in headers if x[1] != 8}  # NOBITS has no file payload
    info = sections['.modinfo'].split(b'\0')
    vermagic, = [x.decode().split('=', 1)[1] for x in info if x.startswith(b'vermagic=')]
    assert vermagic.split()[0] == release, vermagic
    assert 'modversions' in vermagic.split(), vermagic
    versions = sections['__versions']
    # Actual ARM64 headers: unsigned long crc; char name[64-sizeof(unsigned long)].
    assert versions and len(versions) % 64 == 0
    imports = {}
    for i in range(0, len(versions), 64):
        crc, = struct.unpack_from('<Q', versions, i)
        name = versions[i + 8:i + 64].split(b'\0', 1)[0].decode()
        assert name and name not in imports and name in sym, (p, name)
        assert crc & 0xffffffff == sym[name][0], (p, name, hex(crc), sym[name])
        imports[name] = f'0x{crc & 0xffffffff:08x}'
    return {'path': str(p), 'sha256': sha(p), 'elf': 'ELF64 LE AArch64 ET_REL',
            'vermagic': vermagic, 'checked_import_count': len(imports), 'imports': imports}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('base', type=Path)
    ap.add_argument('artifacts', type=Path)
    ap.add_argument('report', type=Path)
    args = ap.parse_args()
    src, out, art = args.base/'src', args.base/'out', args.artifacts
    before, after = art/'vmlinux-Module.symvers-before', out/'Module.symvers'
    old, new = symbols(before), symbols(after)
    assert all(new.get(k) == v for k, v in old.items()), 'vmlinux/module export changed'
    header = (src/'include/linux/moduleparam.h').read_text()
    assert '#define MAX_PARAM_PREFIX_LEN (64 - sizeof(unsigned long))' in header
    release, = re.findall(r'^#define UTS_RELEASE "([^"]+)"', (out/'include/generated/utsrelease.h').read_text(), re.M)
    paths = sorted(out.rglob('*.ko'))
    assert {p.name for p in paths} == {'kutf.ko'}, paths
    rows = [module(p, new, release) for p in paths]
    assert sha(out/'arch/arm64/boot/Image') == (art/'Image-before.sha256').read_text().split()[0]
    assert sha(out/'.config') == sha(art/'kernel.config-before')
    report = {'passed': True, 'scope': 'Static module import CRC and ELF audit only; no live load, hardware, complete ABI or boot proof.',
              'runner_sha256': sha(Path(__file__)), 'base': str(args.base),
              'gator_build_status': 'FAILED: walk_stackframe undefined; not present in original exports either. No gator ABI/load approval.',
              'vmlinux_exports_retained': len(old), 'total_exports_after': len(new),
              'inputs_sha256': {str(p): sha(p) for p in [before, after, out/'.config', out/'include/generated/utsrelease.h', src/'include/linux/moduleparam.h']},
              'image_sha256': sha(out/'arch/arm64/boot/Image'), 'modules': rows}
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS:', [(p['path'], p['checked_import_count']) for p in rows])


if __name__ == '__main__':
    main()
