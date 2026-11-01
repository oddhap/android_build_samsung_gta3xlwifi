#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only NNP kernel source/link/Image checks, NOT execution/flash approval.

Uses fresh scratch, exact source locks, generated class IDs, actual ARM64 symbols,
capability load/store references and existing qtaguid ELF/Image validator. This
is structural link proof, not a general disassembly verifier or kernel/AVC test.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()


def accesses(text, address, mnemonic):
    """Conservative evidence of direct ADRP/ADD+LDR/STR addressing, not CFG proof."""
    bases = {}
    hits = []
    for line in text.splitlines():
        m = re.search(r'\badrp\s+(x\d+), 0x([0-9a-f]+)', line)
        if m:
            bases[m[1]] = int(m[2], 16)
        m = re.search(r'\badd\s+(x\d+), (x\d+), #0x([0-9a-f]+)', line)
        if m and m[2] in bases:
            bases[m[1]] = bases[m[2]] + int(m[3], 16)
        m = re.search(r'\b' + mnemonic + r'\s+w\d+, \[(x\d+)(?:, #0x([0-9a-f]+))?\]', line)
        if m and m[1] in bases and bases[m[1]] + int(m[2] or '0', 16) == address:
            hits.append(line.strip())
    return hits


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ['nm', 'objdump', 'objcopy']:
        p.add_argument('--' + n, type=Path, required=True)
    p.add_argument('--protected', type=Path, action='append', required=True)
    for n in ['source', 'kernel_output', 'image', 'experiment', 'owned_experiment', 'output']:
        p.add_argument(n, type=Path)
    a = p.parse_args()
    src, kout, image, experiment, owned, out = [getattr(a, n).resolve() for n in
        ['source', 'kernel_output', 'image', 'experiment', 'owned_experiment', 'output']]
    protected = [src, kout, experiment, owned] + [x.resolve() for x in a.protected]
    if any(out == x or x in out.parents for x in protected):
        p.error('Scratch must be outside all protected source/output/experiment paths, including aliases')
    if out.exists() or out.is_symlink():
        p.error('Scratch must not already exist')
    out.mkdir(parents=True, exist_ok=False)
    r = {'passed': False, 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
         'scope': 'source/ELF/Image structural link only, not whole loader/kernel/AVC/runtime',
         'live_namespace_policy_reload_exec_tested': False, 'security_approved': False, 'flash_ready': False}
    try:
        lock = json.loads((experiment/'staging-lock.json').read_text())
        project = next(q for q in lock['projects'] if q['path'] == 'kernel/samsung/gta3xlwifi')
        assert len(project['files']) == 5
        assert sha(experiment/project['patch']) == project['sha256']
        for f in project['files']:
            assert sha(src/f['path']) == f['staged_sha256'], f['path']
        assert '# CONFIG_USER_NS is not set' in (kout/'.config').read_text().splitlines()
        generated = (kout/'security/selinux/flask.h').read_text()
        cls = int(re.search(r'^#define\s+SECCLASS_PROCESS2\s+(\d+)', generated, re.M)[1])
        symbols = {}
        for line in subprocess.check_output([str(a.nm.resolve()), '-n', str(kout/'vmlinux')], text=True).splitlines():
            words = line.split()
            if len(words) == 3 and re.fullmatch('[0-9a-f]+', words[0]):
                symbols[words[2]] = int(words[0], 16)
        helpers = [n for n in symbols if re.fullmatch(r'check_nnp_nosuid(?:\.[\w.]+)?', n)]
        assert len(helpers) == 1, helpers
        helper = helpers[0]
        cap = symbols['selinux_policycap_nnp_nosuid_transition']
        requested = [helper, 'selinux_bprm_set_creds', 'security_load_policycaps', 'our_mnt']
        dump = subprocess.check_output([str(a.objdump.resolve()), '-d',
            '--disassemble-symbols=' + ','.join(requested), str(kout/'vmlinux')], text=True)
        (out/'nnp-disassembly.txt').write_text(dump)
        def body(name):
            return re.search(r'^' + format(symbols[name], 'x') + r' <' + re.escape(name) +
                             r'>:\n(.*?)(?=^[0-9a-f]+ <|\Z)', dump, re.M | re.S)[1]
        h, exec_body, load = body(helper), body('selinux_bprm_set_creds'), body('security_load_policycaps')
        for name in ['our_mnt', 'avc_has_perm', 'security_bounded_transition']:
            assert re.search(r'\bbl\s+0x[0-9a-f]+ <' + name + '>', h), name
        assert re.search(r'\bmov\s+w2, #0x' + format(cls, 'x') + r'\b', h)
        assert exec_body.count('<' + helper + '>') == 2
        assert accesses(h, cap, 'ldr') and accesses(load, cap, 'str')
        assert re.search(r'\bmov\s+x1, #0x5\b', load) and '<ebitmap_get_bit>' in load
        subprocess.run([sys.executable, str(Path(__file__).with_name('check-socket-owned-kernel.py')),
            '--objdump', str(a.objdump.resolve()), '--objcopy', str(a.objcopy.resolve()),
            str(src), str(kout), str(image), str(owned), str(out/'owned-image-proof')], check=True)
        r.update(passed=True, process2_kernel_class_id=cls, nnp_helper=helper,
                 capability_address=hex(cap), capability_read_in_exec_helper=accesses(h, cap, 'ldr'),
                 capability_store_on_load=accesses(load, cap, 'str'),
                 namespace_avc_bounded_calls_present=True, explicit_and_auto_exec_calls_retained=True,
                 source_lock_sha256=sha(experiment/'staging-lock.json'),
                 image_sha256=sha(image), image_bytes=image.stat().st_size,
                 disassembly_sha256=sha(out/'nnp-disassembly.txt'),
                 owned_image_evidence='owned-image-proof/report.json')
    finally:
        (out/'report.json').write_text(json.dumps(r, indent=2) + '\n')
    print('PASS: actual namespace/AVC/bounded calls, capability references, class ID and exact ELF/Image; NOT runtime approval')


if __name__ == '__main__':
    main()
