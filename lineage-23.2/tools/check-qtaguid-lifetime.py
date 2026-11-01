#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only source/binary proof of Samsung qtaguid final-socket-release hook.
Not execution or general Android/kernel compatibility validation. Reconstructs
Image from the preserved linked vmlinux in a NEW scratch directory, never builds
or modifies the preserved kernel. Requires llvm-objdump and GNU objcopy paths.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE_IMAGE_SHA = '33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553'
FILES = ('net/ipv4/af_inet.c', 'net/ipv6/af_inet6.c',
         'net/netfilter/xt_qtaguid.c', 'include/linux/netfilter/xt_qtaguid.h')


def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--objdump', type=Path, required=True)
    p.add_argument('--objcopy', type=Path, required=True)
    for arg in ('source', 'kernel_output', 'selected_image', 'output'):
        p.add_argument(arg, type=Path)
    a = p.parse_args()
    source, kout, image, out = (getattr(a, x).resolve() for x in
                               ('source', 'kernel_output', 'selected_image', 'output'))
    for protected in (source, kout):
        if out == protected or protected in out.parents:
            p.error('Scratch must be outside preserved kernel source/output (including symlinks)')
    out.mkdir(parents=True, exist_ok=False)
    r = {'started_at_utc': datetime.now(timezone.utc).isoformat(), 'passed': False,
         'scope': 'offline source/linked-binary/Image identity; not kernel execution',
         'preserved_kernel_modified': False, 'physical_socket_lifecycle_tested': False}
    try:
        r['source_revision'] = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        r['source_sha256'] = {f: sha(source/f) for f in FILES}
        text = {f: (source/f).read_text() for f in FILES}
        ipv4, ipv6, qtag, header = (text[f] for f in FILES)
        if 'qtaguid_untag(sock, true);' not in ipv4 or 'return inet_release(sock);' not in ipv6:
            raise ValueError('Missing expected IPv4/IPv6 final-release source path')
        for needle in ('if (kernel)\n\t\tpid = sock_tag_entry->pid;',
                       'sock_put(sock_tag_entry->sk);', 'kfree(sock_tag_entry);',
                       'rb_erase(&sock_tag_entry->sock_node, &sock_tag_tree);'):
            if needle not in qtag:
                raise ValueError('Missing stored-owner/reference cleanup: ' + needle)
        if 'int qtaguid_untag(struct socket *sock, bool kernel);' not in header:
            raise ValueError('Unexpected kernel hook declaration')
        config = (kout/'.config').read_text()
        for setting in ('CONFIG_IPV6=y', 'CONFIG_NETFILTER_XT_MATCH_QTAGUID=y'):
            if setting not in config.splitlines():
                raise ValueError('Required built-in kernel config missing: ' + setting)
        r['kernel_config_sha256'] = sha(kout/'.config')
        r['vmlinux_sha256'] = sha(kout/'vmlinux')
        r['image_sha256'] = sha(image)
        if r['image_sha256'] != BASE_IMAGE_SHA or sha(kout/'arch/arm64/boot/Image') != BASE_IMAGE_SHA:
            raise ValueError('Selected/output Image differs from preserved port baseline')
        command = [str(a.objcopy.resolve()), '-O', 'binary', '-R', '.note', '-R',
                   '.note.gnu.build-id', '-R', '.comment', '-S', str(kout/'vmlinux'), str(out/'Image')]
        subprocess.run(command, check=True)
        r['image_reconstruction_argv'] = command
        r['reconstructed_image_sha256'] = sha(out/'Image')
        if r['reconstructed_image_sha256'] != BASE_IMAGE_SHA:
            raise ValueError('vmlinux is not the linked source of selected Image')
        dump = subprocess.check_output([str(a.objdump.resolve()), '-d',
            '--disassemble-symbols=inet_release,inet6_release,qtaguid_untag', str(kout/'vmlinux')], text=True)
        (out/'release-disassembly.txt').write_text(dump)
        r['disassembly_sha256'] = sha(out/'release-disassembly.txt')
        def function(name):
            m = re.search(r'^[0-9a-f]+ <' + re.escape(name) + r'>:\n(.*?)(?=^[0-9a-f]+ <|\Z)', dump, re.M | re.S)
            if not m:
                raise ValueError('Missing linked function: ' + name)
            return m.group(1)
        v4, v6 = function('inet_release'), function('inet6_release')
        if not re.search(r'\bbl\s+0x[0-9a-f]+ <inet_release>', v6):
            raise ValueError('No linked IPv6 -> IPv4 release call')
        before = re.split(r'\bbl\s+0x[0-9a-f]+ <qtaguid_untag>', v4)
        if len(before) != 2:
            raise ValueError('No unique linked IPv4 -> qtaguid_untag call')
        if not re.search(r'\bmov\s+w1, #0x1\b', before[0]):
            raise ValueError('No true kernel-owner argument preceding hook')
        # There must be no later instruction overwriting the second argument.
        tail = re.split(r'\bmov\s+w1, #0x1\b[^\n]*\n', before[0])[-1]
        if re.search(r'\t\w+\s+[wx]1,', tail):
            raise ValueError('Second argument overwritten before hook')
        function('qtaguid_untag')
        r.update(passed=True, ipv4_final_close_hook_linked=True,
                 ipv6_reaches_same_hook=True, hook_uses_stored_tagging_owner=True,
                 image_matches_exact_linked_vmlinux=True,
                 new_kernel_patch_required_for_this_hook=False)
    finally:
        r['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
        (out/'report.json').write_text(json.dumps(r, indent=2)+'\n')
    print('PASS: existing final-close hook is linked in exact preserved Image; offline proof only')


if __name__ == '__main__':
    main()
