#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Capture selected networking WIP; never apply it to the active Android tree.
Usage: capture-network-experiment.py [--profile NAME] REFERENCE STAGING SNAPSHOT NEW_OUTPUT
See --help for isolated statistics/DNS, UID policy, qtaguid and SELinux profiles.
The small reference tree must contain the selected unmodified upstream files.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

CONNECTIVITY = 'packages/modules/Connectivity'
STATS = 'service-t/native/libs/libnetworkstats/'
DNS = 'bpf/dns_helper/'
FILES = {
    CONNECTIVITY: [STATS + p for p in ('Android.bp', 'BpfNetworkStats.cpp',
        'Gta3xlwifiLegacyStats.cpp', 'Gta3xlwifiLegacyStats.h', 'QtaguidStats.cpp', 'QtaguidStats.h')]
        + [DNS + p for p in ('DnsBpfHelper.cpp', 'libcom.android.tethering.dns_helper.map.txt',
                             'LegacyDnsPolicy.h', 'include/Gta3xlwifiDnsPolicy.h')]
        + ['service-t/src/com/android/server/net/NetworkStatsFactory.java',
           'tests/unit/java/com/android/server/net/NetworkStatsFactoryTest.java'],
    'packages/modules/DnsResolver': ['DnsProxyListener.cpp'],
}
NETD_QTAGUID_FILES = ['server/Gta3xlwifiQtaguidTransport.cpp',
                      'server/Gta3xlwifiQtaguidTransport.h',
                      'server/Gta3xlwifiQtaguidProtocol.h']
PROFILES = {
    'stats-dns': FILES,
    'uid-policy': {'system/netd': ['server/Gta3xlwifiUidPolicy.cpp', 'server/Gta3xlwifiUidPolicy.h']},
    'qtaguid-socket': {'system/netd': NETD_QTAGUID_FILES},
    'selinux-transitions': {'kernel/samsung/gta3xlwifi': [
        'security/selinux/hooks.c', 'security/selinux/include/classmap.h',
        'security/selinux/include/security.h', 'security/selinux/selinuxfs.c',
        'security/selinux/ss/services.c']},
    'selinux-reader': {'kernel/samsung/gta3xlwifi': [
        'security/selinux/ss/avtab.c', 'security/selinux/ss/avtab.h',
        'security/selinux/ss/policydb.c']},
    'qtaguid-persistent': {
        'system/netd': NETD_QTAGUID_FILES,
        'kernel/samsung/gta3xlwifi': ['net/netfilter/xt_qtaguid.c',
                                    'net/netfilter/xt_qtaguid_internal.h',
                                    'include/uapi/linux/netfilter/xt_qtaguid_sock.h'],
    },
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, default='stats-dns')
    for name in ('reference', 'staging', 'snapshot', 'out'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    reference, staging, snapshot, out = [getattr(args, name).resolve()
                                         for name in ('reference', 'staging', 'snapshot', 'out')]
    selected = PROFILES[args.profile]
    out.mkdir(parents=True, exist_ok=False)
    revisions = {p.get('path', p.get('name')): p.get('revision')
                 for p in ET.parse(snapshot / 'port-manifest.xml').getroot().iter('project')}
    result = {'status': 'EXPERIMENTAL_NOT_APPLIED_NOT_TEST_ROM',
              'active_snapshot': snapshot.name, 'profile': args.profile, 'projects': []}
    for project, files in selected.items():
        patch, manifest = [], []
        for name in files:
            old_path, new_path = reference / project / name, staging / project / name
            old = old_path.read_bytes() if old_path.exists() else b''
            new = new_path.read_bytes()
            if old == new:
                raise ValueError('Expected a selected change: ' + name)
            if (old and not old.endswith(b'\n')) or not new.endswith(b'\n'):
                raise ValueError('Only newline-terminated text is supported')
            patch.append(f'diff --git a/{name} b/{name}\n')
            if not old_path.exists():
                patch.append('new file mode 100644\n')
            patch.extend(difflib.unified_diff(
                old.decode().splitlines(keepends=True), new.decode().splitlines(keepends=True),
                fromfile='a/' + name if old_path.exists() else '/dev/null', tofile='b/' + name))
            manifest.append({'path': name, 'reference_sha256': digest(old) if old_path.exists() else None,
                             'staged_sha256': digest(new)})
        data = ''.join(patch).encode()
        filename = project.replace('/', '_') + '.patch'
        patch_path = out / filename
        patch_path.write_bytes(data)
        # Real Git validates forward and reverse replay, and resulting source bytes.
        with tempfile.TemporaryDirectory(prefix='gta3xlwifi-network-replay-') as d:
            top = Path(d)
            subprocess.run(['git', 'init', '-q', str(top)], check=True)
            for name in files:
                original = reference / project / name
                if original.exists():
                    dest = top / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(original.read_bytes())
            for options in (['--check'], []):
                subprocess.run(['git', '-C', str(top), 'apply', *options, str(patch_path)], check=True)
            for name in files:
                if (top / name).read_bytes() != (staging / project / name).read_bytes():
                    raise ValueError('Replay mismatch: ' + name)
            subprocess.run(['git', '-C', str(top), 'apply', '--reverse', '--check', str(patch_path)],
                           check=True)
        result['projects'].append({'path': project, 'revision': revisions[project],
                                   'patch': filename, 'sha256': digest(data), 'files': manifest,
                                   'selected_file_git_replay_passed': True})
    (out / 'staging-lock.json').write_text(json.dumps(result, indent=2) + '\n')
    count = sum(len(files) for files in selected.values())
    print(f'Captured/replayed {count} selected source files in {len(selected)} EXPERIMENTAL patches; not applied to TOP.')


if __name__ == '__main__':
    main()
