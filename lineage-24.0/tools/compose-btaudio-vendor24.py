#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Add the reviewed Bluetooth audio shim to an already strictly composed vendor.

Exactly three new files (32-bit module, VINTF fragment, AOSP bluetooth audio
policy) and one changed file (audio policy include a2dp -> bluetooth). New
files take uid/gid/mode/SELinux label from their existing siblings. Every
other entry must remain byte- and metadata-identical. No policy change.
"""
import argparse, fcntl, hashlib, json, shutil, subprocess, sys
import xml.etree.ElementTree as ET
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
for n in ['top', 'base-vendor', 'shim-build', 'staging', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
a = p.parse_args()
T, B, S, G, O = (x.resolve() for x in (a.top, a.base_vendor, a.shim_build, a.staging, a.output))
assert not O.exists()
lock = Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
sha = lambda q: hashlib.sha256(q.read_bytes()).hexdigest()
base = json.loads((B/'report.json').read_text())
assert base['passed'] and sha(B/'vendor.raw.img') == base['vendor_raw_sha256']
abi = json.loads((S/'abi-v30.json').read_text())
shim = S/'audio.bluetooth.exynos7904.so'
assert abi['passed'] and not abi['unresolved_symbols'] and abi['shim_sha256'] == sha(shim)
staged = json.loads((G/'report.json').read_text())
for rel, h in staged['files_sha256'].items():
    assert sha(G/rel) == h, rel
O.mkdir(parents=True)
image = O/'vendor.raw.img'
shutil.copyfile(B/'vendor.raw.img', image)
audit = Path(__file__).with_name('audit-ext4-tree24.py')


def manifest(img, label):
    subprocess.run([sys.executable, str(audit), '--image', str(img), '--output', str(O/label)], check=True)
    return json.loads((O/label/'report.json').read_text())['entries']


before = manifest(image, 'before')
work = O/'staged'
work.mkdir()
policy_old = (O/'before/tree/etc/audio_policy_configuration.xml').read_text()
inc_old = '<xi:include href="a2dp_audio_policy_configuration.xml"/>'
inc_new = '<xi:include href="bluetooth_audio_policy_configuration.xml"/>'
assert policy_old.count(inc_old) == 1 and inc_new not in policy_old
policy = work/'audio_policy_configuration.xml'
policy.write_text(policy_old.replace(inc_old, inc_new))
ET.fromstring(policy.read_bytes())
bt_policy = G/'btaudio/vendor/etc/bluetooth_audio_policy_configuration.xml'
assert ET.fromstring(bt_policy.read_bytes()).get('name') == 'bluetooth'
frag = G/'btaudio/vendor/etc/vintf/manifest/gta3xlwifi_btaudio.xml'
ET.fromstring(frag.read_bytes())
new = {'/lib/hw/audio.bluetooth.exynos7904.so': (shim, '/lib/hw/audio.r_submix.default.so'),
       '/etc/vintf/manifest/gta3xlwifi_btaudio.xml': (frag, '/etc/vintf/manifest.xml'),
       '/etc/bluetooth_audio_policy_configuration.xml': (bt_policy, '/etc/a2dp_audio_policy_configuration.xml')}
changed = {'/etc/audio_policy_configuration.xml': policy}
commands = []
for dest, (src, sibling) in list(new.items()) + [(k, (v, k)) for k, v in changed.items()]:
    assert not any(c in str(src)+dest for c in '\n\r"\\ ')
    m = before[sibling]
    assert m['type'] == 'regular' and m['uid'] == 0 and m['gid'] == 0 and m['mode'] == '0644', (sibling, m)
    label_value = m['extended_attributes'].split('"')[1].replace('\\000', '')
    assert label_value in ('u:object_r:vendor_file:s0', 'u:object_r:vendor_configs_file:s0'), label_value
    label = work/(dest.strip('/').replace('/', '_')+'.label')
    label.write_bytes(label_value.encode()+b'\0')
    if dest in changed:
        commands.append('rm '+dest)
    else:
        assert dest not in before, dest
    commands += ['write '+str(src)+' '+dest, 'set_inode_field '+dest+' mode 0100644',
                 'set_inode_field '+dest+' uid 0', 'set_inode_field '+dest+' gid 0',
                 'ea_set -f '+str(label)+' '+dest+' security.selinux']
    commands += ['set_inode_field '+dest+' '+s+' 1230735600' for s in ['atime', 'ctime', 'mtime', 'crtime']]
(O/'compose.commands').write_text('\n'.join(commands)+'\n')
r = subprocess.run(['debugfs', '-w', '-f', str(O/'compose.commands'), str(image)], capture_output=True, text=True)
(O/'compose.log').write_text(r.stdout+r.stderr)
assert r.returncode == 0 and 'Could not' not in r.stdout+r.stderr, r.stdout+r.stderr
r = subprocess.run(['e2fsck', '-fn', str(image)], capture_output=True, text=True)
(O/'e2fsck.log').write_text(r.stdout+r.stderr)
assert r.returncode == 0, r.stdout+r.stderr
after = manifest(image, 'after')
assert set(after) == set(before) | set(new), sorted(set(after) ^ set(before))
for path, m in before.items():
    if path not in changed:
        assert after[path] == m, ('Unreviewed vendor difference', path)
    else:
        assert {k: v for k, v in after[path].items() if k not in ('size', 'sha256')} == \
               {k: v for k, v in m.items() if k not in ('size', 'sha256')}, path
for dest, (src, sibling) in new.items():
    meta = {k: v for k, v in after[dest].items() if k not in ('size', 'sha256')}
    want = {k: v for k, v in before[sibling].items() if k not in ('size', 'sha256')}
    assert meta == want and after[dest]['sha256'] == sha(src), dest
for dest, src in changed.items():
    assert after[dest]['sha256'] == sha(src)
sparse = O/'vendor.img'
subprocess.run([str(T/'out/host/linux-x86/bin/img2simg'), str(image), str(sparse)], check=True)
report = dict(base)
report.update(scope=__doc__, base_vendor_report_sha256=sha(B/'report.json'), shim_sha256=sha(shim),
              shim_abi_report_sha256=sha(S/'abi-v30.json'), btaudio_new_paths={k: sha(v[0]) for k, v in new.items()},
              btaudio_changed_paths={k: sha(v) for k, v in changed.items()},
              vendor_sparse_sha256=sha(sparse), vendor_raw_sha256=sha(image), raw_bytes=image.stat().st_size,
              entries_before=len(before), entries_after=len(after), all_other_contents_and_security_metadata_identical=True,
              hardware_tested=False, flash_ready=False)
(O/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS btaudio vendor composition: 3 new + 1 changed path; all others identical')
