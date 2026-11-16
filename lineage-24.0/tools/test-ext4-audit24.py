#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise complete ext4 audit against controlled inode, xattr and payload changes."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
image=O/'fixture.img'
with image.open('wb') as f:f.truncate(8*1024*1024)
subprocess.run(['mkfs.ext4','-q','-F',str(image)],check=True)
data=O/'payload';data.write_bytes(b'known payload\x00\xff\n');attr=O/'label';attr.write_bytes(b'u:object_r:vendor_configs_file:s0\0');opaque=O/'opaque';opaque.write_bytes(bytes(range(256)))
commands=['mkdir /etc','write '+str(data)+' /etc/policy','set_inode_field /etc/policy mode 0100640','set_inode_field /etc/policy uid 123','set_inode_field /etc/policy gid 456','ea_set -f '+str(attr)+' /etc/policy security.selinux','ea_set -f '+str(opaque)+' /etc/policy user.opaque','symlink /link /outside/never/follow']
cmd=O/'commands';cmd.write_text('\n'.join(commands)+'\n')
r=subprocess.run(['debugfs','-w','-f',str(cmd),str(image)],capture_output=True,text=True);assert r.returncode==0;(O/'setup.log').write_text(r.stdout+r.stderr)
tool=Path(__file__).with_name('audit-ext4-tree24.py')
def audit(label):
 subprocess.run([sys.executable,str(tool),'--image',str(image),'--output',str(O/label)],check=True)
 return json.loads((O/label/'report.json').read_text())['entries']
before=audit('before');item=before['/etc/policy'];sha=lambda b:hashlib.sha256(b).hexdigest()
assert item['uid']==123 and item['gid']==456 and item['mode']=='0640' and item['sha256']==sha(data.read_bytes())
assert item['xattrs_sha256']=={'security.selinux':sha(attr.read_bytes()),'user.opaque':sha(opaque.read_bytes())}
assert before['/link']['target']=='/outside/never/follow'
# Mutate only the end of a 256-byte binary xattr: a printed/truncated listing
# alone must not falsely claim identity.
opaque.write_bytes(bytes(range(255))+b'\x00')
r=subprocess.run(['debugfs','-w','-R','ea_set -f '+str(opaque)+' /etc/policy user.opaque',str(image)],capture_output=True,text=True);assert r.returncode==0
after=audit('after');assert after['/etc/policy']['xattrs_sha256']['user.opaque']==sha(opaque.read_bytes())
assert before['/etc/policy']['xattrs_sha256']!=after['/etc/policy']['xattrs_sha256']
assert all(before[n]==after[n] for n in before if n!='/etc/policy')
(O/'report.json').write_text(json.dumps({'passed':True,'checks':['payload bytes','nondefault inode mode/uid/gid','binary SELinux label','complete binary xattr including changed final byte','symlink target without following','all unrelated entries unchanged']},indent=2)+'\n');print('PASS ext4 audit controlled fixture')
