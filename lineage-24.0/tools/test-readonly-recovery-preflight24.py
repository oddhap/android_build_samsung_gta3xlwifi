#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-test the actual read-only installer probe against a preserved public TWRP image.

Matching metadata is a header-contract fixture, not Android17 decryption proof.
No physical partition, userdata, original recovery or signing material is changed.
"""
import argparse,hashlib,json,shutil,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','recovery','geometry-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
original_sha=sha(a.recovery);assert original_sha=='e6dcc17e478de9d1d3f1c398fd10c9bc9d7ac80e546f18f58cd20d52766485b4'
geometry=json.loads(a.geometry_report.read_text());assert geometry['artifact_checks_passed']
target=geometry['images']['boot.img']['os_version_word'];assert target>>25==17
exe=O/'preflight'
cmd=['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-DRECOVERY_HEADER_SYNC_HOST_TEST',str(a.source),'-lcrypto','-o',str(exe)]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
image=O/'fixture.img';data=a.recovery.read_bytes();source_word=struct.unpack_from('<I',data,44)[0]
with image.open('wb') as f:f.write(data);f.truncate(47185920)
results=[]
def run(name,word,expected,mode='--preflight',status=None):
 before=sha(image);status=status or O/'status';cmd=[str(exe),mode,word,'--test-image',str(image),'--status-file',str(status)]
 r=subprocess.run(cmd,capture_output=True,text=True);assert sha(image)==before,(name,'partition changed')
 assert (r.returncode==0)==expected,(name,r.returncode,r.stdout,r.stderr)
 results.append({'case':name,'exit_code':r.returncode,'partition_bytes_unchanged':True,'stdout':r.stdout,'stderr':r.stderr})
run('published Android14 recovery refuses Android17 target',hex(target),False)
with image.open('r+b') as f:f.seek(44);f.write(struct.pack('<I',(14<<25)|(target&2047)))
run('Android14 with current target SPL still refuses Android17',hex(target),False)
with image.open('r+b') as f:f.seek(44);f.write(struct.pack('<I',target))
run('known payload with exactly matching target header',hex(target),True)
run('apply mode removed',hex(target),False,'--apply')
run('Android14 target rejected',hex(source_word),False)
run('target patch mismatch',hex(target^16),False)
run('invalid month rejected',hex(target&~15),False)
run('malformed number rejected','not-a-number',False)
run('trailing target argument rejected',hex(target)+'junk',False)
protected=O/'protected';protected.write_text('must remain unchanged');link=O/'status-link';link.symlink_to(protected)
run('status symlink rejected without writes',hex(target),False,status=link);assert protected.read_text()=='must remain unchanged'
with image.open('r+b') as f:f.seek(4096);f.write(b'TAMPER')
run('unknown recovery payload rejected',hex(target),False)
with image.open('r+b') as f:f.truncate(47185919)
run('wrong partition geometry rejected',hex(target),False)
assert sha(a.recovery)==original_sha
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'actual_candidate_source_sha256':sha(a.source),'original_public_recovery_sha256':original_sha,'actual_target_header_word':target,'compiler_command':cmd,'cases':results,'original_recovery_unchanged':True,'device_touched':False,'Android17_FBE_validated':False,'flash_ready':False},indent=2)+'\n');print('PASS',len(results),'read-only recovery preflight host cases')
