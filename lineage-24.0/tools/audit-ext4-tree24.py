#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record all ext4 contents and inode security metadata without mounting an image.

Uses read-only debugfs. Extracted regular files are opened with O_NOFOLLOW;
symlinks are recorded as links. No device, signing key or Android source edits.
"""
import argparse,hashlib,json,os,re,stat,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);E=O/'tree';E.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert a.image.is_file()
with a.image.open('rb') as f:assert f.read(4)!=bytes.fromhex('3aff26ed'),'Supply raw ext4, not sparse'
run=subprocess.run(['debugfs','-R',f'rdump / {E}',str(a.image)],capture_output=True,text=True)
(O/'extraction.log').write_text(run.stdout+run.stderr);assert run.returncode==0
paths=[E];todo=[E]
while todo:
 d=todo.pop()
 for x in sorted(d.iterdir()):
  paths.append(x)
  if stat.S_ISDIR(x.lstat().st_mode):todo.append(x)
rels=['/' if x==E else '/'+x.relative_to(E).as_posix() for x in paths]
assert all(not any(c in s for c in '\n\r"\\') for s in rels)
cmd=O/'stat.commands';cmd.write_text(''.join('stat "'+s+'"\n' for s in rels))
r=subprocess.run(['debugfs','-f',str(cmd),str(a.image)],capture_output=True,text=True);assert r.returncode==0
(O/'stat.log').write_text(r.stdout+r.stderr)
blocks=re.split(r'^debugfs: +stat .*\n',r.stdout,flags=re.M)[1:];assert len(blocks)==len(paths),(len(blocks),len(paths))
records={};attribute_jobs=[];X=O/'xattrs';X.mkdir()
for path,rel,block in zip(paths,rels,blocks):
 kind=re.search(r'Inode: (\d+) +Type: (.*?) +Mode: +(\d+)',block);assert kind,(rel,block)
 owner=re.search(r'User: +(\d+) +Group: +(\d+) +Project: +(\d+)',block);assert owner
 attrs=''
 if 'Extended attributes:\n' in block:
  attrs='\n'.join(line for line in block.split('Extended attributes:\n',1)[1].splitlines() if re.match(r'^  [A-Za-z0-9_.-]+ \([0-9]+\)',line))
 item={'type':kind[2],'mode':kind[3],'uid':int(owner[1]),'gid':int(owner[2]),'project':int(owner[3]),'extended_attributes':attrs}
 mode=path.lstat().st_mode
 if stat.S_ISREG(mode):
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'rb') as f:
   h=hashlib.sha256()
   for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
  item.update(size=path.lstat().st_size,sha256=h.hexdigest())
 elif stat.S_ISLNK(mode):item['target']=os.readlink(path)
 elif not stat.S_ISDIR(mode):raise AssertionError(('Unexpected special inode',rel))
 item['xattrs_sha256']={}
 for name,size in re.findall(r'^  ([A-Za-z0-9_.-]+) \((\d+)\)',attrs,re.M):
  target=X/str(len(attribute_jobs));attribute_jobs.append((rel,name,int(size),target))
 records[rel]=item
if attribute_jobs:
 cmd=O/'xattr.commands';cmd.write_text(''.join('ea_get -f '+str(target)+' "'+rel+'" '+name+'\n' for rel,name,size,target in attribute_jobs))
 r=subprocess.run(['debugfs','-f',str(cmd),str(a.image)],capture_output=True,text=True);assert r.returncode==0
 (O/'xattrs.log').write_text(r.stdout+r.stderr)
 for rel,name,size,target in attribute_jobs:
  assert target.is_file() and target.stat().st_size==size,(rel,name,size)
  records[rel]['xattrs_sha256'][name]=sha(target)
report={'image_sha256':sha(a.image),'entries':records,'entry_count':len(records),'source_image_modified':False}
(O/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print('Audited',len(records),'ext4 entries')
