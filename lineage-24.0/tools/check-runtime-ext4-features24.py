#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check actual packaged ext4 feature bits against the selected Samsung kernel.

Uses the source-bound AOSP sparse parser. Read-only partitions may contain
unknown ro-compat bits, as the kernel permits; cache must be writable. Does not
prove live mounts, encryption, filesystem contents or Android execution.
"""
import argparse,hashlib,json,re,shutil,struct,sys,tempfile,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','geometry-report','kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
R=json.loads(a.geometry_report.read_text());assert R['artifact_checks_passed'] and sha(a.archive)==R['archive_sha256']
header=a.kernel/'fs/ext4/ext4.h';text=header.read_text().replace('\\\n',' ')
constants={n:int(v,0) for n,v in re.findall(r'^#define\s+(EXT4_FEATURE_\w+)\s+(0x[0-9a-fA-F]+|[0-9]+)\b',text,re.M)}
supported={}
for kind in ['INCOMPAT','RO_COMPAT']:
 expr=re.search(r'^#define\s+EXT4_FEATURE_'+kind+r'_SUPP\s+([^\n]+)',text,re.M)[1]
 names=re.findall(r'EXT4_FEATURE_\w+',expr);assert names and not re.sub(r'EXT4_FEATURE_\w+|[\s()|]','',expr),expr
 mask=0
 for n in names:mask|=constants[n]
 supported[kind]=mask
sys.path.insert(0,str(a.top/'build/make/tools/releasetools'));sys.dont_write_bytecode=True
import sparse_img
results={}
with zipfile.ZipFile(a.archive) as z,tempfile.TemporaryDirectory(dir=O) as scratch:
 for name in ['system.img','product.img','vendor.img','cache.img']:
  f=Path(scratch)/name
  with z.open('IMAGES/'+name) as src,f.open('wb') as dst:shutil.copyfileobj(src,dst,1024*1024)
  assert sha(f)==R['images'][name]['sha256']
  with f.open('rb') as src:magic=src.read(4)
  if magic==struct.pack('<I',0xed26ff3a):
   img=sparse_img.SparseImage(str(f),clobbered_blocks='0');data=b''.join(img.ReadBlocks(0,(2048+img.blocksize-1)//img.blocksize));img.simg_f.close()
  else:
   with f.open('rb') as src:data=src.read(2048)
  sb=data[1024:2048];assert len(sb)==1024 and struct.unpack_from('<H',sb,0x38)[0]==0xef53
  compat,incompat,ro=struct.unpack_from('<III',sb,0x5c)
  assert not incompat&~supported['INCOMPAT'],('Unsupported ext4 incompat feature',name,hex(incompat))
  readonly=name!='cache.img'
  assert readonly or not ro&~supported['RO_COMPAT'],('Unsupported writable ext4 feature',name,hex(ro))
  results[name]={'image_sha256':sha(f),'compat':hex(compat),'incompat':hex(incompat),'ro_compat':hex(ro),'unknown_incompat':hex(incompat&~supported['INCOMPAT']),'unknown_ro_compat':hex(ro&~supported['RO_COMPAT']),'expected_readonly':readonly,'superblock_sha256':hashlib.sha256(sb).hexdigest()}
  f.unlink()
report={'passed':True,'scope':__doc__,'archive_sha256':R['archive_sha256'],'kernel_ext4_header_sha256':sha(header),'source_sparse_parser_sha256':sha(a.top/'build/make/tools/releasetools/sparse_img.py'),'kernel_supported_masks':{k:hex(v) for k,v in supported.items()},'images':results,'hardware_tested':False,'flash_ready':False}
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS packaged ext4 feature compatibility:',len(results),'images')
