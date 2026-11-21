#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare every actual OTA new/zero block operation to its pinned sparse target image.

Full OTA only: no source-dependent moves, patches or stashes. Erases may affect
only uncared sparse blocks. No device is opened and no update is executed.
"""
import argparse,hashlib,json,shutil,subprocess,sys,tempfile,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','ota','target-files','container','geometry','vendor-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
c=json.loads(a.container.read_text());g=json.loads(a.geometry.read_text());v=json.loads(a.vendor_report.read_text())
assert c['passed'] and c['ota_sha256']==sha(a.ota) and c['target_files_sha256']==sha(a.target_files)==g['archive_sha256']
assert sha(a.vendor_report)==g['vendor_composition_report_sha256'] and v['passed']
sys.path.insert(0,str(a.top/'build/make/tools/releasetools'));sys.dont_write_bytecode=True
import sparse_img
from rangelib import RangeSet
brotli=a.top/'out/host/linux-x86/bin/brotli';results={}
with zipfile.ZipFile(a.ota) as z,zipfile.ZipFile(a.target_files) as t,tempfile.TemporaryDirectory(dir=O) as scratch:
 assert not any(n.startswith('product.') for n in z.namelist())  # runtime40: product folded into system
 for part in ['system','vendor']:
  image=Path(scratch)/(part+'.img');br=Path(scratch)/(part+'.new.dat.br')
  for src,dst in [('IMAGES/'+part+'.img',image)]:
   with t.open(src) as f,dst.open('wb') as out:shutil.copyfileobj(f,out,1024*1024)
  assert sha(image)==g['images'][part+'.img']['sha256']
  with z.open(part+'.new.dat.br') as f,br.open('wb') as out:shutil.copyfileobj(f,out,1024*1024)
  assert z.read(part+'.patch.dat')==b''
  img=sparse_img.SparseImage(str(image),clobbered_blocks='0');assert img.blocksize==4096
  lines=z.read(part+'.transfer.list').decode().splitlines();assert lines[0]=='4' and lines[2:4]==['0','0']
  written=RangeSet();erased=RangeSet();expected=hashlib.sha256();new_count=zero_count=extended_zero_count=0;commands=[]
  for line in lines[4:]:
   op,encoded=line.split();assert op in ['new','zero','erase'],('Unexpected source-dependent command',line)
   values=list(map(int,encoded.split(',')));assert values[0]==len(values)-1 and values[0]%2==0
   pairs=list(zip(values[1::2],values[2::2]));assert pairs and all(0<=s<e<=img.total_blocks for s,e in pairs)
   assert all(pairs[i][1]<=pairs[i+1][0] for i in range(len(pairs)-1))
   ranges=RangeSet(values[1:]);assert ranges.size()==sum(e-s for s,e in pairs)
   assert not ranges.overlaps(written) and not ranges.overlaps(erased),('Overlapping operations',part,line)
   if op=='erase':
    assert not ranges.overlaps(img.care_map) and not ranges.overlaps(img.extended),('Erase overlaps cared/required zero target data',part,line)
    erased=erased.union(ranges)
   else:
    written=written.union(ranges)
    if op=='new':
     assert not ranges.subtract(img.care_map),('New data outside defined sparse bytes',part,line)
     for data in img.ReadRangeSet(ranges):expected.update(data)
     new_count+=ranges.size()
    else:
     defined=ranges.intersect(img.care_map);undefined=ranges.subtract(img.care_map)
     # AOSP explicitly zeros its 512-block read-ahead halo in DONT_CARE
     # space. SparseImage.ReadRangeSet is defined only for cared chunks.
     assert not undefined.subtract(img.extended),('Zero outside defined bytes or required read-ahead halo',part,line)
     for data in img.ReadRangeSet(defined):assert not any(data),('Nonzero cared target scheduled for zero',part,line)
     extended_zero_count+=undefined.size();zero_count+=ranges.size()
   commands.append({'operation':op,'blocks':ranges.size()})
  assert int(lines[1])==new_count+zero_count
  assert not img.care_map.union(img.extended).subtract(written) and written.overlaps(RangeSet([0,1]))
  actual=hashlib.sha256();byte_count=0
  with (O/(part+'-brotli.log')).open('wb') as log:
   proc=subprocess.Popen([str(brotli),'--decompress','--stdout',str(br)],stdout=subprocess.PIPE,stderr=log)
   for data in iter(lambda:proc.stdout.read(1024*1024),b''):actual.update(data);byte_count+=len(data)
   assert proc.wait()==0
  assert byte_count==new_count*4096 and actual.hexdigest()==expected.hexdigest(),('OTA stream differs from built image',part)
  if part=='vendor':assert byte_count==v['raw_bytes'] and actual.hexdigest()==v['vendor_raw_sha256']
  results[part]={'new_blocks':new_count,'zero_blocks':zero_count,'explicit_uncared_read_ahead_zero_blocks':extended_zero_count,'erase_blocks':erased.size(),'physical_image_blocks':img.total_blocks,'decompressed_new_data_bytes':byte_count,'actual_and_expected_new_data_sha256':actual.hexdigest(),'all_cared_target_blocks_covered':True,'erases_only_uncared_blocks':True,'no_overlap_or_source_dependencies':True,'commands':commands}
  img.simg_f.close();image.unlink();br.unlink();print('PASS actual',part,'OTA block stream',byte_count,'bytes',flush=True)
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'ota_sha256':c['ota_sha256'],'target_files_sha256':g['archive_sha256'],'brotli_tool_sha256':sha(brotli),'source_sparse_parser_sha256':sha(a.top/'build/make/tools/releasetools/sparse_img.py'),'images':results,'device_touched':False,'Android17_FBE_validated':False,'flash_ready':False},indent=2)+'\n')
