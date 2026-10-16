#!/usr/bin/env python3
"""Validate a vendor OTA readback while allowing precise ext4 mount bookkeeping.

This is read-only. File data, inode tables, journal and all other image bytes
must match. e2fsck must also accept the actual descriptor checksums and state.
"""
import argparse,hashlib,json,struct,subprocess,zlib
from datetime import datetime,timezone
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--expected-sparse',type=Path,required=True);p.add_argument('--actual-raw',type=Path,required=True);p.add_argument('--image-check',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
def sha(b):return hashlib.sha256(b).hexdigest()
src=a.expected_sparse.read_bytes();image=json.loads(a.image_check.read_text())['images']['vendor.img'];assert sha(src)==image['sha256']
magic,major,minor,fh,ch,bs,blocks,chunks,crc=struct.unpack_from('<IHHHHIIII',src)
assert (magic,major,minor,fh,ch,bs)==(0xed26ff3a,1,0,28,12,4096)
expected=bytearray(bs*blocks);off=fh;position=0
for _ in range(chunks):
 kind,res,n,size=struct.unpack_from('<HHII',src,off);data=src[off+ch:off+size];length=n*bs
 if kind==0xcac1:assert len(data)==length;expected[position:position+length]=data
 elif kind==0xcac2:assert len(data)==4;expected[position:position+length]=data*(length//4)
 elif kind==0xcac3:assert not data
 elif kind==0xcac4:assert n==0 and len(data)==4;assert zlib.crc32(expected[:position])==struct.unpack('<I',data)[0]
 else:raise AssertionError('Unexpected sparse chunk')
 position+=length;off+=size
assert position==len(expected) and off==len(src)
if crc:assert zlib.crc32(expected)==crc
actual=a.actual_raw.read_bytes();assert len(actual)==len(expected)==image['expanded_bytes']==image['partition_bytes']
assert expected[1080:1082]==actual[1080:1082]==b'\x53\xef'
normalized=bytearray(actual);changes={}
def counter(name,off,fmt):
 old=struct.unpack_from(fmt,expected,off)[0];new=struct.unpack_from(fmt,actual,off)[0]
 assert new>=old,(name,old,new)
 if name=='mount_count':assert new in (old,old+1)
 if old!=new:changes[name]={'before':old,'after':new};normalized[off:off+struct.calcsize(fmt)]=expected[off:off+struct.calcsize(fmt)]
counter('last_mount_time',1068,'<I');counter('last_write_time',1072,'<I');counter('mount_count',1076,'<H');counter('lifetime_kbytes_written',1400,'<Q')
# ext4 with 32-byte group descriptors and GDT checksums, as in this reviewed image.
assert struct.unpack_from('<H',expected,1278)[0] in (0,32)
assert not struct.unpack_from('<I',expected,1120)[0]&0x80 # no 64-bit descriptors
blocks_per_group=struct.unpack_from('<I',expected,1056)[0];first=struct.unpack_from('<I',expected,1044)[0]
groups=(blocks-first+blocks_per_group-1)//blocks_per_group;initialized=[]
for group in range(groups):
 start=4096+32*group;old=struct.unpack_from('<H',expected,start+18)[0];new=struct.unpack_from('<H',actual,start+18)[0]
 assert new==old or new==old|4,('Unexpected group flags',group,old,new)
 if new!=old:
  initialized.append(group)
  normalized[start+18:start+20]=expected[start+18:start+20]
  normalized[start+30:start+32]=expected[start+30:start+32]
assert normalized==expected,'Vendor differs outside permitted ext4 counters and initialized-inode flags/checksums'
result=subprocess.run(['e2fsck','-fn',str(a.actual_raw)],capture_output=True,text=True)
assert result.returncode==0,result.stdout+result.stderr
changed_bytes=sum(x!=y for x,y in zip(expected,actual))
report={'passed':True,'checked_at_utc':datetime.now(timezone.utc).isoformat(),'expected_sparse_sha256':sha(src),'expected_raw_sha256':sha(expected),'actual_raw_sha256':sha(actual),'bytes_compared':len(actual),'different_bytes':changed_bytes,'only_permitted_ext4_mount_metadata_changed':True,'vendor_file_data_and_other_metadata_byte_identical':True,'counters_changed':changes,'inode_table_zeroed_flag_added_groups':initialized,'group_descriptor_checksums_validated_by_e2fsck':True,'read_only_e2fsck_exit_code':result.returncode,'image_modified_by_check':False}
a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
