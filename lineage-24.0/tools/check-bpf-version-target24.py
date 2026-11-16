#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Require genuine comments-only API metadata and source-bound actual-kernel comparisons, never loader readiness."""
import argparse,hashlib,json,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','archive','geometry','host-proof','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
g=json.loads(a.geometry.read_text());assert g['artifact_checks_passed'] and sha(a.archive)==g['archive_sha256']
r=json.loads(a.host_proof.read_text());assert r['passed'] and r['metadata_comments_only'] and r['BPF_readiness_not_set']
for name,h in r['source_sha256'].items():assert sha(a.top/name)==h
assert sha(a.top/'packages/modules/Connectivity/bpf/headers/include/bpf/BpfUtils.h')==r['parser_source_sha256']
upstream=a.top/'packages/modules/Connectivity/bpf/loader/netbpfload.rc';assert sha(upstream)==r['upstream_metadata_source_sha256']
with zipfile.ZipFile(a.archive) as z:
 b=z.read('SYSTEM/etc/init/netbpfload.rc');assert b==(a.top/'device/samsung/gta3xlwifi/configs/netbpfload-version.rc').read_bytes()
 assert b.splitlines()[0]==upstream.read_bytes().splitlines()[0]
 assert all(not line.strip() or line.lstrip().startswith(b'#') for line in b.splitlines())
 assert b'bpf.progs_loaded' not in b
 for n in z.namelist():
  if n.endswith(('/build.prop','/prop.default','/default.prop')):
   for line in z.read(n).decode().splitlines():assert not line.startswith('ro.bpf.kver_override=') or not line.split('=',1)[1]
assert not r['kernel_tests']['files']['kernel4_4_claims_ring_buffer5_8']
report={'passed':True,'scope':__doc__,'archive_sha256':g['archive_sha256'],'actual_version_rc_sha256':hashlib.sha256(b).hexdigest(),'actual_version_first_line':b.splitlines()[0].decode(),'comments_only_no_actions_or_services':True,'no_kernel_version_override_in_build_props':True,'BPF_program_readiness_not_set':True,'host_regression_report_sha256':sha(a.host_proof),'supported_kernel_comparisons_preserved':True,'actual_Android_LMKD_execution_proven':False,'flash_ready':False};a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS genuine API metadata, no loader/readiness and actual kernel capability binding')
