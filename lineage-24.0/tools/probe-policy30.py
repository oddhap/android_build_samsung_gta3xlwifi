#!/usr/bin/env python3
"""Isolated actual-vendor policy30 probe. Never installs mappings or disables neverallows."""
import argparse,datetime,hashlib,json,re,subprocess
from pathlib import Path

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('top','vendor','reference','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();top,vendor,ref,out=[getattr(a,n).resolve() for n in ('top','vendor','reference','output')]
 if out.exists() or any(out.is_relative_to(r) for r in (top,vendor,ref)):
  raise ValueError('Output must be fresh and outside all input roots')
 lock=json.loads((ref/'source-lock.json').read_text())
 if lock['revision']!='885cc500f6078a766d1f6def5ce4c06c55841773':raise ValueError('Unexpected reference source')
 for name,info in lock['files'].items():
  if Path(name).name!=name or digest(ref/name)!=info['sha256']:raise ValueError('Reference checksum mismatch')
 build=top/'out';prod=build/'target/product/gta3xlwifi'
 system=prod/'system/etc/selinux';ext=prod/'system/system_ext/etc/selinux';product=prod/'product/etc/selinux'
 tools=build/'host/linux-x86/bin';vp=vendor/'etc/selinux'
 if (vp/'plat_sepolicy_vers.txt').read_text().strip()!='30.0':raise ValueError('Wrong vendor version')
 inputs=[system/'plat_sepolicy.cil',system/'mapping/31.0.cil',ext/'system_ext_sepolicy.cil',product/'product_sepolicy.cil',vp/'plat_pub_versioned.cil',vp/'vendor_sepolicy.cil',vp/'plat_sepolicy_vers.txt',ref/'30.0.cil',ref/'30.0.compat.cil',tools/'combine_maps',tools/'secilc']
 hashes={str(f):digest(f) for f in inputs}
 out.mkdir(parents=True)
 mapping=out/'composed-30.0.cil'
 combine=[str(tools/'combine_maps'),'-t',str(system/'mapping/31.0.cil'),'-b',str(ref/'30.0.cil'),'-o',str(mapping)]
 result=subprocess.run(combine,capture_output=True,text=True)
 (out/'combine.log').write_text(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError('Mapping composition failed; see combine.log')
 policy_inputs=[system/'plat_sepolicy.cil',mapping,ref/'30.0.compat.cil',ext/'system_ext_sepolicy.cil',product/'product_sepolicy.cil',vp/'plat_pub_versioned.cil',vp/'vendor_sepolicy.cil']
 command=[str(tools/'secilc'),'-m','-M','true','-G','-c','30','-o',str(out/'strict.policy'),'-f','/dev/null',*map(str,policy_inputs)]
 result=subprocess.run(command,capture_output=True,text=True)
 log=result.stdout+result.stderr;(out/'strict.log').write_text(log)
 if any(digest(Path(f))!=sha for f,sha in hashes.items()):raise RuntimeError('Input changed during probe')
 report={'checked_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'isolated mapping candidate, not installed or whole Android17 compatibility approval','strict_exit':result.returncode,'neverallow_checks_enabled':True,'neverallow_diagnostics':log.count('neverallow check failed'),'unresolved_symbols':'Failed to resolve' in log,'combine_command':combine,'strict_command':command,'input_sha256':hashes,'composed_mapping_sha256':digest(mapping),'system_ext_and_product_30_mappings_installed':False,'active_top_modified':False,'vendor_image_modified':False,'hardware_tested':False,'flash_ready':False}
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 print('Strict exit:',result.returncode,'neverallow diagnostics:',report['neverallow_diagnostics'])
 return 0 if result.returncode==0 else 1
if __name__=='__main__':raise SystemExit(main())
