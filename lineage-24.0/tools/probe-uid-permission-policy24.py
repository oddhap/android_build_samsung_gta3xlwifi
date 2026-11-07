#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Probe actual staged packet-barrier lease policy permissions, genfs labels and ioctl bounds.

Uses libsepol for real genfs contexts and the real A17 strict compiler as a
negative-test oracle: adding a contradiction for 0x6750..0x6756 must fail, while adding
assertions denying its neighbors must pass. Existing assertions are never removed.
No tested/probe policy is selected into Android images or applied to a kernel.
"""
import argparse,hashlib,importlib.util,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','strict-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=json.loads(a.strict_report.read_text());assert base['passed_strict'];command=base['results'][0]['command'];assert '-N' not in command and base['results'][0]['neverallow_checks_enabled']
inputs={Path(x['path']):x['sha256'] for x in base['inputs']};inputs[a.strict_report]=sha(a.strict_report);policy=a.strict_report.with_name('strict.policy');assert sha(policy)==base['results'][0]['compiled_policy_sha256'];inputs[policy]=sha(policy)
for path,h in inputs.items():assert sha(path)==h
platform=next(path for path in inputs if path.name=='plat_sepolicy.cil');assert 'sysfs_gta3xlwifi_netpolicy' in platform.read_text();compiler=Path(command[0]);assert sha(compiler)==base['compiler_sha256'];inputs[compiler]=sha(compiler)
queries=[]
for domain,target,cls,perms,expected in [('netd','gta3xlwifi_netpolicy_device','chr_file',['open','read','getattr','ioctl'],'allow'),('netd','gta3xlwifi_netpolicy_device','chr_file',['write'],'deny'),('netd','sysfs_gta3xlwifi_netpolicy','file',['open','read','getattr'],'allow'),('netd','sysfs_gta3xlwifi_netpolicy','file',['write'],'deny'),('netd','sysfs','dir',['search'],'allow'),('init','sysfs_gta3xlwifi_netpolicy','file',['read','getattr'],'allow'),('init','sysfs_gta3xlwifi_netpolicy','file',['write'],'deny'),('system_server','gta3xlwifi_netpolicy_device','chr_file',['open','ioctl'],'deny'),('untrusted_app','gta3xlwifi_netpolicy_device','chr_file',['open','ioctl'],'deny')]:
 for permission in perms:queries.append({'source':'u:r:'+domain+':s0','target':'u:object_r:'+target+':s0','class':cls,'permission':permission,'expected':expected})
(O/'queries.json').write_text(json.dumps(queries,indent=2)+'\n');helper=Path(__file__).with_name('query-strict-policy-access.py');subprocess.run(['python3',str(helper),'--top',str(T),'--policy',str(policy),'--queries',str(O/'queries.json'),'--output',str(O/'permissions')],check=True);inputs[helper]=sha(helper)
csource=O/'genfs.c';csource.write_text(r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb/services.h>
int main(int argc,char **argv){
 assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);assert(fseek(f,0,SEEK_END)==0);long n=ftell(f);assert(n>0);rewind(f);void *data=malloc(n);assert(data);assert(fread(data,1,n,f)==(size_t)n);assert(fclose(f)==0);assert(sepol_load_policy(data,n)==0);free(data);
 const char *paths[]={"/devices/virtual/misc/gta3xlwifi_netpolicy/dev"};
 sepol_security_class_t c;assert(sepol_string_to_security_class("file",&c)==0);
 for(unsigned i=0;i<sizeof(paths)/sizeof(paths[0]);i++){sepol_security_id_t sid;sepol_security_context_t context;size_t size;assert(sepol_genfs_sid("sysfs",paths[i],c,&sid)==0);assert(sepol_sid_to_context(sid,&context,&size)==0);assert(!strcmp(context,"u:object_r:sysfs_gta3xlwifi_netpolicy:s0"));printf("genfs=%s context=%s\n",paths[i],context);free(context);}
 return 0;
}
''')
cc=T/'prebuilts/clang/host/linux-x86/clang-r584948/bin/clang';lib=T/'out/soong/.intermediates/external/selinux/libsepol/libsepol/linux_glibc_x86_64_static/libsepol.a';inputs[cc]=sha(cc);inputs[lib]=sha(lib)
cmd=[str(cc),'-std=gnu11','-Wall','-Wextra','-Werror','-fuse-ld=lld','-I'+str(T/'external/selinux/libsepol/include'),str(csource),str(lib),'-o',str(O/'genfs')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
r=subprocess.run([str(O/'genfs'),str(policy)],capture_output=True,text=True);(O/'genfs.log').write_text(r.stdout+r.stderr);assert r.returncode==0,(r.stdout,r.stderr);assert sum(line.startswith('genfs=') for line in r.stdout.splitlines())==1
# Validate the actual isolated character-device file context against the binary.
file_contexts=a.strict_report.parent.parent/'metadata/file_contexts';inputs[file_contexts]=sha(file_contexts)
checkfc=Path(base['build_output_root'])/'host/linux-x86/bin/checkfc';inputs[checkfc]=sha(checkfc)
r=subprocess.run([str(checkfc),str(policy),str(file_contexts)],capture_output=True,text=True);(O/'file-contexts.log').write_text(r.stdout+r.stderr);assert r.returncode==0,(r.stdout,r.stderr)
spec=importlib.util.spec_from_file_location('diagnostics',Path(__file__).with_name('policy-diagnostics.py'));diagnostics=importlib.util.module_from_spec(spec);spec.loader.exec_module(diagnostics);probes=[]
for number,expected in [(0x6750,255),(0x6751,255),(0x6752,255),(0x6753,255),(0x6754,255),(0x6755,255),(0x6756,255),(0x674f,0),(0x6757,0)]:
 directory=O/format(number,'x');directory.mkdir();fragment=directory/'plat_sepolicy.cil';assertion='(neverallowx netd gta3xlwifi_netpolicy_device (ioctl chr_file (0x'+format(number,'x')+')))';fragment.write_text(platform.read_text()+'\n; Negative-test assertion only, never an image input.\n'+assertion+'\n')
 cmd=[str(fragment) if x==str(platform) else x for x in command];assert cmd.count(str(fragment))==1;cmd[cmd.index('-o')+1]=str(directory/'probe.policy');r=subprocess.run(cmd,capture_output=True,text=True);log=r.stdout+r.stderr;(directory/'strict.log').write_text(log);blocks=diagnostics.blocks(log)
 assert r.returncode==expected,(number,r.returncode,log[-12000:])
 if expected==255:assert len(blocks)==1 and blocks[0]['kind']!='neverallow' and 'gta3xlwifi_netpolicy_device' in blocks[0]['assertion']
 else:assert not blocks
 probes.append({'ioctl':number,'extra_probe_assertion':assertion,'expected_compiler_exit':expected,'actual_compiler_exit':r.returncode,'diagnostic_blocks':len(blocks),'command':cmd,'platform_probe_sha256':sha(fragment)})
for path,h in inputs.items():assert sha(path)==h,'Input changed: '+str(path)
inputs[Path(__file__)]=sha(Path(__file__));inputs[csource]=sha(csource)
report={'passed':True,'scope':__doc__,'permissions':str(O/'permissions/report.json'),'permission_queries':len(queries),'actual_genfs_file_labels_checked':1,'file_context_validated_against_actual_policy':True,'strict_ioctl_contradiction_probes':probes,'inputs_sha256':{str(p):h for p,h in inputs.items()},'active_policy_or_images_changed':False,'hardware_tested':False,'flash_ready':False};(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: '+str(len(queries))+' actual permissions, actual device/genfs labels, seven enabled ioctls and two denied neighbors with strict compiler oracles')
