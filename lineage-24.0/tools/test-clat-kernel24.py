#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual built qtaguid CLAT tag0/UID1029 lifetime functions with explicit kernel primitives.

The final socket release call is a fixture boundary, not an actual socket close
inside a running Android kernel. Complete built source hashes are checked twice.
"""
import argparse,fcntl,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['kernel','kernel-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();K=a.kernel.resolve();O=a.output.resolve();assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads(a.kernel_report.read_text());manifest=a.kernel_report.with_name('source-after.json');audit=json.loads(manifest.read_text());assert r['passed'] and r['actual_Image_all_modules_and_Gator_built']
def check():
 assert subprocess.check_output(['git','-C',str(K),'rev-parse','HEAD'],text=True).strip()==audit['revision']
 for n,h in audit['tracked_sha256'].items():
  f=K/n;actual=hashlib.sha256(f.readlink().as_posix().encode()).hexdigest() if f.is_symlink() else sha(f);assert actual==h,n
check()
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('owned',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=K/'net/netfilter/xt_qtaguid.c';header=K/'include/uapi/linux/netfilter/xt_qtaguid_sock.h';inet=K/'net/ipv4/af_inet.c';inet6=K/'net/ipv6/af_inet6.c';release=m.extract(inet.read_text(),'inet_release');release6=m.extract(inet6.read_text(),'inet6_release');assert 'qtaguid_untag(sock, true)' in release and 'inet_release(sock)' in release6
old=m.TEST.replace('int main(void)', 'static int previous_owned_regressions(void)',1);pos=old.rindex('}');old=old[:pos]+'return 0;\n'+old[pos:]
extra=r'''
int main(void){CHECK(previous_owned_regressions()==0);unsigned begin=checks;
 for(int round=0;round<3;round++){
  struct file daemon=session(100+round,true);socks[0].sk_family=AF_INET6;
  tag(0,0,1029);struct sock_tag*entry=get_sock_stat_nl(&socks[0]);CHECK(entry&&entry->pid==0&&socks[0].refs==2);
  CHECK(uid_tag_data_tree_search(&uid_tag_data_tree,1029)->num_active_tags==1);
  release(&daemon);CHECK(get_sock_stat_nl(&socks[0])&&socks[0].refs==2);
  struct file restarted=session(200+round,true);release(&restarted);CHECK(get_sock_stat_nl(&socks[0]));
  as(300+round,1029);CHECK(qtaguid_untag(&sockets[0],true)==0);CHECK(!get_sock_stat_nl(&socks[0])&&socks[0].refs==1);
  CHECK(!uid_tag_data_tree_search(&uid_tag_data_tree,1029));CHECK(qtaguid_untag(&sockets[0],true)==-EINVAL);socks[0].sk_family=AF_INET;empty();
 }
 printf("clat_kernel_cases=%u total_cases=%u\n",checks-begin,checks);return 0;
}
'''
code=O/'test.c';code.write_text(m.PREAMBLE+'\n'+header.read_text()+'\n'+'\n\n'.join(m.extract(source.read_text(),n) for n in m.NAMES)+old+extra)
cmd=['cc','-std=gnu11','-Wall','-Werror','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(code),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=90,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);match=re.search(r'clat_kernel_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert match;check()
inputs=[Path(__file__),helper,source,header,inet,inet6,code,a.kernel_report,manifest,a.kernel_report.with_name('Image')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[2]),'clat_kernel_cases':int(match[1]),'complete_built_source_files_verified_before_after':len(audit['tracked_sha256']),'actual_INET_and_INET6_final_release_hooks_checked':True,'inputs_sha256':{str(f):sha(f) for f in inputs},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
