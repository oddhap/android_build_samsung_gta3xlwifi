#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile actual private oneshot/main/provider and fully link netd outside TOP."""
import argparse,fcntl,hashlib,json,shlex,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','base-report','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();inputs={};commands=[]
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
def run(label,c):
 commands.append(c);x=subprocess.run(c,cwd=T,capture_output=True,text=True);(O/(label+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,(label,x.stderr[-14000:]);return x.stdout
base=json.loads(a.base_report.read_text());assert base['passed'] and base['one_actual_static_DNS_helper_instance'];bind(a.base_report);bind(Path(__file__))
for name,h in base['inputs_sha256'].items():assert sha(name)==h,'Changed prerequisite '+name
for f in S.rglob('*'):
 if f.is_file():bind(f)
audit=Path(__file__).with_name('audit-port.py');bind(audit)
def check(n):run(n,[sys.executable,str(audit),str(T),str(a.snapshot),str(O/(n+'.json'))])
check('source-before')
try:
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';bind(ninja)
 def query(target):
  raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);assert len(raw.splitlines())==1
  c=[]
  for w in shlex.split(raw):
   if w.startswith('@'):bind(T/w[1:]);c.extend(shlex.split((T/w[1:]).read_text()))
   else:c.append(w)
  if c[0]=='PWD=/proc/self/cwd':c=c[1:]
  if Path(c[0]).name=='ccache':c=c[1:]
  return c
 target='out/soong/.intermediates/system/netd/server/netd/android_arm64_armv8-a_cfi/obj/system/netd/server/main.o'
 held=next(c.copy() for c in base['commands'] if c[-1].endswith('/Gta3xlwifiHeldProvider.cpp'))
 for name,c in [('main',query(target)),('Gta3xlwifiHeldProvider',held)]:
  assert '-flto' in c and any(w.startswith('-fsanitize=') and 'cfi' in w.split('=',1)[1].split(',') for w in c)
  c.insert(1,'-I'+str(S));c[c.index('-o')+1]=str(O/(name+'.o'));c[c.index('-MF')+1]=str(O/(name+'.o.d'));c[-1]=str(S/(name+'.cpp'));bind(T/c[0]);run(name+'-compile',c)
 full=next(c.copy() for c in base['commands'] if '-o' in c and c[c.index('-o')+1].endswith('/netd'))
 oldserver=next(w for w in full if w.endswith('/libnetd_server.a'));bind(oldserver);server=O/'libnetd_server.a';shutil.copyfile(oldserver,server)
 ar=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin/llvm-ar';bind(ar);run('archive',[str(ar),'rD',str(server),str(O/'Gta3xlwifiHeldProvider.o')]);full[full.index(oldserver)]=str(server)
 oldmain=next(w for w in full if w.endswith('/main.o'));bind(oldmain);full[full.index(oldmain)]=str(O/'main.o');full[full.index('-o')+1]=str(O/'netd');run('netd-link',full)
 # init_rc is a current configurable base property; this product's VendorVar is
 # explicitly string "true", so the selection uses that exact type/value.
 variables=T/'out/soong/soong.lineage_gta3xlwifi.variables';d=json.loads(variables.read_text());assert d['VendorVars']['gta3xlwifi']['legacy_networking']=='true';assert not d.get('VendorVarTypes',{}).get('gta3xlwifi',{}).get('legacy_networking');bind(variables)
 module=T/'build/soong/android/module.go';assert 'Init_rc proptools.Configurable[[]string]' in module.read_text();bind(module)
 for n,path in [('loader.Android.bp','packages/modules/Connectivity/bpf/loader/Android.bp'),('netbpfload.rc','packages/modules/Connectivity/bpf/loader/netbpfload.rc')]:assert (S/(n+'.reference')).read_bytes()==(T/path).read_bytes();bind(T/path)
 verifier=T/'out/host/linux-x86/bin/host_init_verifier';bind(verifier);run('private-init-verify',[str(verifier),str(S/'netbpfload.gta3xlwifi.rc')])
 assert not any(w in (S/'netbpfload.gta3xlwifi.rc').read_text() for w in ['setprop ','wait_for_prop ','exec_start bpfloader'])
 for name,h in inputs.items():assert sha(name)==h
 check('source-after')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'commands':commands,'inputs_sha256':inputs,'actual_main_provider_CFI_full_netd_link':True,'actual_host_init_verifier':True,'stock_init_selected_for_other_products':True,'Soong_selection_type_bound_not_full_graph_build':True,'no_fake_BPF_property':True,'netd_sha256':sha(O/'netd'),'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual private oneshot/provider/main CFI full link, init verifier and complete source audits')
finally:
 if not (O/'source-after.json').exists():check('source-after')
