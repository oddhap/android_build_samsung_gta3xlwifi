#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile/link sole-owner DNS callbacks through the actual resolver DSO, outside TOP.

Retains current compiler/CFI/dependency flags, appends one resolver export, checks
full netd/resolver links and full source audits. Not device or boot execution.
"""
import argparse,fcntl,hashlib,json,re,shlex,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','base-report','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();inputs={};commands=[]
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
def run(label,command):
 commands.append(command);x=subprocess.run(command,cwd=T,capture_output=True,text=True);(O/(label+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,(label,x.stderr[-14000:]);return x.stdout
base=json.loads(a.base_report.read_text());assert base['passed'] and base['full_netd_linked'];bind(a.base_report);bind(Path(__file__))
for path,h in base['inputs_sha256'].items():assert sha(path)==h,'Changed prerequisite '+path
for q in S.rglob('*'):
 if q.is_file():bind(q)
audit=Path(__file__).with_name('audit-port.py');bind(audit);ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';bind(ninja)
def check(name):run(name,[sys.executable,str(audit),str(T),str(a.snapshot),str(O/(name+'.json'))])
def query(target):
 raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',target],cwd=T,text=True);assert len(raw.splitlines())==1
 args=[]
 for word in shlex.split(raw):
  if word.startswith('@'):bind(T/word[1:]);args.extend(shlex.split((T/word[1:]).read_text()))
  else:args.append(word)
 if args[0]=='PWD=/proc/self/cwd':args=args[1:]
 if Path(args[0]).name=='ccache':args=args[1:]
 return args
check('source-before')
try:
 helper='out/soong/.intermediates/packages/modules/Connectivity/bpf/dns_helper/libdns_helper/android_arm64_armv8-a_static_cfi_apex31_sabi/obj/packages/modules/Connectivity/bpf/dns_helper/DnsBpfHelper.o'
 proxy='out/soong/.intermediates/packages/modules/DnsResolver/libnetd_resolv/android_arm64_armv8-a_static_cfi_apex31_sabi/obj/packages/modules/DnsResolver/DnsProxyListener.o'
 resolver='out/soong/.intermediates/packages/modules/DnsResolver/libnetd_resolv/android_arm64_armv8-a_shared_cfi_apex31/unstripped/libnetd_resolv.so'
 for source,path in [('DnsBpfHelper.cpp','packages/modules/Connectivity/bpf/dns_helper/DnsBpfHelper.cpp'),('DnsProxyListener.cpp','packages/modules/DnsResolver/DnsProxyListener.cpp'),('libnetd_resolv.map.txt','packages/modules/DnsResolver/libnetd_resolv.map.txt')]:assert (S/(source+'.reference')).read_bytes()==(T/path).read_bytes();bind(T/path)
 def compile(name,template):
  command=template.copy();assert '-flto' in command and any(x.startswith('-fsanitize=') and 'cfi' in x.split('=',1)[1].split(',') for x in command)
  command[1:1]=['-I'+str(S)];command[command.index('-o')+1]=str(O/(name+'.o'));command[command.index('-MF')+1]=str(O/(name+'.o.d'));command[-1]=str(S/(name+'.cpp'));bind(T/command[0]);run(name+'-compile',command);return str(O/(name+'.o'))
 p_template=next(c for c in base['commands'] if c[-1].endswith('/Gta3xlwifiSocketPolicyProjection.cpp'))
 projection=compile('Gta3xlwifiSocketPolicyProjection',p_template);held=compile('Gta3xlwifiHeldProvider',p_template)
 helper_obj=compile('DnsBpfHelper',query(helper));proxy_obj=compile('DnsProxyListener',query(proxy))
 resolver_link=query(resolver);bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';ar=bin/'llvm-ar';bind(ar)
 assert resolver_link.count(proxy)==1;resolver_link[resolver_link.index(proxy)]=proxy_obj
 # The actual helper is static inside the resolver. Rebuild its archive, never
 # register a second helper copy in netd or link it as another DSO.
 archive=next(x for x in resolver_link if x.endswith('/libdns_helper.a'));bind(T/archive);new_archive=O/'libdns_helper.a';shutil.copyfile(T/archive,new_archive);run('helper-archive',[str(ar),'rD',str(new_archive),helper_obj]);resolver_link[resolver_link.index(archive)]=str(new_archive)
 version='-Wl,--version-script,packages/modules/DnsResolver/libnetd_resolv.map.txt';assert version in resolver_link;resolver_link[resolver_link.index(version)]='-Wl,--version-script,'+str(S/'libnetd_resolv.map.txt')
 resolver_link[resolver_link.index('-o')+1]=str(O/'libnetd_resolv.so');run('resolver-link',resolver_link)
 def exported(path):
  text=subprocess.check_output([str(bin/'llvm-nm'),'--dynamic','--defined-only',str(path)],text=True);return {line.split()[-1] for line in text.splitlines() if len(line.split())>=3}
 old_symbols=exported(T/resolver);new_symbols=exported(O/'libnetd_resolv.so');extra={s for s in new_symbols-old_symbols if s.startswith('resolv_set_gta3xlwifi_policy')};assert len(extra)==1 and new_symbols==old_symbols|extra,(old_symbols-new_symbols,new_symbols-old_symbols)
 full=next(c.copy() for c in base['commands'] if '-o' in c and c[c.index('-o')+1].endswith('/netd'))
 old_server=next(x for x in full if x.endswith('/libnetd_server.a'));bind(old_server);server=O/'libnetd_server.a';shutil.copyfile(old_server,server);run('server-archive',[str(ar),'rD',str(server),projection,held]);full[full.index(old_server)]=str(server)
 old_resolver=next(x for x in full if x.endswith('/libnetd_resolv.so'));bind(T/old_resolver);full[full.index(old_resolver)]=str(O/'libnetd_resolv.so');full[full.index('-o')+1]=str(O/'netd');run('netd-link',full)
 readelf=bin/'llvm-readelf';bind(readelf)
 def needed(path):return re.findall(r'\(NEEDED\).*\[(.*?)\]',subprocess.check_output([str(readelf),'-d',str(path)],text=True))
 assert needed(O/'netd')==needed(a.base_report.parent/'netd');assert needed(O/'libnetd_resolv.so')==needed(T/resolver)
 for c in [resolver_link,full]:
  for word in c:
   path=Path(word) if word.startswith('/') else T/word
   if path.is_file() and not path.is_relative_to(O):bind(path)
 for path,h in inputs.items():assert sha(path)==h
 check('source-after')
 (O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'commands':commands,'inputs_sha256':inputs,'one_actual_static_DNS_helper_instance':True,'new_resolver_export':sorted(extra),'original_resolver_exports_preserved':True,'netd_sha256':sha(O/'netd'),'resolver_sha256':sha(O/'libnetd_resolv.so'),'original_CFI_flags_retained':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual resolver/netd CFI links, one static DNS-helper instance, append-only export and source audits')
finally:
 if not (O/'source-after.json').exists():check('source-after')
