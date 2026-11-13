#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind actual factory defaults and actual A17 MARK/policy save formatting.

Executes previously tested actual factory code and actual formatter bodies with
minimal payload fixtures. No kernel rules, ABI execution or readiness is claimed.
"""
import argparse,hashlib,importlib.util,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['factory-host','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);R=a.factory_host;A=a.android_source;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['mark_variants']==20
for name,h in r['inputs_sha256'].items():assert sha(Path(name))==h
prefix=(R/'test.cpp').read_text().split('static unsigned cases,variants;',1)[0]
(O/'factory.cpp').write_text(prefix+'\nint main(){for(const auto&row:BandwidthController::makeGta3xlwifiAccountingCommands()){for(unsigned char c:row)printf("%02x",c);puts("");}}\n')
cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-I'+str(A/'system/netd/include'),str(O/'factory.cpp'),'-o',str(O/'factory')];x=subprocess.run(cmd,capture_output=True,text=True);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'factory')],capture_output=True,text=True);assert x.returncode==0 and not x.stderr;rows=[bytes.fromhex(s).decode() for s in x.stdout.splitlines()];assert rows[-1]=='COMMIT\n';(O/'source-program.json').write_text(json.dumps(rows,indent=2)+'\n')
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
mark=A/'external/iptables/extensions/libxt_MARK.c';policy=A/'external/iptables/extensions/libxt_policy.c';uapi=A/'bionic/libc/kernel/uapi/linux/netfilter/xt_policy.h';flags={n:int(v,16) for n,v in re.findall(r'XT_POLICY_MATCH_(IN|OUT|NONE|STRICT) = (0x[0-9a-f]+)',uapi.read_text())};assert flags=={'IN':1,'OUT':2,'NONE':4,'STRICT':8}
code='#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\nstruct xt_mark_tginfo2{uint32_t mark,mask;};struct xt_entry_target{_Alignas(8) unsigned char data[8];};struct xt_policy_info{unsigned flags;};\n'
for name,value in flags.items():code+='#define XT_POLICY_MATCH_'+name+' '+str(value)+'\n'
code+=m.extract(mark.read_text(),'mark_tg_save')+'\n'+m.extract(policy.read_text(),'print_flags')+'''
int main(void){struct xt_entry_target t;struct xt_mark_tginfo2*info=(void*)t.data;info->mark=0x100000;info->mask=0x100000;printf("-j MARK");mark_tg_save(NULL,&t);puts("");info->mark=0;printf("-j MARK");mark_tg_save(NULL,&t);puts("");struct xt_policy_info p={XT_POLICY_MATCH_IN};printf("-m policy");print_flags("--",&p);puts("");p.flags=XT_POLICY_MATCH_OUT;printf("-m policy");print_flags("--",&p);puts("");}
'''
(O/'formatters.c').write_text(code);command=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all',str(O/'formatters.c'),'-o',str(O/'formatters')];x=subprocess.run(command,capture_output=True,text=True);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'formatters')],capture_output=True,text=True);assert x.returncode==0 and not x.stderr;expected=['-j MARK --set-xmark 0x100000/0x100000','-j MARK --set-xmark 0x0/0x100000','-m policy --dir in --pol ipsec','-m policy --dir out --pol ipsec'];assert x.stdout.splitlines()==expected
(O/'canonical-formatters.json').write_text(json.dumps(expected,indent=2)+'\n');paths=[Path(__file__),helper,R/'report.json',R/'test.cpp',mark,policy,uapi,O/'factory.cpp',O/'formatters.c'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'source_program':rows,'canonical_formatter_results':expected,'inputs_sha256':{str(p):sha(p) for p in paths},'factory_compile_command':cmd,'formatter_compile_command':command,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual factory defaults and four actual formatter outputs')
