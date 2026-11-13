#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check exact packet producer capability delta, unchanged accounting and four product configs.

A compiled-source primitive, never a BPF object, installed-rule or Ready claim.
Actual ARM64 producer reachability remains a mandatory full-kernel build check.
"""
import argparse,hashlib,importlib.util,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','config','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
h=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',h);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
rel='net/netfilter/gta3xlwifi_packet_stats.c';module=S/rel;old=B/rel;new=module.read_text();fn=m.extract(new,'gta3xlwifi_packet_hooks_features');assert new.replace(fn+'\nEXPORT_SYMBOL_GPL(gta3xlwifi_packet_hooks_features);\n','',1)==old.read_text()
rel='include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h';header=S/rel;oldheader=B/rel;addition='/* Compiled dual-stack actual packet producers, separate from storage. */\n#define GTA3XLWIFI_UID_CAP_PACKET_STATS_HOOKS (1U << 13)\n';assert header.read_text().replace(addition,'',1)==oldheader.read_text()
rel='include/net/gta3xlwifi_packet_stats.h';assert (S/rel).read_text().replace('u32 gta3xlwifi_packet_hooks_features(void);\n','',1)==(B/rel).read_text()
rel='net/netfilter/gta3xlwifi_netpolicy.c';assert (S/rel).read_text().replace(' | gta3xlwifi_packet_hooks_features();',';',1)==(B/rel).read_text()
raw=S/'net/netfilter/xt_qtaguid.c';assert sha(raw)==sha(B/'net/netfilter/xt_qtaguid.c')
config=a.config.read_text()
for name in ['CONFIG_INET','CONFIG_IPV6','CONFIG_NETFILTER_XT_MATCH_QTAGUID']:assert re.search('^'+name+'=y$',config,re.M)
code='#include <assert.h>\n#include <stdint.h>\n#include <stdio.h>\n#include "'+str(header)+'"\ntypedef uint32_t u32;\n'+fn+'\n'+m.extract(new,'gta3xlwifi_packet_stats_features')+'''
int main(void){
#ifdef BOTH_ENABLED
 assert(gta3xlwifi_packet_hooks_features()==8192);
 assert(gta3xlwifi_packet_stats_features()==4096);
#else
 assert(gta3xlwifi_packet_hooks_features()==0);
 assert(gta3xlwifi_packet_stats_features()==0);
#endif
 puts("passed_cases=2");return 0;
}
''';(O/'test.c').write_text(code);variants=[]
for flags in [[],['-DCONFIG_INET=1'],['-DCONFIG_IPV6=1'],['-DCONFIG_INET=1','-DCONFIG_IPV6=1','-DBOTH_ENABLED=1']]:
 n=str(len(variants));cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror',*flags,'-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all',str(O/'test.c'),'-o',str(O/('test-'+n))];x=subprocess.run(cmd,capture_output=True,text=True);(O/('compile-'+n+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
 x=subprocess.run([str(O/('test-'+n))],capture_output=True,text=True,timeout=30);(O/('test-'+n+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0 and x.stdout=='passed_cases=2\n' and not x.stderr;variants.append({'flags':flags,'command':cmd,'passed_cases':2})
paths=[Path(__file__),h,module,old,header,oldheader,raw,B/'net/netfilter/xt_qtaguid.c',a.config,O/'test.c',S/'net/netfilter/gta3xlwifi_netpolicy.c',B/'net/netfilter/gta3xlwifi_netpolicy.c',S/'include/net/gta3xlwifi_packet_stats.h',B/'include/net/gta3xlwifi_packet_stats.h'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':8,'config_variants':variants,'only_exact_getter_header_dispatch_delta':True,'packet_and_accounting_bodies_identical':True,'actual_product_builtin_dual_stack_config_checked':True,'inputs_sha256':{str(p):sha(p) for p in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: 8 packet feature getter checks/four configs, exact accounting identity and product config bound')
