#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute actual interface registration/correction feature getters for four configs.

Registration/config inputs are fixtures. Product config and actual source are
hash-bound; full ARM64 callback relocations are a separate mandatory check.
"""
import argparse,hashlib,importlib.util,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','config','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
module=S/'net/netfilter/gta3xlwifi_iface_stats.c';raw=S/'net/netfilter/xt_qtaguid.c';header=S/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h';config=a.config.read_text()
for name in ['CONFIG_INET','CONFIG_IPV6','CONFIG_NETFILTER_XT_MATCH_QTAGUID']:assert re.search('^'+name+'=y$',config,re.M)
code='#include <assert.h>\n#include <stdbool.h>\n#include <stdint.h>\n#include <stdio.h>\n#include "'+str(header)+'"\ntypedef uint32_t u32;\n#define READ_ONCE(x) (x)\nstatic bool gta3xlwifi_iface_registered;\n'+m.extract(module.read_text(),'gta3xlwifi_iface_egress_features')+'\n'+m.extract(raw.read_text(),'gta3xlwifi_iface_stats_features')+'''
int main(void){
#ifdef BOTH_ENABLED
 unsigned expected=GTA3XLWIFI_UID_CAP_IFACE_DROP_UNDO;
#else
 unsigned expected=0;
#endif
 assert(gta3xlwifi_iface_egress_features()==expected);
 assert(gta3xlwifi_iface_stats_features()==0);
 gta3xlwifi_iface_registered=true;
 assert(gta3xlwifi_iface_stats_features()==(GTA3XLWIFI_UID_CAP_IFACE_STATS|expected));
 puts("passed_cases=3");
}
'''
(O/'test.c').write_text(code);variants=[]
for flags in [[],['-DCONFIG_INET=1'],['-DCONFIG_IPV6=1'],['-DCONFIG_INET=1','-DCONFIG_IPV6=1','-DBOTH_ENABLED=1']]:
 n=str(len(variants));cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror',*flags,'-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all',str(O/'test.c'),'-o',str(O/('test-'+n))];x=subprocess.run(cmd,capture_output=True,text=True);(O/('compile-'+n+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
 x=subprocess.run([str(O/('test-'+n))],capture_output=True,text=True,timeout=30);(O/('test-'+n+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0 and x.stdout=='passed_cases=3\n' and not x.stderr;variants.append({'flags':flags,'command':cmd,'passed_cases':3})
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,module,raw,header,a.config,O/'test.c'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':12,'config_variants':variants,'actual_product_builtin_dual_stack_config_checked':True,'inputs_sha256':{str(p):sha(p) for p in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: 12 feature getter checks/four configs, actual product config bound')
