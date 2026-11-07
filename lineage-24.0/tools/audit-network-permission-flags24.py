#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind selected CP2A permission/metrics flag values to actual generated Java.

Read-only source/cache/generated-code audit, not runtime or readiness evidence.
No flags, policy inputs, maps or properties are changed.
"""
import argparse,fcntl,hashlib,json,re,subprocess,sys,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','snapshot','platform-contract','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p)
audit=Path(__file__).with_name('audit-port.py');bind(audit);bind(Path(__file__))
def audit_source(name):subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/name)],check=True)
audit_source('source-audit-before.json')
try:
 prior=json.loads(a.platform_contract.read_text());assert prior['passed_source_contract_checks'] and not prior['flags_changed'];bind(a.platform_contract)
 for path,h in prior['inputs_sha256'].items():assert sha(Path(path))==h,path;bind(path)
 platform={x['name']:x for x in prior['selected_cp2a_security_flags']};assert len(platform)==2 and all(x['permission']=='READ_ONLY' and x['actual_generated_getter_returns'] is True for x in platform.values())
 base=T/'out/soong/.intermediates/packages/modules/Connectivity/common';cache=base/'com.android.tethering.flags-aconfig/aconfig-cache.pb';aconfig=T/'out/host/linux-x86/bin/aconfig';bind(cache);bind(aconfig)
 names={'permission_map_uid_migration':('permissionMapUidMigration',True),'loopback_access_metrics':('loopbackAccessMetrics',True),'collect_beta_metrics':('collectBetaMetrics',False)}
 cmd=[str(aconfig),'dump','--cache',str(cache),'--format','{fully_qualified_name}|{state}|{permission}|{is_fixed_read_only}|{trace:paths}']
 for n in names:cmd+=['--filter','name:'+n]
 raw=subprocess.check_output(cmd,text=True);(O/'selected-flags.txt').write_text(raw);rows={}
 for line in raw.splitlines():
  if not line:continue
  fq,state,permission,fixed,trace=line.split('|');n=fq.removeprefix('com.android.tethering.flags.');assert n in names and fq=='com.android.tethering.flags.'+n and n not in rows;assert state==('ENABLED' if names[n][1] else 'DISABLED') and permission=='READ_ONLY'
  paths=[value.strip() for value in trace.split(',')]
  for path in paths:
   resolved=(T/path).resolve();assert resolved.is_relative_to(T);bind(resolved)
  rows[n]={'fully_qualified_name':fq,'state':state,'permission':permission,'is_fixed_read_only':fixed=='true','trace_paths':paths,'generated_getters':[]}
 assert set(rows)==set(names)
 for variant in ['android_common','android_common_apex31']:
  jar=base/'com.android.tethering.flags-aconfig-java'/variant/'gen/com.android.tethering.flags-aconfig-java.srcjar';bind(jar)
  with zipfile.ZipFile(jar) as z:
   files=[n for n in z.namelist() if n.endswith('/Flags.java') or n.endswith('/FeatureFlagsImpl.java')];assert files
   for n,(method,expected) in names.items():
    found=[]
    for member in files:
     text=z.read(member).decode();matches=list(re.finditer(r'public\s+(?:static\s+)?boolean\s+'+method+r'\(\)\s*\{\s*return\s+(true|false);\s*\}',text))
     for match in matches:assert (match[1]=='true')==expected;found.append({'srcjar':str(jar),'member':member,'getter':match[0],'returns':expected})
    assert found,(variant,method);rows[n]['generated_getters']+=found
 for path in [T/'packages/modules/Connectivity/common/Android.bp',T/'packages/modules/Connectivity/service/src/com/android/server/BpfNetMaps.java']:bind(path)
 java=(T/'packages/modules/Connectivity/service/src/com/android/server/BpfNetMaps.java').read_text();assert 'return sPermissionMapUidMigrationEnabled && mDeps.isAccessLocalNetworkPermissionEnabled();' in java
 for path,h in inputs.items():assert sha(Path(path))==h,path
 audit_source('source-audit-after.json')
 (O/'report.json').write_text(json.dumps({'passed_source_contract_checks':True,'scope':__doc__,'project_revisions':prior['project_revisions'],'inputs_sha256':inputs,'command':cmd,'selected_cp2a_flags':list(rows.values()),'platform_security_flags_reused':prior['selected_cp2a_security_flags'],'android17_permission_propagation_expected_enabled':True,'uid_migration_requires_real_dynamic_no_internet_create_check':True,'static_inet_group_check_is_not_complete_dynamic_permission_enforcement':True,'loopback_metrics_requires_real_event_producer_and_consumer':True,'beta_local_network_metrics_selected_disabled':True,'runtime_or_hardware_tested':False,'flags_changed':False,'bpf_or_network_ready_claimed':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual CP2A readonly UID migration/loopback metrics enabled, beta metrics disabled; both generated Java variants bound')
finally:
 if not (O/'source-audit-after.json').exists():audit_source('source-audit-after.json')
