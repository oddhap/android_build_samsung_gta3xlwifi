#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record actual Android17 networking contracts and existing kernel enforcement.

Read-only source/generated-code evidence, not hardware probes or backend readiness.
No flags, maps, permissions, properties, processes or policy inputs are replaced.
"""
import argparse,fcntl,hashlib,json,re,subprocess,sys,xml.etree.ElementTree as ET,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','snapshot','kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();K=a.kernel.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
mutex=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(mutex,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(p):p=Path(p).resolve();inputs[str(p)]=sha(p);return p
audit=bind(Path(__file__).with_name('audit-port.py'));bind(Path(__file__))
def source_audit(name):subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/name)],check=True)
source_audit('source-audit-before.json')
try:
 manifest=bind(a.snapshot/'port-manifest.xml');revisions={x.get('path',x.get('name')):x.get('revision') for x in ET.parse(manifest).getroot().iter('project')}
 jar=bind(T/'out/soong/.intermediates/frameworks/base/android.permission.flags-aconfig-java/android_common/gen/android.permission.flags-aconfig-java.srcjar')
 with zipfile.ZipFile(jar) as z:generated=z.read('android/permission/flags/Flags.java').decode()
 flags=[]
 for flag,method in [('access_local_network_permission_enabled','accessLocalNetworkPermissionEnabled'),('use_loopback_interface_permission_enabled','useLoopbackInterfacePermissionEnabled')]:
  proto=bind(T/'build/release/aconfig/cp2a/android.permission.flags'/(flag+'_flag_values.textproto'));text=proto.read_text()
  assert 'state: ENABLED' in text and 'permission: READ_ONLY' in text
  getter=re.search(r'public static boolean '+method+r'\(\)\s*\{\s*return true;\s*\}',generated);assert getter,method
  flags.append({'name':flag,'package':'android.permission.flags','selected_release_value':'ENABLED','permission':'READ_ONLY','actual_generated_getter_returns':True,'getter':getter.group()})
 bpf=bind(T/'packages/modules/Connectivity/service/src/com/android/server/BpfNetMaps.java');text=bpf.read_text()
 assert 'if (SdkLevel.isAtLeastT()) {\n            sL4sSupported = deps.isL4sProgramLoaded();\n            initBpfMaps(deps);' in text
 updatable=bind(T/'packages/modules/Connectivity/bpf/netd/NetdUpdatable.cpp');u=updatable.read_text();assert 'sBpfHandler.init(cg2_path)' in u and re.search(r'if \(!ret.ok\(\)\)\s*\{[^}]*abort\(\);',u)
 aidl=bind(T/'packages/modules/Connectivity/staticlibs/netd/Android.bp');assert '"netd_aidl_interface-V18-java"' in aidl.read_text() and 'versions_with_info:' in aidl.read_text()
 platform=bind(T/'frameworks/base/data/etc/platform.xml');permission=ET.parse(platform).getroot().find("permission[@name='android.permission.INTERNET']");assert permission is not None and any(g.get('gid')=='inet' for g in permission.findall('group'))
 config=bind(K/'out/.config');cfg=config.read_text();assert 'CONFIG_ANDROID_PARANOID_NETWORK=y\n' in cfg and '# CONFIG_BPF_SYSCALL is not set\n' in cfg
 sources=[]
 for relative in ['net/ipv4/af_inet.c','net/ipv6/af_inet6.c']:
  path=bind(K/'src'/relative);body=path.read_text();assert re.search(r'#ifdef CONFIG_ANDROID_PARANOID_NETWORK.*?return in_egroup_p\(AID_INET\) \|\| capable\(CAP_NET_RAW\);',body,re.S)
  assert re.search(r'if \(!current_has_network\(\)\)\s*return -EACCES;',body);sources.append(relative)
 kernel_aids=bind(K/'src/include/linux/android_aid.h');android_aids=bind(T/'system/core/libcutils/include/private/android_filesystem_config.h')
 assert re.search(r'#define AID_INET\s+KGIDT_INIT\(3003\)',kernel_aids.read_text())
 assert re.search(r'#define AID_INET\s+3003\b',android_aids.read_text())
 for path,h in inputs.items():assert sha(Path(path))==h,'Changed input: '+path
 source_audit('source-audit-after.json')
 (O/'report.json').write_text(json.dumps({'passed_source_contract_checks':True,'scope':__doc__,'inputs_sha256':inputs,'project_revisions':{k:revisions[k] for k in ['build/release','frameworks/base','packages/modules/Connectivity','system/core']},'selected_cp2a_security_flags':flags,'existing_internet_permission_mechanism':{'kernel_config_enabled':True,'ipv4_ipv6_create_paths':sources,'permission_linux_group':3003,'privileged_exception':'CAP_NET_RAW','denial_errno':'EACCES','android17_platform_permission_maps_inet_group':True,'device_execution_tested':False},'current_backend_gates':{'java_initialization_opens_real_bpf_maps_on_T_plus':True,'native_updatable_initialization_aborts_on_real_bpf_handler_failure':True,'stable_netd_aidl_version':18,'complete_legacy_provider_still_required':True},'flags_changed':False,'bpf_or_network_ready_claimed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS source contract: actual generated LNA/loopback flags TRUE; real existing IPv4/IPv6 INET group enforcement; actual startup gates retained')
finally:
 if not (O/'source-audit-after.json').exists():source_audit('source-audit-after.json')
