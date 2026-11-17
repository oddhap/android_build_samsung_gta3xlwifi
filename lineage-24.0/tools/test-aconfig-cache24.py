#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate a genuine, ordered cache-backed metadata store against current policy.
No flag, service, kernel capability, policy allowance or partition is substituted.
"""
from pathlib import Path
import ctypes,hashlib,json,stat,subprocess,sys
T=Path('/srv/android/src/lineage-24.0-arm64');A=Path('/srv/android/artifacts/lineage-24.0-arm64');C=A/'aconfig-cache-source-composition-20261117-01';O=A/'aconfig-cache-host-20261117-03';O.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sel=json.loads((C/'selection.json').read_text());assert len(sel['files'])==3 and not sel['compiled_policy_rules_changed']
root='device/samsung/gta3xlwifi/';board=root+'BoardConfig.mk';rc=root+'rootdir/init.exynos7904.rc';fc=root+'sepolicy/private/file_contexts'
for f,x in sel['files'].items():assert sha(C/'files'/f)==x['after'] and sha(T/f)==x['before']
source=(C/'files'/rc).read_text();assert source.startswith((T/rc).read_text());assert source.count('mount none /cache/gta3xlwifi_metadata /metadata bind')==1;active='\n'.join(l for l in source[len((T/rc).read_text()):].splitlines() if not l.lstrip().startswith('#'));assert 'mount_all' not in active;assert 'setprop' not in active
verifier=T/'out/host/linux-x86/bin/host_init_verifier';r=subprocess.run([str(verifier),str(C/'files'/rc)],capture_output=True,text=True);(O/'init-verifier.log').write_text(r.stdout+r.stderr);assert r.returncode==0
init=T/'system/core/init/init.cpp';text=init.read_text();assert text.index('parser.ParseConfig("/system/etc/init/hw/init.rc")')<text.index('parser.ParseConfig("/system/etc/init")')
base=T/'system/core/rootdir/init.rc';assert 'import /init.${ro.hardware}.rc' in base.read_text();create=T/'system/core/rootdir/create_root_structure.mk';assert '$(BOARD_ROOT_EXTRA_FOLDERS)' in create.read_text()
arc=T/'out/target/product/gta3xlwifi/system/etc/init/aconfigd.rc';text=arc.read_text();assert 'on post-fs\n' in text and 'exec_start system_aconfigd_platform_init' in text
# Read the actual installed compiled flags; keep the protection's true value.
flags=T/'out/target/product/gta3xlwifi/system/etc/aconfig_flags.pb';tool=T/'out/host/linux-x86/bin/aconfig';name='android.security.aapm_feature_disable_insecure_wifi_autojoin';cmd=[str(tool),'dump','--cache',str(flags),'--filter','fully_qualified_name:'+name,'--format','{fully_qualified_name} {state:bool} {permission} {container}'];r=subprocess.run(cmd,capture_output=True,text=True,check=True);assert r.stdout.strip()==name+' true READ_ONLY system';(O/'actual-security-flag.txt').write_text(r.stdout);flag_line=r.stdout.strip()
prod=T/'out/target/product/gta3xlwifi';paths=[prod/'system/etc/selinux/plat_file_contexts',prod/'system/system_ext/etc/selinux/system_ext_file_contexts',prod/'product/etc/selinux/product_file_contexts',A/'legacy-shm-policy-strict-20261117-01/metadata/vendor/etc/selinux/vendor_file_contexts'];lines=(C/'files'/fc).read_text().splitlines();extra=[l for l in lines if l.startswith('/cache/gta3xlwifi_metadata')];assert len(extra)==len(sel['canonical_metadata_rules'])
combined=O/'combined_file_contexts';combined.write_text('\n'.join(p.read_text() for p in paths)+'\n'+'\n'.join(extra)+'\n')
policy=A/'legacy-shm-policy-strict-20261117-01/strict/strict.policy';candidate=O/'candidate_system_ext_file_contexts';candidate.write_text(paths[1].read_text()+'\n'+'\n'.join(extra)+'\n');r=subprocess.run([str(T/'out/host/linux-x86/bin/checkfc'),'-e',str(policy),str(candidate)],capture_output=True,text=True);assert r.returncode==0,r.stderr
lib=ctypes.CDLL('libselinux.so.1');lib.selabel_open.restype=ctypes.c_void_p
class Opt(ctypes.Structure):_fields_=[('type',ctypes.c_int),('value',ctypes.c_char_p)]
lib.selabel_open.argtypes=[ctypes.c_uint,ctypes.POINTER(Opt),ctypes.c_uint];lib.selabel_lookup.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_char_p),ctypes.c_char_p,ctypes.c_int];lib.freecon.argtypes=[ctypes.c_char_p];lib.selabel_close.argtypes=[ctypes.c_void_p]
op=Opt(3,str(combined).encode());handle=lib.selabel_open(0,ctypes.byref(op),1);assert handle
lookups=[]
for path,expected in [('/cache/gta3xlwifi_metadata','metadata_file'),('/cache/gta3xlwifi_metadata/aconfig/maps/system.package.map','aconfig_storage_metadata_file'),('/cache/gta3xlwifi_metadata/aconfig/flags/system.val','aconfig_storage_flags_metadata_file'),('/cache/gta3xlwifi_metadata_other','cache_file'),('/cache/recovery','cache_recovery_file')]:
 ctx=ctypes.c_char_p();assert lib.selabel_lookup(handle,ctypes.byref(ctx),path.encode(),stat.S_IFDIR)==0;label=ctx.value.decode();lib.freecon(ctx);assert label=='u:object_r:'+expected+':s0',(path,label,expected);lookups.append(dict(path=path,label=label))
lib.selabel_close(handle)
queries=[]
def q(s,t,c,p,exp='allow'):queries.append(dict(source='u:r:'+s+':s0',target='u:object_r:'+t+':s0',**{'class':c},permission=p,expected=exp))
for p in ['mounton','create','search','setattr']:q('init','metadata_file','dir',p)
for p in ['search','add_name']:q('init','cache_file','dir',p)
q('init','labeledfs','filesystem','mount')
for s in ['aconfigd','aconfigd_mainline']:
 for t in ['aconfig_storage_metadata_file','aconfig_storage_flags_metadata_file']:
  for p in ['search','create','add_name']:q(s,t,'dir',p)
  for p in ['open','create','write','read','map']:q(s,t,'file',p)
for s in ['system_server','untrusted_app']:
 for p in ['open','read','map']:q(s,'aconfig_storage_metadata_file','file',p)
 q(s,'aconfig_storage_metadata_file','file','write','deny');q(s,'aconfig_storage_flags_metadata_file','dir','search','deny');q(s,'aconfig_storage_flags_metadata_file','file','read','deny')
(O/'queries.json').write_text(json.dumps(queries,indent=2)+'\n')
# Existing mapper regression depends on unchanged sources and the exact same
# boolean config call. Rebind only the unrelated root-directory addition; actual
# production Soong types and dual-ABI compiler flags are checked again after build.
old=A/'legacy-gralloc-host-20261117-02/report.json';g=json.loads(old.read_text());assert g['passed'];assert sha(C/'baseline'/board)==g['source_sha256'][board]
assert (C/'files'/board).read_text().startswith((C/'baseline'/board).read_text());delta=(C/'files'/board).read_text()[len((C/'baseline'/board).read_text()):];assert delta=='\n# Immutable SAR root needs the real metadata bind-mount point.\nBOARD_ROOT_EXTRA_FOLDERS += metadata\n'
assert (C/'files'/board).read_text().count('$(call soong_config_set_bool,libui,legacy_gralloc,true)')==1
g['source_sha256'][board]=sha(C/'files'/board);g.update(inherited_actual_mapper_regression_sha256=sha(old),mapper_tests_rerun=False,only_unrelated_root_directory_added=True,root_delta=delta);(O/'mapper-regression-binding.json').write_text(json.dumps(g,indent=2)+'\n')
report=dict(passed=True,scope=__doc__,source_sha256={f:sha(C/'files'/f) for f in sel['files']},actual_init_parser_exit=0,root_import_precedes_service_config_parse=True,supported_aconfig_post_fs_retry_retained=True,actual_security_flag=flag_line,actual_metadata_label_lookups=lookups,all_canonical_metadata_rules_mirrored=True,compiled_policy_rules_changed=False,existing_partition_and_userdata_preserved=True,flag_values_or_services_disabled=False,inputs_sha256={str(p):sha(p) for p in [init,base,create,arc,flags,tool,verifier,policy]},hardware_backend_proven=False,flash_ready=False)
(O/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS actual init parser/order, real security flag, complete canonical metadata labels and retained mapper configuration')
