#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind actual selected A17 LNA permission, prefix, direction and cache expressions.

Read-only source evidence; no policy/map/flag/device modification or enforcement
claim. In migrated permission mode only literal UID0/1000 is exempt, not all core
appIds. Other core behavior must not be copied from the ordinary-owner matcher.
"""
import argparse,fcntl,hashlib,importlib.util,json,re
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','flags-report','source-audit','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
mutex=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(mutex,fcntl.LOCK_EX|fcntl.LOCK_NB)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();flags=json.loads(a.flags_report.read_text());assert flags['passed_source_contract_checks'] and flags['android17_permission_propagation_expected_enabled']
inputs={Path(p):h for p,h in flags['inputs_sha256'].items()}
for f,h in inputs.items():assert sha(f)==h
source=json.loads(a.source_audit.read_text());assert source['passed'] and source['project_count']==1243 and source['reviewed_patch_count']==17
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
c=T/'packages/modules/Connectivity/bpf/progs/netd.c';h=c.with_name('netd.h');ct=c.read_text();ht=h.read_text();root=m.extract(ht,'is_system_or_root');assert 'uid == AID_SYSTEM' in root and 'uid == AID_ROOT' in root and 'AID_USER_OFFSET' not in root
aids=T/'system/core/libcutils/include/private/android_filesystem_config.h';aid=aids.read_text();assert re.search(r'#define AID_ROOT\s+0\b',aid) and re.search(r'#define AID_SYSTEM\s+1000\b',aid)
blocked=m.extract(ct,'is_local_network_access_blocked');assert 'if (is_system_or_root(uid)) return false;' in blocked and 'PERMISSION_BIT_ACCESS_LOCAL_NETWORK' in blocked
allowed=m.extract(ct,'is_local_net_access_allowed');assert 'if (!v || *v)' in allowed and 'return v && *v;' in allowed
cached=m.extract(ct,'is_local_net_access_allowed_cached');assert 'if (!KVER_IS_AT_LEAST(kver, 5, 10))' in cached and 'return is_local_net_access_allowed(&query_key, uid);' in cached
packet=m.extract(ct,'should_block_local_network_packets');assert 'egress.egress ? &packet->daddr : &packet->saddr' in packet and 'egress.egress ? packet->dport : packet->sport' in packet
assert 'STRUCT_SIZE(LocalNetAccessKey, 4 + 4 + 16 + 2 + 2);' in ht and 'STRUCT_SIZE(LocalNetUidHostAllowlistKey, 4 + 4 + 4 + 16);' in ht
java=[]
for name in ['LocalNetAccessKey.java','LocalNetUidHostAllowlistKey.java']:
 paths=list((T/'packages/modules/Connectivity').rglob(name));assert len(paths)==1;java+=paths
for f in [c,h,aids,*java,helper,Path(__file__),a.flags_report,a.source_audit]:inputs[f]=sha(f)
O.mkdir(parents=True);(O/'functions.txt').write_text('\n\n'.join([root,blocked,allowed,cached,packet])+'\n')
for f,h in inputs.items():assert sha(f)==h
(O/'report.json').write_text(json.dumps({'passed_source_contract_checks':True,'scope':__doc__,'inputs_sha256':{str(f):h for f,h in inputs.items()},'permission_exempt_uids_literal':[0,1000],'other_core_appids_not_blanket_exempt':True,'prefix_lookup_default_allow':True,'denied_prefix_exception':'Only a matching true UID/interface/remote-host allowlist entry permits access','key_struct_bytes':28,'max_prefix_payload_bits':192,'remote_endpoint':'egress destination/address+port; ingress source/address+port','old_kernel_cache_branch':'Direct lookup on kernel4.4; no5.10 socket-storage cache','hardware_tested':False,'network_ready':False,'flash_ready':False},indent=2)+'\n');print('PASS source-only LNA contract: literal0/1000 exemptions, mandatory bit, actual LPM/default/override/direction/cache branches')
