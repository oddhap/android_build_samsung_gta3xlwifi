#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind qtaguid group initialization to actual A17 zygote and kernel filtering.

Source/configuration and real init-parser checks only; no live ownership,
credentials, counters, kernel operation or device readiness is established.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','kernel-src','kernel-config','candidate-rc','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();kernel=a.kernel_src/'net/netfilter/xt_qtaguid.c';generic=a.kernel_src/'fs/proc/generic.c';zygote=T/'frameworks/base/core/java/com/android/internal/os/ZygoteInit.java';ids=T/'system/core/libcutils/include/private/android_filesystem_config.h';old=T/'device/samsung/gta3xlwifi/rootdir/init.gta3xlwifi.compat.rc';verifier=T/'out/host/linux-x86/bin/host_init_verifier'
paths=[Path(__file__),kernel,generic,zygote,ids,old,a.kernel_config,a.candidate_rc,verifier];inputs={str(p.resolve()):sha(p) for p in paths}
cfg=a.kernel_config.read_text().splitlines();assert 'CONFIG_NETFILTER_XT_MATCH_QTAGUID=y' in cfg
q=kernel.read_text();assert 'static bool proc_stats_readall_limited = true;' in q
start=q.index('static bool can_read_other_uid_stats(');predicate=q[start:q.index('\n}',start)+3];assert 'in_egroup_p(xt_qtaguid_stats_file->gid)' in predicate and 'proc_stats_readall_limited' in predicate
start=q.index('static int __init qtaguid_proc_register(');register=q[start:q.index('\n}',start)+3];assert 'proc_create_data("stats"' in register and 'proc_set_user' not in register
assert not re.search(r'xt_qtaguid_stats_file->(?:uid|gid)\s*=',q)
g=generic.read_text();start=g.index('static struct proc_dir_entry *__proc_create(');create=g[start:g.index('\n}',start)+3];assert 'ent = kzalloc(' in create and not re.search(r'ent->(?:uid|gid)\s*=',create)
numbers={}
for name,expected in [('ROOT',0),('NET_BW_STATS',3006),('NET_BW_ACCT',3007)]:
 match=re.search(r'^#define AID_'+name+r'\s+(\d+)\b',ids.read_text(),re.M);assert match and int(match.group(1))==expected;numbers[name]=expected
z=zygote.read_text();matches=list(re.finditer(r'"--setgroups=[0-9,]+"(?:\s*\+\s*"[0-9,]+")*',z));assert len(matches)==1
m=matches[0];literal=''.join(re.findall(r'"([^"]*)"',m.group()));groups=list(map(int,literal.removeprefix('--setgroups=').split(',')));assert 3006 in groups and 3007 in groups;assert '"--setuid=1000"' in z[m.start()-200:m.start()] and '"--setgid=1000"' in z[m.start()-200:m.start()]
rc=a.candidate_rc.read_text();before=old.read_text();assert 'xt_qtaguid' not in before
addition='''
    # qtaguid filters rows by these real groups; readable alone is insufficient.
    # Keep its kernel UID restrictions enabled and restrict direct control writes.
    chown root net_bw_stats /proc/net/xt_qtaguid/stats
    chmod 0440 /proc/net/xt_qtaguid/stats
    chown root net_bw_acct /proc/net/xt_qtaguid/ctrl
    chmod 0660 /proc/net/xt_qtaguid/ctrl
''';assert rc.count(addition)==1 and rc.replace(addition,'')==before
assert rc.index(addition)<rc.index('on shutdown') and 'on init\n    stop cpboot-daemon\n'+addition in rc
assert 'bpf.progs_loaded' not in rc and 'stats_readall_limited' not in rc and 'ctrl_write_limited' not in rc
cmd=[str(verifier),str(a.candidate_rc.resolve())];result=subprocess.run(cmd,capture_output=True,text=True);(O/'init-verifier.log').write_text(result.stdout+result.stderr);assert result.returncode==0,(result.stdout,result.stderr)
for path,h in inputs.items():assert sha(Path(path))==h,'Input changed: '+path
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'inputs_sha256':inputs,'platform_aids':numbers,'actual_system_server_groups':groups,'actual_kernel_predicate_sha256':hashlib.sha256(predicate.encode()).hexdigest(),'default_kernel_proc_entry_zero_initialized':True,'kernel_group_restrictions_remain_enabled':True,'candidate_rc_only_adds_four_metadata_commands_and_comments':True,'candidate_stats_mode':'0440','candidate_ctrl_mode':'0660','init_verifier_command':cmd,'init_verifier_exit':result.returncode,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual kernel filtering/A17 zygote group contract and real init parser; no limiter/readiness bypass')
