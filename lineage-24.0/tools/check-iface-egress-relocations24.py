#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify actual ARM64 output code changes only the policy call target.

Compiler inlining can duplicate source callback bodies. Compare complete actual
baseline/candidate disassembly, not an assumed source-to-machine call count.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['base-output','candidate-output','objdump','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={str(Path(__file__).resolve()):sha(Path(__file__)),str(a.objdump):sha(a.objdump)};results=[]
for rel in ['net/ipv4/ip_output.o','net/ipv6/ip6_output.o']:
 before=a.base_output/rel;after=a.candidate_output/rel;inputs[str(before)]=sha(before);inputs[str(after)]=sha(after)
 values=[]
 for name,path in [('before',before),('after',after)]:
  text=subprocess.check_output([str(a.objdump),'-dr',str(path)],text=True);(O/(Path(rel).stem+'-'+name+'.txt')).write_text(text);values.append(text.replace(str(path),'<object>'))
 old,new=values;assert 'gta3xlwifi_accounted_egress' not in old and 'gta3xlwifi_egress_policy' not in new
 n=len(re.findall(r'R_AARCH64_(?:CALL|JUMP)26\s+gta3xlwifi_egress_policy\b',old));m=len(re.findall(r'R_AARCH64_(?:CALL|JUMP)26\s+gta3xlwifi_accounted_egress\b',new));assert n>0 and n==m,(rel,n,m)
 assert old==new.replace('gta3xlwifi_accounted_egress','gta3xlwifi_egress_policy'),rel
 results.append({'object':rel,'baseline_policy_call_relocations':n,'candidate_accounted_call_relocations':m,'entire_normalized_disassembly_identical':True})
module=a.candidate_output/'net/netfilter/gta3xlwifi_iface_stats.o';inputs[str(module)]=sha(module);text=subprocess.check_output([str(a.objdump),'-dr',str(module)],text=True);(O/'iface-module.txt').write_text(text)
# The policy is external; the compiler may inline the same-TU counter function.
assert re.search(r'R_AARCH64_(?:CALL|JUMP)26\s+gta3xlwifi_egress_policy\b',text)
for f,h in inputs.items():assert sha(Path(f))==h
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'output_objects':results,'counter_module_calls_actual_policy':True,'inputs_sha256':inputs,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: complete IPv4/IPv6 code identity after policy-target substitution;',sum(r['candidate_accounted_call_relocations'] for r in results),'actual call relocations')
