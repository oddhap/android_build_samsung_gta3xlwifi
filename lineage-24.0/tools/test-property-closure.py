#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-check positive property-owner closure against the real Android17 secilc.

Replays the exact positive dependency graph in a small noninstallable policy.
Strict fixtures independently detect both missing and falsely assigned owners.
This is compiler membership validation, not AV/MLS runtime or boot validation.
"""
import argparse, hashlib, json, subprocess
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
for n in ['proof','compiler','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();r=json.loads(a.proof.read_text());out=a.output.resolve();assert not out.exists()
assert not out.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for path,h in r['inputs_sha256'].items():assert sha(Path(path))==h
expected=set(r['unowned_types']);properties={row['type'] for row in r['rows']}
attrs=set(r['dependency_attributes_resolved']);assert not properties&attrs
def render(node):return node if isinstance(node,str) else '('+' '.join(render(x) for x in node)+')'
header='''(class file (read))
(classorder (file))
(sid kernel)
(sidorder (kernel))
(user fixture_u)
(role fixture_r)
(type fixture_domain)
(roletype fixture_r fixture_domain)
(userrole fixture_u fixture_r)
(sensitivity s0)
(sensitivityorder (s0))
(level low (s0))
(userlevel fixture_u low)
(userrange fixture_u (low low))
(sidcontext kernel (fixture_u fixture_r fixture_domain (low low)))
(allow fixture_domain fixture_domain (file (read)))
'''
body=''.join(f'(type {name})\n' for name in sorted(properties))
body+=''.join(f'(typeattribute {name})\n' for name in sorted(attrs))
for name,definitions in r['positive_definitions'].items():
 for expr in definitions:body+=f'(typeattributeset {name} {render(expr)})\n'
body+='''(typeattribute fixture_actual_unowned)
(typeattributeset fixture_actual_unowned (and property_type (not (or system_property_type vendor_property_type))))
(allow fixture_domain fixture_actual_unowned (file (read)))
'''
# Owned targets must never match the compiler's unowned predicate.
owned=properties-expected
case_a=header+body+'(typeattribute fixture_expected_owned)\n'
if owned:case_a+='(typeattributeset fixture_expected_owned ('+' '.join(sorted(owned))+'))\n'
case_a+='(neverallow fixture_domain fixture_expected_owned (file (read)))\n'
# Every predicted unowned concrete type must cause its own strict diagnostic.
case_b=header+body+''.join(f'(neverallow fixture_domain {name} (file (read)))\n' for name in sorted(expected))
out.mkdir(parents=True);(out/'NOT_AN_INSTALLATION_POLICY.txt').write_text(__doc__+'\n')
results=[]
for name,text,wanted in [('owned-guard',case_a,0),('unowned-witness',case_b,255 if expected else 0)]:
 source=out/(name+'.cil');source.write_text(text)
 command=[str(a.compiler),'-m','-M','false','-c','30','-o',str(out/(name+'.policy')),'-f','/dev/null',str(source)]
 result=subprocess.run(command,capture_output=True,text=True);log=result.stdout+result.stderr
 (out/(name+'.log')).write_text(log)
 assert result.returncode==wanted,(name,result.returncode,log[:1200])
 blocks=log.split('neverallow check failed at ')[1:]
 if name=='unowned-witness':
  actual=set()
  for block in blocks:
   line=next(s.strip() for s in block.splitlines() if s.strip().startswith('(neverallow fixture_domain '))
   actual.add(line.split()[2])
  assert actual==expected and len(blocks)==len(expected),(len(actual),len(expected))
 else:assert not blocks
 results.append({'fixture':name,'exit':result.returncode,'strict_neverallow_checks':True,
                 'diagnostic_blocks':len(blocks),'command':command,'source_sha256':sha(source)})
report={'scope':__doc__,'concrete_properties_tested':len(properties),'expected_unowned':sorted(expected),
        'zero_ownership_membership_differences':True,'results':results,'compiler_sha256':sha(a.compiler),
        'proof_sha256':sha(a.proof),'runner_sha256':sha(Path(__file__)),
        'runtime_or_boot_tested':False,'security_approved':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS: actual Android17 strict compiler validates',len(properties),'property memberships;',len(expected),'unowned')
