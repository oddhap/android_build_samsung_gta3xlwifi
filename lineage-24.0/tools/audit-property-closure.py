#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Resolve complete positive property-owner membership paths in linked CIL.

Rejects negative expressions, unknown symbols and dependency cycles rather than
guessing. This audits ownership membership, not AV/MLS decisions or runtime use.
"""
import argparse, hashlib, importlib.util, json, re
from collections import defaultdict
from pathlib import Path

def load(name):
 s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
cil,forms=load('stage-vendor-uwb-namespace'),load('stage-platform-policy-port')

def tree(text):
 stack=[];result=None
 for kind,value,_,_ in cil.tokens(text):
  if kind=='(':
   node=[]
   if stack:stack[-1].append(node)
   stack.append(node)
  elif kind==')':
   result=stack.pop()
  else:
   assert kind=='symbol';stack[-1].append(value)
 assert not stack
 return result

p=argparse.ArgumentParser(description=__doc__)
for n in ['baseline','contexts','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
base=json.loads(a.baseline.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
types,attributes,origins=set(),set(),defaultdict(set)
alias_declarations=set();aliases={}
definitions=defaultdict(list);inputs={}
for item in base['inputs']:
 path=Path(item['path']);assert sha(path)==item['sha256'];inputs[str(path)]=item['sha256']
 text=path.read_text()
 for kind,start,stop in forms.statements(text,cil.tokens):
  if kind not in {'type','typeattribute','typeattributeset','typealias','typealiasactual'}:continue
  form=tree(text[start:stop])
  if kind=='typealias':alias_declarations.add(form[1])
  elif kind=='typealiasactual':
   assert form[1] not in aliases or aliases[form[1]]==form[2]
   aliases[form[1]]=form[2]
  elif kind=='type':types.add(form[1]);origins[form[1]].add(str(path))
  elif kind=='typeattribute':attributes.add(form[1])
  else:definitions[form[1]].append(form[2])
assert not types&attributes
assert alias_declarations==aliases.keys()
cache={};visited=set()
def resolve(name,trail=()):
 if name in aliases:
  assert name not in trail,('Type alias cycle',name,trail)
  return resolve(aliases[name],trail+(name,))
 if name in types:return {name}
 assert name in attributes,('Unknown property dependency',name,trail)
 if name in cache:return cache[name]
 assert name not in trail,('Property dependency cycle',name,trail)
 visited.add(name)
 value=set()
 for expr in definitions[name]:value|=evaluate(expr,trail+(name,))
 cache[name]=value;return value
def evaluate(expr,trail):
 if isinstance(expr,str):return resolve(expr,trail)
 if not expr:return set()
 if expr[0] in ['not','xor','all']:raise ValueError(('Nonpositive expression',expr,trail))
 if expr[0]=='and':
  assert len(expr)>=3
  result=evaluate(expr[1],trail)
  for x in expr[2:]:result &= evaluate(x,trail)
  return result
 parts=expr[1:] if expr[0]=='or' else expr
 result=set()
 for x in parts:result |= evaluate(x,trail)
 return result
properties=resolve('property_type')
owner_names=['system_property_type','vendor_property_type'];macro_aliases={}
attribute_source=Path('/srv/android/src/lineage-24.0-arm64/system/sepolicy/public/attributes')
if 'product_property_type' in attributes:owner_names.append('product_property_type')
else:
 assert re.search(r"define\(`product_property_type',\s*`system_property_type'\)",attribute_source.read_text())
 macro_aliases['product_property_type']='system_property_type'
owners={n:resolve(n) for n in owner_names}
scopes={n:resolve(n) for n in ['vendor_internal_property_type','vendor_restricted_property_type','vendor_public_property_type']}
unowned=properties-set.union(*owners.values())
contexts=defaultdict(list)
for number,line in enumerate(a.contexts.read_text().splitlines(),1):
 fields=line.partition('#')[0].split()
 if fields:
  assert len(fields)>=2 and fields[1].startswith('u:object_r:')
  contexts[fields[1].split(':')[2]].append({'name':fields[0],'line':number})
rows=[]
for name in sorted(properties):
 rows.append({'type':name,'owners':[k for k,v in owners.items() if name in v],
              'vendor_scopes':[k for k,v in scopes.items() if name in v],
              'declaration_inputs':sorted(origins[name]),'vendor_context_names':contexts[name]})
report={'scope':__doc__,'concrete_property_types':len(properties),'owner_counts':{k:len(v&properties) for k,v in owners.items()},
 'unowned_types':sorted(unowned),'rows':rows,'dependency_attributes_resolved':sorted(visited),
 'positive_definitions':{k:definitions[k] for k in sorted(visited)},'type_alias_actuals':aliases,
 'm4_owner_aliases':macro_aliases,
 'inputs_sha256':inputs|{str(attribute_source):sha(attribute_source),str(a.contexts):sha(a.contexts),str(a.baseline):sha(a.baseline),str(Path(__file__)):sha(Path(__file__))},
 'negative_or_unknown_or_cyclic_dependencies_accepted':False,'av_mls_or_runtime_decisions_proved':False,'security_approved':False}
for path,h in inputs.items():assert sha(Path(path))==h
a.output.write_text(json.dumps(report,indent=2)+'\n')
print('Properties:',len(properties),'; unowned:',len(unowned),'; vendor-restricted:',len(scopes['vendor_restricted_property_type']&properties))
