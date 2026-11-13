#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual held accounting bootstrap with source-bound factory/formatter fixtures.

Executes actual lease/bootstrap C++; syscall and table effects are modeled. Both
families/all tables, every firewall fault point, partial recovery and foreign
preservation are checked. No real rules or network readiness are installed.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','transport-host','roots-host','contract','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();T=a.transport_host.resolve();R=a.roots_host.resolve();K=a.contract.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for base in [T,R]:
 r=json.loads((base/'report.json').read_text());assert r['passed'] and sha(base/'test.cpp')==r['inputs_sha256'][str(base/'test.cpp')]
r=json.loads((K/'report.json').read_text());assert r['passed'];program=r['source_program'];canonical=r['canonical_formatter_results'];assert len(canonical)==4
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h');code=(T/'test.cpp').read_text().split('int main(){',1)[0]
code+='\n#include "Gta3xlwifiAccountingRoots.h"\n#include <array>\n#include <map>\n#include <set>\n#include <sstream>\nusing namespace android::net::gta3xlwifi;\nstatic const std::vector<std::string> program={'+','.join(json.dumps(x) for x in program)+'};\n'
code+='static const std::vector<std::pair<std::string,std::string>> formatters={'+','.join('{'+json.dumps(x)+','+json.dumps(y)+'}' for x,y in zip(['-j MARK --or-mark 0x100000','-j MARK --set-mark 0x0/0x100000','-m policy --pol ipsec --dir in','-m policy --pol ipsec --dir out'],canonical))+'};\n'
code+=r'''
static std::string canonicalRule(std::string line){for(const auto&[from,to]:formatters){auto n=line.find(from);if(n!=std::string::npos)line.replace(n,from.size(),to);}return line;}
using Rules=std::map<std::string,std::vector<std::string>>;
struct Table{Rules chains;std::vector<std::string> policies;bool operator==(const Table&)const=default;};
using Tables=std::array<std::array<Table,3>,2>;
static unsigned tableIndex(const std::string&name){if(name=="filter")return 0;if(name=="raw")return 1;assert(name=="mangle");return 2;}
static std::array<Rules,3> expected(){std::array<Rules,3> rows;for(const auto*n:{"bw_INPUT","bw_OUTPUT","bw_costly_shared","bw_data_saver","bw_penalty_box","bw_happy_box"})rows[0][n]={};rows[1]["bw_raw_PREROUTING"]={};rows[2]["bw_mangle_POSTROUTING"]={};unsigned table=0;for(const auto&line:program){if(line.front()=='*'){table=tableIndex(line.substr(1));continue;}if(line.rfind("COMMIT",0)==0)continue;auto n=line.substr(3,line.find(' ',3)-3);rows[table][n].push_back(canonicalRule(line));}return rows;}
struct Model:IptablesRestoreInterface{
 Tables tables;unsigned calls=0,writes=0,fault=0,malform=0;bool after=false,foreignMutation=false;std::string bad;
 Model(){auto rows=expected();for(unsigned f=0;f<2;++f)for(unsigned k=0;k<3;++k){auto&t=tables[f][k];t.chains=rows[k];for(auto&[n,r]:t.chains){(void)n;r.clear();}t.chains["oem_saved"]={"-A oem_saved -m comment --comment retained -j RETURN"};if(k==0){t.chains["bw_global_alert"]={};t.policies={"-P INPUT ACCEPT","-P OUTPUT DROP","-P FORWARD DROP"};}else if(k==1)t.policies={"-P PREROUTING ACCEPT","-P OUTPUT ACCEPT"};else t.policies={"-P PREROUTING ACCEPT","-P INPUT ACCEPT","-P FORWARD ACCEPT","-P OUTPUT ACCEPT","-P POSTROUTING ACCEPT"};}}
 std::string snapshot(const Table&t){std::string s;for(const auto&line:t.policies)s+=line+"\n";for(const auto&[n,r]:t.chains){(void)r;s+="-N "+n+"\n";}for(const auto&[n,r]:t.chains){(void)n;for(const auto&line:r)s+=line+"\n";}return s;}
 int execute(IptablesTarget family,const std::string&command,std::string*output)override{
  assert(held&&files.size()==1);++calls;bool failure=calls==fault;if(failure&&!after)return -1;
  assert(family==V4||family==V6);unsigned f=family==V4?0:1;std::istringstream in(command);std::string line;assert(std::getline(in,line)&&line.front()=='*');unsigned k=tableIndex(line.substr(1));auto&t=tables[f][k];assert(std::getline(in,line));
  if(line=="-S"){assert(output&&std::getline(in,line)&&line=="COMMIT"&&!std::getline(in,line));*output=calls==malform?bad:snapshot(t);}
  else{assert(!output);++writes;do{if(line=="COMMIT")break;assert(std::find(program.begin(),program.end(),line)!=program.end()&&line.rfind("-A ",0)==0);auto n=line.substr(3,line.find(' ',3)-3);assert(t.chains.count(n));t.chains[n].push_back(canonicalRule(line));}while(std::getline(in,line));assert(line=="COMMIT"&&!std::getline(in,line));if(foreignMutation){t.chains["oem_saved"].push_back("-A oem_saved -j RETURN");foreignMutation=false;}}
  return failure?-1:0;
 }
 void assertComplete(const Tables&before){auto rows=expected();for(unsigned f=0;f<2;++f)for(unsigned k=0;k<3;++k){const auto&t=tables[f][k];assert(t.policies==before[f][k].policies);for(const auto&[n,r]:rows[k])assert(t.chains.at(n)==r);for(const auto&[n,r]:before[f][k].chains)if(!rows[k].count(n))assert(t.chains.at(n)==r);}}
};
static void resetAccounting(){resetEvents();features=4095;}
int main(){unsigned points=0;C(AccountingRoots::validProgram(program));auto badProgram=program;badProgram[1]+=" -j ACCEPT";C(!AccountingRoots::validProgram(badProgram));
 resetAccounting();{Model k;NetpolicyLease l;AccountingRoots roots(k,l);C(roots.prepare(badProgram)==-EINVAL&&k.calls==0&&opens==0);C(roots.prepare(program)==-ENOTCONN&&k.calls==0);}
 resetAccounting();{Model k;NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0);auto before=k.tables;C(roots.prepare(program)==0&&held&&files.size()==1&&opens==1&&k.writes==6);k.assertComplete(before);points=k.calls;C(points==18);auto writes=k.writes;C(roots.prepare(program)==0&&k.writes==writes);C(roots.verifyProducers()==0&&k.writes==writes);
  k.tables[0][0].chains["bw_INPUT"].insert(k.tables[0][0].chains["bw_INPUT"].begin(),"-A bw_INPUT -i wlan0 -j bw_costly_shared");k.tables[1][0].chains["bw_happy_box"]={"-A bw_happy_box -g g24_meter_allow"};C(roots.verifyProducers()==0);k.tables[1][2].chains["bw_mangle_POSTROUTING"].pop_back();C(roots.verifyProducers()==-EPROTO&&files.empty()&&held);
 }
 for(unsigned n=0;n<5;++n){resetAccounting();Model k;auto rows=expected();for(unsigned f=0;f<2;++f)for(unsigned t=0;t<3;++t)for(const auto&[name,rules]:rows[t])k.tables[f][t].chains[name]=std::vector<std::string>(rules.begin(),rules.begin()+std::min<size_t>(n,rules.size()));auto before=k.tables;NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0&&roots.prepare(program)==0&&held);k.assertComplete(before);}
 for(unsigned point=1;point<=points;++point)for(bool after:{false,true}){resetAccounting();Model k;k.fault=point;k.after=after;NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0);C(roots.prepare(program)==-EREMOTEIO&&k.calls==point&&files.empty()&&held);}
 for(int cap:{1023,1024,2047,2048,3071}){resetAccounting();features=cap;Model k;NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0);C(roots.prepare(program)==-EOPNOTSUPP&&k.calls==0&&files.empty()&&held);}
 resetAccounting();{Model k;NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0&&l.release()==0&&!held);C(roots.prepare(program)==-EBUSY&&k.calls==0&&files.empty()&&held);}
 for(unsigned f=0;f<2;++f)for(unsigned t=0;t<3;++t){resetAccounting();Model k;auto rows=expected();auto name=rows[t].begin()->first;k.tables[f][t].chains[name]={"-A "+name+" -m bpf --object-pinned /old -j RETURN"};NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0);C(roots.prepare(program)==-EPROTO&&k.writes==0&&files.empty()&&held);}
 resetAccounting();{Model k;NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0);k.tables[1][2].chains.erase("bw_mangle_POSTROUTING");C(roots.prepare(program)==-ENOENT&&k.writes==0&&files.empty()&&held);}
 for(const auto&bad:std::vector<std::string>{"","-P PREROUTING ACCEPT","-P INPUT ACCEPT\n-N bw_INPUT\n-N bw_INPUT\n","-P INPUT ACCEPT\n-A missing -j RETURN\n","-P INPUT ACCEPT\n\t-N bw_INPUT\n","-X foreign\n"}){resetAccounting();Model k;k.malform=1;k.bad=bad;NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0);C(roots.prepare(program)==-EPROTO&&k.writes==0&&files.empty()&&held);}
 resetAccounting();{Model k;k.foreignMutation=true;NetpolicyLease l;AccountingRoots roots(k,l);C(l.start()==0);C(roots.prepare(program)==-EPROTO&&files.empty()&&held);}
 C(files.empty()&&held);printf("passed_cases=%u prepare_fault_points=%u\n",cases,points);
}
'''
(O/'test.cpp').write_text(code);sources=[S/'Gta3xlwifiNetpolicyLease.cpp',S/'Gta3xlwifiAccountingRoots.cpp'];cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+n for n in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=90,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.fullmatch(r'passed_cases=(\d+) prepare_fault_points=(\d+)\n',x.stdout);assert m and int(m[1])>100 and int(m[2])==18
paths=[Path(__file__),T/'report.json',T/'test.cpp',R/'report.json',R/'IptablesRestoreController.h',K/'report.json',O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[p.with_suffix('.h') for p in sources],*[p for p in (S/'linux/netfilter').glob('*.h')]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'prepare_fault_points':int(m[2]),'actual_factory_and_formatter_contract_bound':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'rules_installed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
