
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>
enum IptablesTarget{V4,V6,V4V6};
struct State{bool legacy=false;std::set<std::string> existing;std::string command;IptablesTarget target=V4;int result=0;unsigned calls=0;} g;
namespace android::base{bool GetBoolProperty(const std::string& name,bool fallback){assert(name=="ro.gta3xlwifi.legacy_networking"&&!fallback);return g.legacy;}}
std::string format(const char* fmt,va_list args){va_list copy;va_copy(copy,args);int n=vsnprintf(nullptr,0,fmt,copy);va_end(copy);assert(n>=0);std::vector<char> b(n+1);assert(vsnprintf(b.data(),b.size(),fmt,args)==n);return std::string(b.data(),n);}
std::string StringPrintf(const char* fmt,...){va_list a;va_start(a,fmt);auto s=format(fmt,a);va_end(a);return s;}
void StringAppendF(std::string* out,const char* fmt,...){va_list a;va_start(a,fmt);*out+=format(fmt,a);va_end(a);}
namespace Before{
static const char* CHILD_CHAIN_TEMPLATE="-A %s -j %s\n";
class Controllers{public:
 static int createChildChains(IptablesTarget,const char*,const char*,const std::vector<const char*>&,bool);
 static std::set<std::string> findExistingChildChains(IptablesTarget,const char*,const char*){return g.existing;}
 static int execIptablesRestore(IptablesTarget target,const std::string& command){++g.calls;g.target=target;g.command=command;return g.result;}
};
int Controllers::createChildChains(IptablesTarget target, const char* table,
                                   const char* parentChain,
                                   const std::vector<const char*>& childChains,
                                   bool exclusive) {
    std::string command = StringPrintf("*%s\n", table);

    // We cannot just clear all the chains we create because vendor code modifies filter OUTPUT and
    // mangle POSTROUTING directly. So:
    //
    // - If we're the exclusive owner of this chain, simply clear it entirely.
    // - If not, then list the chain's current contents to ensure that if we restart after a crash,
    //   we leave the existing rules alone in the positions they currently occupy. This is faster
    //   than blindly deleting our rules and recreating them, because deleting a rule that doesn't
    //   exists causes iptables-restore to quit, which takes ~30ms per delete. It's also more
    //   correct, because if we delete rules and re-add them, they'll be in the wrong position with
    //   regards to the vendor rules.
    //
    // TODO: Make all chains exclusive once vendor code uses the oem_* rules.
    std::set<std::string> existingChildChains;
    if (exclusive) {
        // Just running ":chain -" flushes user-defined chains, but not built-in chains like INPUT.
        // Since at this point we don't know if parentChain is a built-in chain, do both.
        StringAppendF(&command, ":%s -\n", parentChain);
        StringAppendF(&command, "-F %s\n", parentChain);
    } else {
        existingChildChains = findExistingChildChains(target, table, parentChain);
    }

    for (const auto& childChain : childChains) {
        // Always clear the child chain.
        StringAppendF(&command, ":%s -\n", childChain);
        // But only add it to the parent chain if it's not already there.
        if (existingChildChains.find(childChain) == existingChildChains.end()) {
            StringAppendF(&command, CHILD_CHAIN_TEMPLATE, parentChain, childChain);
        }
    }
    command += "COMMIT\n";
    return execIptablesRestore(target, command);
}}
namespace After{
static const char* CHILD_CHAIN_TEMPLATE="-A %s -j %s\n";
class Controllers{public:
 static int createChildChains(IptablesTarget,const char*,const char*,const std::vector<const char*>&,bool);
 static std::set<std::string> findExistingChildChains(IptablesTarget,const char*,const char*){return g.existing;}
 static int execIptablesRestore(IptablesTarget target,const std::string& command){++g.calls;g.target=target;g.command=command;return g.result;}
};
int Controllers::createChildChains(IptablesTarget target, const char* table,
                                   const char* parentChain,
                                   const std::vector<const char*>& childChains,
                                   bool exclusive) {
    std::string command = StringPrintf("*%s\n", table);

    // We cannot just clear all the chains we create because vendor code modifies filter OUTPUT and
    // mangle POSTROUTING directly. So:
    //
    // - If we're the exclusive owner of this chain, simply clear it entirely.
    // - If not, then list the chain's current contents to ensure that if we restart after a crash,
    //   we leave the existing rules alone in the positions they currently occupy. This is faster
    //   than blindly deleting our rules and recreating them, because deleting a rule that doesn't
    //   exists causes iptables-restore to quit, which takes ~30ms per delete. It's also more
    //   correct, because if we delete rules and re-add them, they'll be in the wrong position with
    //   regards to the vendor rules.
    //
    // TODO: Make all chains exclusive once vendor code uses the oem_* rules.
    std::set<std::string> existingChildChains;
    if (exclusive) {
        // Just running ":chain -" flushes user-defined chains, but not built-in chains like INPUT.
        // Since at this point we don't know if parentChain is a built-in chain, do both.
        StringAppendF(&command, ":%s -\n", parentChain);
        StringAppendF(&command, "-F %s\n", parentChain);
        // Rebuild a legacy root with the held guard in the SAME transaction.
        // A later insertion would leave an unguarded window on netd restart.
        // The complete owner must hold the private kernel lease before init.
        if (!strcmp(table, "filter") &&
            (!strcmp(parentChain, "INPUT") || !strcmp(parentChain, "FORWARD") ||
             !strcmp(parentChain, "OUTPUT")) &&
            android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
            StringAppendF(&command, "-A %s -m gta3xlwifi_guard -j DROP\n", parentChain);
        }
    } else {
        existingChildChains = findExistingChildChains(target, table, parentChain);
    }

    for (const auto& childChain : childChains) {
        // Always clear the child chain.
        StringAppendF(&command, ":%s -\n", childChain);
        // But only add it to the parent chain if it's not already there.
        if (existingChildChains.find(childChain) == existingChildChains.end()) {
            StringAppendF(&command, CHILD_CHAIN_TEMPLATE, parentChain, childChain);
        }
    }
    command += "COMMIT\n";
    return execIptablesRestore(target, command);
}}

int main(){unsigned cases=0;
 for(bool legacy:{false,true})for(auto table:{"filter","mangle","raw","nat"})for(auto parent:{"INPUT","FORWARD","OUTPUT","POSTROUTING"})for(bool exclusive:{false,true})for(auto target:{V4,V6,V4V6})for(bool existing:{false,true})for(int result:{0,-1,11}){
  if(target==V4V6&&!exclusive)continue; // Actual lookup rejects this unsupported combination.
  g=State{};g.legacy=legacy;g.result=result;if(existing)g.existing={"child_a"};
  std::vector<const char*> children={"child_a","child_b"};
  assert(Before::Controllers::createChildChains(target,table,parent,children,exclusive)==result);auto before=g.command;assert(g.calls==1&&g.target==target);
  g.calls=0;assert(After::Controllers::createChildChains(target,table,parent,children,exclusive)==result);assert(g.calls==1&&g.target==target);
  std::string expected=before;
  if(legacy&&exclusive&&!strcmp(table,"filter")&&(strcmp(parent,"INPUT")==0||strcmp(parent,"FORWARD")==0||strcmp(parent,"OUTPUT")==0)){
   std::string flush="-F "+std::string(parent)+"\n";auto pos=expected.find(flush);assert(pos!=std::string::npos);
   expected.insert(pos+flush.size(),"-A "+std::string(parent)+" -m gta3xlwifi_guard -j DROP\n");
  }
  assert(g.command==expected);++cases;
 }
 printf("passed_cases=%u\n",cases);
}
