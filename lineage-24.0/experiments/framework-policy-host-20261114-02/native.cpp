
#include "Gta3xlwifiPolicyFrame.h"
#include <cassert>
#include <fstream>
#include <cstdio>
using namespace android::net::gta3xlwifi;
static std::ifstream stream;static unsigned cases,frames;
static uint32_t word(){unsigned char b[4];stream.read((char*)b,4);assert(stream.gcount()==4);return (uint32_t(b[0])<<24)|(uint32_t(b[1])<<16)|(uint32_t(b[2])<<8)|b[3];}
#define C(x) do{assert(x);++cases;}while(0)
int main(int argc,char**argv){assert(argc==2);stream.open(argv[1],std::ios::binary);while(stream.peek()!=EOF){auto flags=word();bool loop=word(),saver=word();std::vector<int32_t>counts;std::array<std::vector<int32_t>,10>sections;for(auto&section:sections){auto count=word();C(count<=1000000);counts.push_back(count);for(unsigned i=0;i<count;i++)section.push_back((int32_t)word());}PolicyFrame frame;C(!frame.begin(counts,flags,loop,true,saver));for(unsigned s=0;s<10;s++)for(size_t offset=0;offset<sections[s].size();offset+=4096){auto end=std::min(offset+4096,sections[s].size());C(!frame.append(s,offset,{sections[s].begin()+offset,sections[s].begin()+end}));}SocketPolicyProjection::State state;C(!frame.compile(&state));unsigned queries=word();for(unsigned q=0;q<queries;q++){int32_t uid=word();uint32_t expected=word(),actual=0;C(!state.policy.blockedReasons(uid,&actual)&&actual==expected);expected=word();C(!state.permissions.get(uid,&actual)&&actual==expected);for(int chain=1;chain<=12;chain++){int32_t rule;expected=word();C(!state.policy.getUidRule(chain,uid,&rule)&&rule==(int32_t)expected);}}unsigned prefixes=word();for(unsigned q=0;q<prefixes;q++){LocalNetworkState::Entry query{word(),{},false};for(unsigned n=0;n<6;n++){uint32_t v=word();for(unsigned k=0;k<4;k++)query.key[4*n+k]=v>>(24-8*k);}bool expected=word(),found=false,allowed=false;C(!state.local.lookup(LocalNetworkState::Table::Network,query,&found,&allowed)&&allowed==expected);}++frames;}printf("native_frames=%u native_comparisons=%u\n",frames,cases);}
