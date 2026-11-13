#include "Gta3xlwifiPermissionBootstrap.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
using B=android::net::gta3xlwifi::PermissionBootstrap;
using U=android::net::gta3xlwifi::UidPermissionState;
namespace Oracle {
static bool mIsLoopbackPermissionEnabled;
// LINT.IfChange(uid_permission_chunk_type)
// Each UID costs 7 bits (permissions ACCESS_LOCAL_NETWORK / INTERNET /
// UPDATE_DEVICE_STATS or loopback related perms)
// One int64 can store up to 9 UIDs (7 * 9 = 63 bits per int64)
#define PERMISSION_COUNT 7
#define UIDS_PER_INT64 (64 / PERMISSION_COUNT)
#define CHUNK_INT64_COUNT 128
// One chunk can store 128 * 9 = 1152 UIDs using 128 int64
#define CHUNK_UID_COUNT (CHUNK_INT64_COUNT * UIDS_PER_INT64)
#define UID_PERMISSION_MASK ((1 << PERMISSION_COUNT) - 1)
#define PERMISSION_BIT_NONE 0
#define PERMISSION_BIT_ACCESS_LOCAL_NETWORK (1 << 0)
#define PERMISSION_BIT_UPDATE_DEVICE_STATS (1 << 1)
#define PERMISSION_BIT_NO_INTERNET (1 << 2)
// Required for an app to interact with other applications via IP packets on the
// loopback interface.
#define PERMISSION_BIT_USE_LOOPBACK_INTERFACE (1 << 3)
// Required to be able to interact with other applications via IP packets on the
// loopback interface without requiring permissions from the other app
#define PERMISSION_BIT_FORCE_USE_LOOPBACK_INTERFACE (1 << 4)
// Permissions below are required to interact across users/profiles via IP
// packets on the loopback interface.
#define PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL (1 << 5)
#define PERMISSION_BIT_INTERACT_ACROSS_USERS_OR_PROFILES (1 << 6)

static constexpr int PERMISSION_BPF_MAP_BIT_ACCESS_LOCAL_NETWORK=1 << 0;
static constexpr int PERMISSION_BPF_MAP_BIT_UPDATE_DEVICE_STATS=1 << 1;
static constexpr int PERMISSION_BPF_MAP_BIT_INTERNET=1 << 2;
static constexpr int PERMISSION_BPF_MAP_BIT_USE_LOOPBACK_INTERFACE=1 << 3;
static constexpr int PERMISSION_BPF_MAP_BIT_FORCE_USE_LOOPBACK_INTERFACE=1 << 4;
static constexpr int PERMISSION_BPF_MAP_BIT_INTERACT_ACROSS_USERS_FULL=1 << 5;
static constexpr int PERMISSION_BPF_MAP_BIT_INTERACT_ACROSS_PROFILES=1 << 6;
static constexpr int PERMISSION_BPF_MAP_BIT_INTERACT_ACROSS_USERS=1 << 7;
static constexpr int PERMISSION_BPF_MAP_BIT_MAINLINE_NETWORK_STACK=1 << 8;
static constexpr int PERMISSION_BPF_MAP_BIT_ACCESS_NETWORK_STATE=1 << 9;
    static int convertToChunkPermissionBits(int permissionBits) {
        int chunkPermissions = PERMISSION_BIT_NONE;
        if ((permissionBits & PERMISSION_BPF_MAP_BIT_ACCESS_LOCAL_NETWORK) != 0
                || (permissionBits & PERMISSION_BPF_MAP_BIT_MAINLINE_NETWORK_STACK) != 0) {
            chunkPermissions |= PERMISSION_BIT_ACCESS_LOCAL_NETWORK;
        }
        if ((permissionBits & PERMISSION_BPF_MAP_BIT_UPDATE_DEVICE_STATS) != 0) {
            chunkPermissions |= PERMISSION_BIT_UPDATE_DEVICE_STATS;
        }
        if ((permissionBits & PERMISSION_BPF_MAP_BIT_INTERNET) == 0) {
            chunkPermissions |= PERMISSION_BIT_NO_INTERNET;
        }
        if (!mIsLoopbackPermissionEnabled) {
            return chunkPermissions;
        }

        if ((permissionBits & PERMISSION_BPF_MAP_BIT_USE_LOOPBACK_INTERFACE) != 0) {
            chunkPermissions |= PERMISSION_BIT_USE_LOOPBACK_INTERFACE;
        }
        if ((permissionBits & PERMISSION_BPF_MAP_BIT_FORCE_USE_LOOPBACK_INTERFACE) != 0) {
            chunkPermissions |= PERMISSION_BIT_FORCE_USE_LOOPBACK_INTERFACE;
        }
        if ((permissionBits & PERMISSION_BPF_MAP_BIT_INTERACT_ACROSS_USERS_FULL) != 0) {
            chunkPermissions |= PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL;
        }
        // INTERACT_ACROSS_PROFILES and INTERACT_ACROSS_USERS are passed down to the ebpf map as a
        // single OR bit
        if ((permissionBits & PERMISSION_BPF_MAP_BIT_INTERACT_ACROSS_PROFILES) != 0
                || (permissionBits & PERMISSION_BPF_MAP_BIT_INTERACT_ACROSS_USERS) != 0) {
            chunkPermissions |= PERMISSION_BIT_INTERACT_ACROSS_USERS_OR_PROFILES;
        }
        return chunkPermissions;
    }
}

static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
static std::vector<U::Entry> values(const U&u){std::vector<U::Entry> v;assert(!u.snapshot(&v));return v;}
static B::Snapshot frame(){B::Snapshot f;f.users={0};f.knownUids={10001,10002,10002};f.observed={{0,1023},{1000,1023},{10001,4}};return f;}
static void rejected(const B::Snapshot&f,int error){U output;assert(!output.set(777,1));auto before=values(output);T(B::compile(f,&output)==error&&values(output)==before);}
int main(){
 static_assert(B::PerUserRange==100000&&B::MaxEntries==65536);
 for(bool loop:{false,true})for(unsigned raw=0;raw<1024;raw++){Oracle::mIsLoopbackPermissionEnabled=loop;uint32_t out=777;assert(!B::convert(raw,loop,&out)&&out==(unsigned)Oracle::convertToChunkPermissionBits(raw));++comparisons;}
 uint32_t sentinel=777;T(B::convert(1024,true,&sentinel)==-EINVAL&&sentinel==777);T(B::convert(UINT32_MAX,false,&sentinel)==-EINVAL&&sentinel==777);T(B::convert(4,true,nullptr)==-EINVAL);T(B::compile(frame(),nullptr)==-EINVAL);
 for(bool loop:{false,true}){auto f=frame();f.loopbackPermissionEnabled=loop;U out;T(B::compile(f,&out)==0);uint32_t mask=777;T(!out.get(0,&mask)&&mask==(loop?123u:3u));T(!out.get(1000,&mask)&&mask==(loop?123u:3u));T(!out.get(10001,&mask)&&mask==0);T(!out.get(10002,&mask)&&mask==4);T(values(out).size()==3);f.observed.push_back({10003,0});f.knownUids.push_back(10003);T(!B::compile(f,&out)&&!out.get(10003,&mask)&&mask==4);}
 {auto f=frame();f.users={0,10,21474};f.observed.insert(f.observed.end(),{{1000000,1023},{1001000,1023},{2147400000,1023},{2147401000,1023},{1010001,4},{INT_MAX,4}});f.knownUids.insert(f.knownUids.end(),{1010001,1010002,INT_MAX});U out;uint32_t mask;T(!B::compile(f,&out)&&!out.get(1010001,&mask)&&mask==0);T(!out.get(1010002,&mask)&&mask==4);T(!out.get(INT_MAX,&mask)&&mask==0);}
 for(unsigned which=0;which<13;which++){auto f=frame();int error=-EINVAL;switch(which){case 0:f.users.clear();error=-EPROTO;break;case 1:f.users={1};error=-EPROTO;break;case 2:f.users={0,0};break;case 3:f.users.push_back(-1);break;case 4:f.users.push_back(INT_MAX);break;case 5:f.observed.erase(f.observed.begin());error=-EPROTO;break;case 6:f.observed[1].bits=1022;error=-EPROTO;break;case 7:f.observed.push_back({10001,4});break;case 8:f.observed.push_back({-1,4});break;case 9:f.observed.push_back({10003,1024});break;case 10:f.observed.push_back({110001,4});error=-EPROTO;break;case 11:f.knownUids.push_back(-1);break;case 12:f.knownUids.push_back(110001);error=-EPROTO;break;}rejected(f,error);}
 for(unsigned part=0;part<3;part++){auto f=frame();if(part==0)f.users.resize(65537);else if(part==1)f.knownUids.resize(65537);else f.observed.resize(65537);rejected(f,-E2BIG);}
 {auto f=frame();f.users={0,1};f.observed={{0,1023},{1000,1023},{100000,1023},{101000,1023}};f.knownUids.clear();for(int uid=2000;uid<62000;uid++)f.observed.push_back({uid,1});for(int uid=80000;uid<140000;uid++)f.knownUids.push_back(uid);rejected(f,-E2BIG);}
 {auto f=frame();f.users={0,1};f.observed={{0,1023},{1000,1023},{100000,1023},{101000,1023}};f.knownUids.clear();for(int uid=2000;uid<61000;uid++)f.observed.push_back({uid,4});for(int uid=80000;uid<139000;uid++)f.knownUids.push_back(uid);U out;T(!B::compile(f,&out)&&values(out).size()==59002);}
 printf("passed_cases=%u actual_A17_conversion_comparisons=%u\n",cases,comparisons);return 0;
}
