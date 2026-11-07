
#include "Gta3xlwifiUidPermissionState.h"
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
using P=android::net::gta3xlwifi::UidPermissionState;
namespace Oracle{
#define function static
#define AID_USER_OFFSET 100000U
#define AID_APP_START 10000U
static std::map<uint32_t,uint32_t> values;
static uint8_t get_chunk_permissions(uint32_t uid){auto i=values.find(uid);return i==values.end()?0:i->second;}
static constexpr int BPF_ALLOW=1,BPF_DISALLOW=0;
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

static inline bool is_system_uid(uint32_t uid) {
    // MIN_SYSTEM_UID is AID_ROOT == 0, so uint32_t is *always* >= 0
    // MAX_SYSTEM_UID is AID_NOBODY == 9999, while AID_APP_START == 10000
    return ((uid % AID_USER_OFFSET) < AID_APP_START);
}
function bool can_force_loopback(const uint32_t permissions) {
    return (permissions & PERMISSION_BIT_FORCE_USE_LOOPBACK_INTERFACE)
        && (permissions & PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL);
}
function bool uids_have_loopback_permissions(const uint32_t sender_uid,
                                             const uint32_t receiver_uid) {
    // TODO: be more specific about which system uids we should exempt
    if (is_system_uid(sender_uid) || is_system_uid(receiver_uid)) return true;

    bool same_profile =
        sender_uid / AID_USER_OFFSET == receiver_uid / AID_USER_OFFSET;
    if (same_profile) return true;

    uint32_t sender_perms = get_chunk_permissions(sender_uid);
    uint32_t receiver_perms = get_chunk_permissions(receiver_uid);
    if (can_force_loopback(sender_perms)
        || can_force_loopback(receiver_perms)) return true;

    // TODO: check loopback interface permissions for both sender and receiver
    bool same_app_id =
        sender_uid % AID_USER_OFFSET == receiver_uid % AID_USER_OFFSET;
    if (same_app_id) {
        return
            (sender_perms & PERMISSION_BIT_INTERACT_ACROSS_USERS_OR_PROFILES) ||
            (sender_perms & PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL);
    } else {
        return sender_perms & PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL;
    }
}
static int migrated_create(uint32_t uid){return (get_chunk_permissions(uid) & PERMISSION_BIT_NO_INTERNET)
                   ? BPF_DISALLOW
                   : BPF_ALLOW;}
}

static_assert(P::KnownMask==UID_PERMISSION_MASK&&PERMISSION_COUNT==7);
static_assert(P::AccessLocalNetwork==PERMISSION_BIT_ACCESS_LOCAL_NETWORK);
static_assert(P::UpdateDeviceStats==PERMISSION_BIT_UPDATE_DEVICE_STATS);
static_assert(P::NoInternet==PERMISSION_BIT_NO_INTERNET);
static_assert(P::UseLoopbackInterface==PERMISSION_BIT_USE_LOOPBACK_INTERFACE);
static_assert(P::ForceUseLoopbackInterface==PERMISSION_BIT_FORCE_USE_LOOPBACK_INTERFACE);
static_assert(P::InteractAcrossUsersFull==PERMISSION_BIT_INTERACT_ACROSS_USERS_FULL);
static_assert(P::InteractAcrossUsersOrProfiles==PERMISSION_BIT_INTERACT_ACROSS_USERS_OR_PROFILES);
unsigned cases=0,loopback=0,noInternet=0;
#define T(x) do{assert(x);++cases;}while(0)
int main(){
 P p;uint32_t mask=777;bool allowed=false;std::vector<P::Entry> entries{{777,1}};std::vector<int32_t> members{777};
 T(p.get(10001,&mask)==0&&mask==0);T(p.noInternetDenied(10001,&allowed)==0&&!allowed);
 T(p.get(-1,&mask)==-EINVAL&&mask==0);T(p.get(0,nullptr)==-EINVAL);
 T(p.set(-1,1)==-EINVAL);T(p.set(10001,128)==-EINVAL);T(p.set(10001,UINT32_MAX)==-EINVAL);T(p.remove(-1)==-EINVAL);
 T(p.set(10001,P::AccessLocalNetwork)==0);T(p.noInternetDenied(10001,&allowed)==0&&!allowed);
 T(p.set(10001,P::NoInternet)==0);T(p.noInternetDenied(10001,&allowed)==0&&allowed);
 T(p.noInternetDenied(-1,&allowed)==-EINVAL&&allowed);T(p.noInternetDenied(0,nullptr)==-EINVAL);
 T(p.loopbackAllowed(1,110001,nullptr)==-EINVAL);
 T(p.snapshot(nullptr)==-EINVAL);T(p.matchingUids(0,&members)==-EINVAL&&members==std::vector<int32_t>{777});T(p.matchingUids(128,&members)==-EINVAL&&members==std::vector<int32_t>{777});T(p.matchingUids(1,nullptr)==-EINVAL);
 T(p.replace({{10003,1},{10001,2},{10002,0}})==0);T(p.snapshot(&entries)==0&&(entries==std::vector<P::Entry>{{10001,2},{10003,1}}));auto before=entries;
 T(p.replace({{10001,1},{10001,2}})==-EINVAL);T(p.snapshot(&entries)==0&&entries==before);
 T(p.replace({{10001,1},{-1,2}})==-EINVAL);T(p.snapshot(&entries)==0&&entries==before);
 T(p.replace({{10001,1},{10002,128}})==-EINVAL);T(p.snapshot(&entries)==0&&entries==before);
 T(p.set(INT_MAX,P::KnownMask)==0);T(p.matchingUids(P::InteractAcrossUsersFull|P::ForceUseLoopbackInterface,&members)==0&&members==std::vector<int32_t>{INT_MAX});
 T(p.remove(10001)==0);T(p.get(10001,&mask)==0&&mask==0);T(p.set(INT_MAX,0)==0);T(p.snapshot(&entries)==0&&(entries==std::vector<P::Entry>{{10003,1}}));
 const uint32_t uids[]={0,1000,10001,110001,110002,100001,65534,INT_MAX};
 for(uint32_t sender:uids)for(uint32_t receiver:uids){
  P value;
  for(uint32_t sm=0;sm<=P::KnownMask;sm++)for(uint32_t rm=0;rm<=P::KnownMask;rm++){
   assert(value.set(sender,sm)==0&&value.set(receiver,rm)==0);Oracle::values.clear();Oracle::values[sender]=sm;Oracle::values[receiver]=rm;
   assert(value.loopbackAllowed(sender,receiver,&allowed)==0&&allowed==Oracle::uids_have_loopback_permissions(sender,receiver));++loopback;
   bool denied=true;assert(value.noInternetDenied(sender,&denied)==0&&denied==(Oracle::migrated_create(sender)==Oracle::BPF_DISALLOW));++noInternet;
  }
 }
 P edge;Oracle::values.clear();
 for(uint32_t sender:{0u,10001u,UINT32_MAX})for(uint32_t receiver:{0u,10001u,UINT32_MAX}){T(edge.loopbackAllowed(sender,receiver,&allowed)==0&&allowed==Oracle::uids_have_loopback_permissions(sender,receiver));}
 T(edge.set(10001,P::InteractAcrossUsersFull)==0);T(edge.loopbackAllowed(10001,UINT32_MAX,&allowed)==0&&allowed);
 // This is the pure UID predicate: real sender65534 is NOT normalized here.
 // Packet bpf_traffic_account performs that separate normalization to0 first.
 T(edge.loopbackAllowed(65534,110001,&allowed)==0&&!allowed);T(edge.loopbackAllowed(0,110001,&allowed)==0&&allowed);
 printf("passed_cases=%u loopback=%u no_internet=%u\n",cases,loopback,noInternet);
}
