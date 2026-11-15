#include <linux/netfilter/gta3xlwifi_packet_stats.h>
static_assert(sizeof(gta3xlwifi_uid_cleanup)==64);
static_assert(__builtin_offsetof(gta3xlwifi_uid_cleanup,nonce)==16);
static_assert(__builtin_offsetof(gta3xlwifi_uid_cleanup,generation)==24);
static_assert(__builtin_offsetof(gta3xlwifi_uid_cleanup,active_epoch)==32);
static_assert(__builtin_offsetof(gta3xlwifi_uid_cleanup,reserved)==40);
static_assert(GTA3XLWIFI_UID_CLEANUP==0xc0406763U);
static_assert(GTA3XLWIFI_UID_CAP_UID_CLEANUP_RECEIPT==131072U);
extern "C" unsigned receipt_size(){return sizeof(gta3xlwifi_uid_cleanup);}
