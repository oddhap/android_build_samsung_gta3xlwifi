#include <linux/netfilter/gta3xlwifi_loopback.h>
static_assert(sizeof(gta3xlwifi_loopback_transfer)==32);
static_assert(sizeof(gta3xlwifi_loopback_event)==40);
static_assert(__builtin_offsetof(gta3xlwifi_loopback_transfer,entries)==8);
static_assert(__builtin_offsetof(gta3xlwifi_loopback_transfer,first_sequence)==16);
static_assert(__builtin_offsetof(gta3xlwifi_loopback_transfer,lost_events)==24);
static_assert(__builtin_offsetof(gta3xlwifi_loopback_event,boottime_ns)==16);
static_assert(__builtin_offsetof(gta3xlwifi_loopback_event,sequence)==24);
static_assert(__builtin_offsetof(gta3xlwifi_loopback_event,lost_events)==32);
static_assert(GTA3XLWIFI_LOOPBACK_GET_EVENTS==0xc0206759);
#include <linux/netfilter/gta3xlwifi_local_network.h>
#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
static_assert(sizeof(gta3xlwifi_lna_transfer)==40);
static_assert(sizeof(gta3xlwifi_lna_entry)==32);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,revision)==16);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,network_entries)==24);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,host_entries)==32);
static_assert(GTA3XLWIFI_LNA_SET_IMAGE==0x40286757);
static_assert(GTA3XLWIFI_LNA_GET_IMAGE==0xc0286758);
static_assert(sizeof(gta3xlwifi_uid_permission_transfer)==24);
static_assert(__builtin_offsetof(gta3xlwifi_uid_permission_transfer,revision)==8);
static_assert(__builtin_offsetof(gta3xlwifi_uid_permission_transfer,entries)==16);
static_assert(sizeof(gta3xlwifi_uid_permission_entry)==8);
static_assert(GTA3XLWIFI_UID_FEATURES==0x6754);
static_assert(GTA3XLWIFI_UID_SET_IMAGE==0x40186755);
static_assert(GTA3XLWIFI_UID_GET_IMAGE==0xc0186756);
extern "C" unsigned uid_wire_size(){return sizeof(gta3xlwifi_uid_permission_transfer);}
