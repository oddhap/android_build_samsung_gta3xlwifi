#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
static_assert(sizeof(gta3xlwifi_uid_permission_transfer)==24);
static_assert(__builtin_offsetof(gta3xlwifi_uid_permission_transfer,revision)==8);
static_assert(__builtin_offsetof(gta3xlwifi_uid_permission_transfer,entries)==16);
static_assert(sizeof(gta3xlwifi_uid_permission_entry)==8);
static_assert(GTA3XLWIFI_UID_FEATURES==0x6754);
static_assert(GTA3XLWIFI_UID_SET_IMAGE==0x40186755);
static_assert(GTA3XLWIFI_UID_GET_IMAGE==0xc0186756);
extern "C" unsigned uid_wire_size(){return sizeof(gta3xlwifi_uid_permission_transfer);}
