#!/usr/bin/env python3
"""Stage device-scoped v1 raw-key fscrypt support for the real Samsung keyring API."""
from pathlib import Path
import difflib,hashlib,json
root=Path(__file__).resolve().parents[1];out=root/'integration/lineage-24.0/experiments/legacy-fscrypt-20261105-01';work=root/'work/fscrypt24'
assert not work.exists();sha=lambda b:hashlib.sha256(b).hexdigest();changes={}
def oldfile(project,path,reference):
 b=reference.read_bytes();changes.setdefault(project,{})[path]={'before':b,'after':b};return b.decode()
def save(project,path,text):changes[project][path]['after']=text.encode()
def newfile(project,path,data):assert path not in changes.setdefault(project,{});changes[project][path]={'before':None,'after':data}
p='system/vold';s=oldfile(p,'KeyUtil.cpp',root/'reference/vold24-20261105/KeyUtil.cpp')
s=s.replace('#include <android-base/logging.h>','#include <android-base/logging.h>\n#ifdef GTA3XLWIFI_LEGACY_FSCRYPT\n#include <keyutils.h>\n#include <vector>\n#endif',1)
marker='// Build a struct fscrypt_key_specifier for use in the key management ioctls.';assert s.count(marker)==1
helpers='''#ifdef GTA3XLWIFI_LEGACY_FSCRYPT
// Samsung's v1 fscrypt uses real logon keys in the inherited init keyring.
// Wrapped keys and v2 policies must never enter this raw v1 compatibility path.
static const char* const kLegacyKeyPrefixes[] = {"ext4", "f2fs", "fscrypt"};

static bool legacyFscryptKeyring(key_serial_t* ring) {
    *ring = keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", "fscrypt", 0);
    if (*ring < 0) {
        PLOG(ERROR) << "Missing inherited fscrypt keyring";
        return false;
    }
    return true;
}

static bool installKeyLegacy(const KeyBuffer& key, const std::string& raw_ref) {
    if (key.size() != FSCRYPT_MAX_KEY_SIZE || raw_ref.size() != FSCRYPT_KEY_DESCRIPTOR_SIZE) {
        LOG(ERROR) << "Invalid legacy v1 key or descriptor size";
        return false;
    }
    key_serial_t ring;
    if (!legacyFscryptKeyring(&ring)) return false;
    KeyBuffer payload(sizeof(fscrypt_key), 0);
    auto* fs_key = reinterpret_cast<fscrypt_key*>(payload.data());
    static_assert(sizeof(fs_key->raw) == FSCRYPT_MAX_KEY_SIZE);
    fs_key->size = key.size();
    memcpy(fs_key->raw, key.data(), key.size());
    std::vector<key_serial_t> inserted;
    auto rollback = [&]() {
        for (auto id : inserted) {
            if (keyctl_unlink(id, ring) < 0) PLOG(ERROR) << "Legacy key insertion rollback failed";
        }
    };
    for (auto prefix : kLegacyKeyPrefixes) {
        const auto name = std::string(prefix) + ":" + keyrefstring(raw_ref);
        const auto existing = keyctl_search(ring, "logon", name.c_str(), 0);
        if (existing >= 0) continue;
        if (errno != ENOKEY) {
            PLOG(ERROR) << "Legacy key lookup failed";
            rollback();
            return false;
        }
        const auto id = add_key("logon", name.c_str(), payload.data(), payload.size(), ring);
        if (id < 0) {
            PLOG(ERROR) << "Legacy key insertion failed";
            rollback();
            return false;
        }
        inserted.push_back(id);
    }
    return true;
}

static bool evictKeyLegacy(const std::string& raw_ref) {
    if (raw_ref.size() != FSCRYPT_KEY_DESCRIPTOR_SIZE) return false;
    key_serial_t ring;
    if (!legacyFscryptKeyring(&ring)) return false;
    bool success = true;
    for (auto prefix : kLegacyKeyPrefixes) {
        const auto name = std::string(prefix) + ":" + keyrefstring(raw_ref);
        const auto id = keyctl_search(ring, "logon", name.c_str(), 0);
        if (id < 0) {
            if (errno != ENOKEY) {
                PLOG(ERROR) << "Legacy eviction lookup failed";
                success = false;
            }
            continue;
        }
        if (keyctl_unlink(id, ring) < 0) {
            PLOG(ERROR) << "Legacy key unlink failed";
            success = false;
        }
    }
    // Old fscrypt caches per-inode keys. As in the v1 platform, user processes
    // must have closed their files; this cannot revoke keys held by open files.
    sync();
    if (!writeStringToFile("2", "/proc/sys/vm/drop_caches")) {
        PLOG(ERROR) << "Failed to reclaim legacy encrypted inode caches";
        success = false;
    }
    return success;
}
#endif

'''
s=s.replace(marker,helpers+marker)
for function,options,call in [('ADD','options','installKeyLegacy(key, policy->key_raw_ref)'),('REMOVE','policy.options','evictKeyLegacy(policy.key_raw_ref)')]:
 marker=f'    if (ioctl(fd, FS_IOC_{function}_ENCRYPTION_KEY, arg) != 0) {{' if function=='ADD' else '    if (ioctl(fd, FS_IOC_REMOVE_ENCRYPTION_KEY, &arg) != 0) {'
 assert s.count(marker)==1
 extra=f'''\n#ifdef GTA3XLWIFI_LEGACY_FSCRYPT
        if (errno == ENOTTY && {options}.version == 1 && {options}.key_type == KeyType::kRaw) {{
            return {call};
        }}
#endif'''
 s=s.replace(marker,marker+extra)
save(p,'KeyUtil.cpp',s)
s=oldfile(p,'Android.bp',root/'reference/vold24-20261105/Android.bp');marker='    name: "vold_default_flags",';assert s.count(marker)==1
s=s.replace(marker,marker+'\n    defaults: ["gta3xlwifi_legacy_fscrypt_defaults"],');save(p,'Android.bp',s)
p='system/core';s=oldfile(p,'init/init.cpp',root/'reference/init24-20261105/init.cpp')
marker='#include "init.h"';assert s.count(marker)==1
s=s.replace(marker,marker+'\n#ifdef GTA3XLWIFI_LEGACY_FSCRYPT\n#include <keyutils.h>\n#endif')
marker='int SecondStageMain(int argc, char** argv) {';assert s.count(marker)==1
helper='''#ifdef GTA3XLWIFI_LEGACY_FSCRYPT
// Must run before property threads or service forks, so every child inherits
// the same real session keyring. Storage key payloads are inserted only by vold.
static bool SetupLegacyFscryptKeyrings() {
    if (keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 1) < 0) {
        PLOG(ERROR) << "Cannot create inherited session keyring";
        return false;
    }
    if (keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", "fscrypt", 0) >= 0) return true;
    if (errno != ENOKEY) {
        PLOG(ERROR) << "Cannot inspect fscrypt keyring";
        return false;
    }
    if (add_key("keyring", "fscrypt", nullptr, 0, KEY_SPEC_SESSION_KEYRING) < 0) {
        PLOG(ERROR) << "Cannot create fscrypt keyring";
        return false;
    }
    return true;
}
#endif

'''
s=s.replace(marker,helper+marker)
marker='    // Indicate that booting is in progress to background fw loaders, etc.';assert s.count(marker)==1
s=s.replace(marker,'''#ifdef GTA3XLWIFI_LEGACY_FSCRYPT
    if (!SetupLegacyFscryptKeyrings()) {
        LOG(FATAL) << "Legacy encrypted storage keyring setup failed";
    }
#endif

'''+marker)
assert s.index('if (!SetupLegacyFscryptKeyrings())')<s.index('    PropertyInit();')
save(p,'init/init.cpp',s)
s=oldfile(p,'init/Android.bp',root/'reference/init24-20261105/Android.bp');marker='    name: "libinit_defaults",\n    recovery_available: true,\n    defaults: [';assert s.count(marker)==1
s=s.replace(marker,marker+'\n        "gta3xlwifi_legacy_fscrypt_defaults",');save(p,'init/Android.bp',s)
ref=root/'reference/keyutils21-20261105'
for name in ['keyutils.cpp','NOTICE','include/keyutils.h']:
 b=(ref/name).read_bytes()
 if name.endswith('.h'):b=b.replace(b'#include <stdint.h>',b'#include <stdint.h>\n#include <stddef.h>')
 newfile(p,'libgta3xlwifi_keyutils/'+name,b)
newfile(p,'libgta3xlwifi_keyutils/Android.bp',b'''package {
    default_applicable_licenses: ["gta3xlwifi_keyutils_license"],
}
license {
    name: "gta3xlwifi_keyutils_license",
    visibility: [":__subpackages__"],
    license_kinds: ["SPDX-license-identifier-BSD"],
    license_text: ["NOTICE"],
}
cc_library_static {
    name: "libgta3xlwifi_keyutils",
    ramdisk_available: true,
    vendor_ramdisk_available: true,
    recovery_available: true,
    export_include_dirs: ["include"],
    srcs: ["keyutils.cpp"],
    cflags: ["-Wall", "-Wextra", "-Werror"],
    stl: "none",
}
cc_defaults {
    name: "gta3xlwifi_legacy_fscrypt_defaults",
    cflags: select(soong_config_variable("gta3xlwifi", "legacy_fscrypt"), {
        true: ["-DGTA3XLWIFI_LEGACY_FSCRYPT"],
        default: [],
    }),
    static_libs: select(soong_config_variable("gta3xlwifi", "legacy_fscrypt"), {
        true: ["libgta3xlwifi_keyutils"],
        default: [],
    }),
}
''')
p='device/samsung/gta3xlwifi';s=oldfile(p,'BoardConfig.mk',root/'device/BoardConfig.mk');s+='\n# Real legacy v1 fscrypt keyring API; never disable userdata encryption.\nSOONG_CONFIG_gta3xlwifi += legacy_fscrypt\nSOONG_CONFIG_gta3xlwifi_legacy_fscrypt := true\n';save(p,'BoardConfig.mk',s)
work.mkdir();projects=[]
revisions={'system/core':'65d661b1a536701e8b118be4e9728d7b5ca727c9','system/vold':'11d8982f824d52e8122c7aa732207ba66b8f23c8','device/samsung/gta3xlwifi':'2f649d06fec3318926c61aaf7a5fa3f40aa9f266'}
for project,files in changes.items():
 pieces=[];rows=[]
 for path,x in files.items():
  dest=work/project/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(x['after'])
  pieces.extend(difflib.unified_diff((x['before'] or b'').decode().splitlines(True),x['after'].decode().splitlines(True),fromfile='a/'+path if x['before'] is not None else '/dev/null',tofile='b/'+path))
  rows.append({'path':path,'before_sha256':sha(x['before']) if x['before'] is not None else None,'candidate_sha256':sha(x['after'])})
 patch=''.join(pieces).encode();name=project.replace('/','_')+'.patch';(out/name).write_bytes(patch)
 projects.append({'path':project,'revision':revisions[project],'patch':name,'patch_sha256':sha(patch),'files':rows})
r={'scope':__doc__,'prerequisites':['port-20261103-07'],'projects':projects,'runner_sha256':sha(Path(__file__).read_bytes()),'source_refs_sha256':{str(p.relative_to(root)):sha(p.read_bytes()) for directory in ['vold21-20261105','vold24-20261105','init24-20261105','keyutils21-20261105'] for p in (root/'reference'/directory).rglob('*') if p.is_file()},'selinux_modified':False,'fstab_encryption_modified':False,'actual_key_material_accessed':False,'hardware_tested':False,'flash_ready':False}
(out/'staging-lock.json').write_text(json.dumps(r,indent=2)+'\n');print('Staged device-only legacy v1 keyring/init proposal across three projects; TOP unchanged')
