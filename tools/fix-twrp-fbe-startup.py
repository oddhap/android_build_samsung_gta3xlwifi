#!/usr/bin/env python3
"""Let recovery report unavailable FBE services rather than hang its UI."""
from pathlib import Path

root = Path('/srv/android/src/twrp-12.1')
path = root / 'system/vold/Decrypt.cpp'
text = path.read_text()
anchor = 'extern "C" bool Decrypt_DE() {\n'
guard = '''    // SM-T510 recovery: Samsung's keystore service is not yet ported.
    // Do not enter Keymaster's indefinite wait when the service is absent.
    ndk::SpAIBinder service(AServiceManager_checkService(
            "android.system.keystore2.IKeystoreService/default"));
    if (!service.get()) {
        printf("FBE keystore unavailable; encrypted data remains locked\\n");
        return false;
    }
'''
assert text.count(anchor) == 1
if guard not in text and "for (int attempt = 0; !service.get()" not in text:
    path.write_text(text.replace(anchor, anchor + guard))

path = root / 'bootable/recovery/partition.cpp'
text = path.read_text()
old = '''if (!Decrypt_FBE_DE() && strcmp(crypto_state, "error") != 0) {
			if (is_device_fbe == 1)'''
new = '''if (!Decrypt_FBE_DE() && (Is_FBE || strcmp(crypto_state, "error") != 0)) {
            // Preserve locked FBE state after a failed DE-key initialization.
            Is_Encrypted = true;
            Is_Decrypted = false;
            DataManager::SetValue(TW_IS_ENCRYPTED, 1);
            DataManager::SetValue(TW_IS_DECRYPTED, 0);
            DataManager::SetValue(TW_IS_FBE, Is_FBE ? 1 : is_device_fbe);
			if (is_device_fbe == 1 || Is_FBE)'''
if old in text:
    assert text.count(old) == 1
    path.write_text(text.replace(old, new))
else:
    assert new in text

# Failed DE initialization leaves no parsed users. An empty list must not be
# interpreted as a user who is already decrypted.
path = root / 'bootable/recovery/partitionmanager.cpp'
text = path.read_text()
old = '''\t\tbool user_need_decrypt = false;
'''
new = '''\t\tSet_Crypto_Type("file");
        if (Users_List.empty()) {
            LOGERR("FBE users unavailable; encrypted data remains locked\\n");
            DataManager::SetValue(TW_IS_ENCRYPTED, 1);
            DataManager::SetValue(TW_IS_DECRYPTED, 0);
            return -1;
        }
'''+old
if new not in text:
    assert text.count(old) == 1
    path.write_text(text.replace(old, new, 1))

# Preserve normal successful operations which don't need a key-blob upgrade.
path = root / 'system/vold/KeyStorage.cpp'
text = path.read_text()
old = '    // if (!opHandle.getUpgradedBlob()) return opHandle;'
new = '    if (!opHandle.getUpgradedBlob()) return opHandle;'
if old in text:
    assert text.count(old) == 1
    path.write_text(text.replace(old, new, 1))
else:
    assert new in text

# libvold is linked into recovery, whose default logger suppresses useful
# failure details. Route messages to recovery.log, without logging credentials.
path = root / 'system/vold/Decrypt.cpp'
text = path.read_text()
anchor = 'extern "C" bool Decrypt_DE() {\n'
logger = '''    android::base::SetLogger(android::base::StderrLogger);
    android::base::SetMinimumLogSeverity(android::base::ERROR);
'''
if logger not in text:
    path.write_text(text.replace(anchor, anchor + logger, 1))

# Give hardware HALs a bounded window to register before loading DE keys.
path = root / 'system/vold/Decrypt.cpp'
text = path.read_text()
old = guard
new = guard.replace("Samsung's keystore service is not yet ported.",
                    "Hardware HALs must be ready before loading keys.")
new = new.replace('    if (!service.get()) {', '''    for (int attempt = 0; !service.get() && attempt < 200; ++attempt) {
        usleep(100000);
        service = ndk::SpAIBinder(AServiceManager_checkService(
                "android.system.keystore2.IKeystoreService/default"));
    }
    if (!service.get()) {''')
if old in text:
    path.write_text(text.replace(old, new, 1))
else:
    assert new in text

# Snapshot the Android database only after DE unlock, with recovery keystore
# stopped, into tmpfs. Android files are never opened writable.
path = root / 'system/vold/Decrypt.cpp'
text = path.read_text()
if '#include <android-base/properties.h>' not in text:
    text = text.replace('#include <android-base/file.h>', '#include <android-base/file.h>\n#include <android-base/properties.h>')
new = r'''	void copySqliteDb() {
        // The source database belongs to Android and is never opened writable.
        // Stop recovery's keystore before replacing its temporary database.
        static bool copied = false;
        if (copied) return;
        const std::string src = "/data/misc/keystore/persistent.sqlite";
        const std::string dst = "/tmp/misc/keystore/persistent.sqlite";
        std::string database, wal;
        if (!android::base::ReadFileToString(src, &database)) {
            printf("Android keystore database is not readable yet\n");
            return;
        }
        bool has_wal = access((src + "-wal").c_str(), F_OK) == 0;
        if (has_wal && !android::base::ReadFileToString(src + "-wal", &wal)) {
            printf("Unable to read Android keystore WAL\n");
            return;
        }
        auto stage = [&](const std::string& content, const std::string& path) {
            return android::base::WriteStringToFile(content, path, 0600, 1017, 1017);
        };
        if (!stage(database, dst + ".new") || (has_wal && !stage(wal, dst + "-wal.new"))) {
            printf("Unable to stage temporary recovery keystore database\n");
            return;
        }
        if (!android::base::SetProperty("ctl.stop", "keystore2") ||
            !android::base::WaitForProperty("init.svc.keystore2", "stopped", std::chrono::seconds(5))) {
            printf("Recovery keystore did not stop; database left unchanged\n");
            return;
        }
        // These paths are in tmpfs, never the installed ROM's database.
        unlink((dst + "-wal").c_str());
        unlink((dst + "-shm").c_str());
        bool replaced = rename((dst + ".new").c_str(), dst.c_str()) == 0;
        if (replaced && has_wal) replaced = rename((dst + "-wal.new").c_str(), (dst + "-wal").c_str()) == 0;
        bool started = android::base::SetProperty("ctl.start", "keystore2") &&
            android::base::WaitForProperty("init.svc.keystore2", "running", std::chrono::seconds(5));
        if (!replaced || !started) {
            printf("Recovery keystore database initialization failed\n");
            return;
        }
        copied = true;
        printf("Android keystore snapshot loaded into recovery tmpfs\n");
    }'''
if new not in text:
    start = text.index('\tvoid copySqliteDb() {')
    end = text.index('\n\t/* C++ replacement', start)
    text = text[:start] + new + '\n' + text[end:]
text = text.replace('android::base::SetMinimumLogSeverity(android::base::INFO);', 'android::base::SetMinimumLogSeverity(android::base::ERROR);')
path.write_text(text)

# Recovery must read existing keys, never generate replacement keys or rewrite
# Android's encryption-mode/reference files during a decryption attempt.
path = root / 'system/vold/FsCrypt.cpp'
text = path.read_text()
start = text.index('bool fscrypt_initialize_systemwide_keys() {')
end = text.index('\nbool fscrypt_init_user0()', start)
part = text[start:end]
old = "retrieveOrGenerateKey(device_key_path, device_key_temp, kEmptyAuthentication,\n                               makeGen(options), &device_key)"
new = "retrieveKey(device_key_path, kEmptyAuthentication, &device_key)"
if old in part:
    part = part.replace(old, new, 1)
else:
    assert new in part
old_start = part.find('    std::string options_string;')
if old_start != -1:
    old_end = part.index('    return true;', old_start)
    part = part[:old_start] + "    // Keep references in recovery memory; Android's files are untouched.\n    de_key_raw_ref = device_policy.key_raw_ref;\n\n" + part[old_end:]
text = text[:start] + part + text[end:]
old = "if (!create_and_install_user_keys(0, false)) return false;"
new = 'LOG(ERROR) << "User 0 DE key missing; refusing to create replacement keys";\n            return false;'
if old in text:
    text = text.replace(old, new, 1)
else:
    assert new in text
path.write_text(text)

# Collapse an earlier diagnostic logger insertion; keep source idempotent.
path = root / 'system/vold/Decrypt.cpp'
text = path.read_text().replace(logger + logger, logger)
path.write_text(text)

# The installed fstab specifies the actual format. Do not guess an alternate
# hardware-wrapped format following an unrelated legacy keyring failure.
path = root / 'system/vold/FsCrypt.cpp'
text = path.read_text()
start = text.index('bool fscrypt_initialize_systemwide_keys() {')
end = text.index('\nbool fscrypt_init_user0()', start)
part = text[start:end]
part = part.replace('install:\n', '')
branch_start = part.find('        if (retry) {')
if branch_start != -1:
    branch_end = part.index('        return false;', branch_start)
    part = part[:branch_start] + part[branch_end:]
text = text[:start] + part + text[end:]
path.write_text(text)

# Loading an existing CE key must not discard old bindings or rename key dirs.
path = root / 'system/vold/FsCrypt.cpp'
text = path.read_text()
start = text.index('static bool read_and_fixate_user_ce_key(')
end = text.index('\nstatic bool ', start + 10)
part = text[start:end]
part = part.replace('            fixate_user_ce_key(directory_path, ce_key_path, paths);',
                    '            // Recovery reads existing bindings without changing Android keys.')
text = text[:start] + part + text[end:]
path.write_text(text)

# Check the HAL response, token length and authorization result, not merely
# Binder transport success. Failed PIN/TEE verification must stop immediately.
path = root / 'system/vold/Decrypt.cpp'
text = path.read_text()
new = r'''            bool verified = false;
            android::hardware::Return<void> hwRet =
                gk_device->verify(fakeUid(user_id), 0 /* challenge */,
                                 pwd_handle_hidl, gk_pwd_token_hidl,
                    [&verified](const android::hardware::gatekeeper::V1_0::GatekeeperResponse& rsp) {
                        if (rsp.code < android::hardware::gatekeeper::V1_0::GatekeeperStatusCode::STATUS_OK) {
                            printf("Gatekeeper rejected verification, status=%d timeout=%u\n",
                                   static_cast<int>(rsp.code), rsp.timeout);
                            return;
                        }
                        if (rsp.data.size() != sizeof(hw_auth_token_t)) {
                            printf("Gatekeeper returned an invalid auth token size\n");
                            return;
                        }
                        const auto* token = reinterpret_cast<const hw_auth_token_t*>(rsp.data.data());
                        HardwareAuthToken auth;
                        auth.timestamp.milliSeconds = betoh64(token->timestamp);
                        auth.challenge = token->challenge;
                        auth.userId = token->user_id;
                        auth.authenticatorId = token->authenticator_id;
                        auth.authenticatorType = static_cast<HardwareAuthenticatorType>(betoh32(token->authenticator_type));
                        auth.mac.assign(token->hmac, token->hmac + sizeof(token->hmac));
                        ndk::SpAIBinder binder(AServiceManager_checkService("android.security.authorization"));
                        auto service = aidl::android::security::authorization::IKeystoreAuthorization::fromBinder(binder);
                        if (!service) {
                            printf("Keystore authorization service unavailable\n");
                            return;
                        }
                        auto status = service->addAuthToken(auth);
                        if (!status.isOk()) {
                            printf("Keystore rejected auth token, error=%d\n", status.getServiceSpecificError());
                            return;
                        }
                        verified = true;
                    });'''
if new not in text:
    start = text.index('\t\t\tandroid::hardware::Return<void> hwRet =', text.index('bool Decrypt_User_Synth_Pass('))
    end = text.index('\n\t\t\tfree(gk_pwd_token);', start)
    text = text[:start] + new + text[end:]
    tail = text.index('\n\t\t\tfree(gk_pwd_token);', start)
    marker = 'if (!hwRet.isOk()) {'
    position = text.index(marker, tail)
    text = text[:position] + text[position:].replace(marker, 'if (!hwRet.isOk() || !verified) {', 1)
path.write_text(text)
