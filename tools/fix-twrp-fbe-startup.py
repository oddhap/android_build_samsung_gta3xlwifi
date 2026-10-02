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
if guard not in text:
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
