#!/usr/bin/env python3
"""Apply the SM-T510 Android 14 automatic FBE decryption fix to a TWRP tree."""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("checkout", type=Path)
args = parser.parse_args()
path = args.checkout / "system/vold/Decrypt.cpp"
text = path.read_text()

def replace(old, new):
    global text
    if new in text:
        return
    if text.count(old) != 1:
        raise SystemExit("Unexpected source at anchor: " + old[:80])
    text = text.replace(old, new, 1)

# Android 14's stretchLskf(NONE, null) uses Arrays.copyOf(default-password, 32).
# memcpy alone leaves the trailing 16 bytes uninitialized.
replace("unsigned char password_token[PASSWORD_TOKEN_SIZE];",
        "unsigned char password_token[PASSWORD_TOKEN_SIZE] = {}; // Android NONE uses zero padding")

# init.svc.keystore2=running only means fork succeeded. The Binder interface is
# registered later, particularly after the no-credential database snapshot.
replace('''			auto keystore = ks2::IKeystoreService::fromBinder(keystoreBinder);
			auto rc = keystore->getKeyEntry''', '''			for (int attempt = 0; !keystoreBinder.get() && attempt < 200; ++attempt) {
				usleep(100000);
				keystoreBinder = ::ndk::SpAIBinder(AServiceManager_checkService(
					"android.system.keystore2.IKeystoreService/default"));
			}
			auto keystore = ks2::IKeystoreService::fromBinder(keystoreBinder);
			if (!keystore) {
				printf("Synthetic password keystore unavailable; data remains locked\\n");
				return disk_decryption_secret_key;
			}
			auto rc = keystore->getKeyEntry''')

replace('''		unsigned char* byteptr = (unsigned char*)spblob_data.data();''', '''		if (spblob_data.size() < 2 + 12 + AES_BLOCK_SIZE) {
			printf("Synthetic password blob is truncated\\n");
			return disk_decryption_secret_key;
		}
		unsigned char* byteptr = (unsigned char*)spblob_data.data();''')
replace('''			ks2::CreateOperationResponse encOperationResponse;
			auto begin_rc''', '''			if (!keyResponse.iSecurityLevel) {
				printf("Synthetic password key has no security level\\n");
				return disk_decryption_secret_key;
			}
			ks2::CreateOperationResponse encOperationResponse;
			auto begin_rc''')
replace('''			std::optional<std::vector<uint8_t>> optPlaintext;''', '''			if (!encOperationResponse.iOperation) {
				printf("Synthetic password operation unavailable\\n");
				return disk_decryption_secret_key;
			}
			std::optional<std::vector<uint8_t>> optPlaintext;''')
replace('''			size_t keystore_result_size = optPlaintext->size();''', '''			if (!optPlaintext || optPlaintext->size() < 12 + AES_BLOCK_SIZE) {
				printf("Synthetic password intermediate blob is truncated\\n");
				return disk_decryption_secret_key;
			}
			size_t keystore_result_size = optPlaintext->size();''')

# The final 16 bytes are the authentication tag, not ciphertext. Refuse any
# result unless GCM authentication succeeds; never derive an FBE key from it.
replace('''			int cipher_size = keystore_result_size - 12;''',
        '''			int cipher_size = keystore_result_size - 12 - AES_BLOCK_SIZE;''')
replace('''				printf("Unable to obtain personalized_application_id\\n");
				return disk_decryption_secret_key;''', '''				printf("Unable to obtain personalized_application_id\\n");
				free(keystore_result);
				return disk_decryption_secret_key;''')
replace('''			EVP_DecryptInit(d_ctx, EVP_aes_256_gcm(), key, intermediate_iv);
			unsigned char* secret_key = (unsigned char*)malloc(cipher_size);
			if (!secret_key) {
				printf("malloc failure on secret key\\n");
				return disk_decryption_secret_key;
			}
			EVP_DecryptUpdate(d_ctx, secret_key, &actual_size, intermediate_cipher_text, cipher_size);
			unsigned char tag[AES_BLOCK_SIZE];
			EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
			EVP_DecryptFinal_ex(d_ctx, secret_key + actual_size, &final_size);
			EVP_CIPHER_CTX_free(d_ctx);
			free(personalized_application_id);
			free(keystore_result);
			int secret_key_real_size = actual_size - 16;''', '''			unsigned char* secret_key = (unsigned char*)malloc(cipher_size + AES_BLOCK_SIZE);
			bool authenticated = d_ctx && secret_key &&
				EVP_DecryptInit_ex(d_ctx, EVP_aes_256_gcm(), nullptr, key, intermediate_iv) == 1 &&
				EVP_DecryptUpdate(d_ctx, secret_key, &actual_size, intermediate_cipher_text, cipher_size) == 1 &&
				EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, AES_BLOCK_SIZE,
					const_cast<unsigned char*>(intermediate_cipher_text + cipher_size)) == 1 &&
				EVP_DecryptFinal_ex(d_ctx, secret_key + actual_size, &final_size) == 1;
			EVP_CIPHER_CTX_free(d_ctx);
			free(personalized_application_id);
			free(keystore_result);
			if (!authenticated) {
				printf("Synthetic password authentication failed; data remains locked\\n");
				free(secret_key);
				return disk_decryption_secret_key;
			}
			int secret_key_real_size = actual_size + final_size;''')

# Avoid changing any shared inode if the checkout was created with link-dest.
temporary = path.with_suffix(".pinfree.tmp")
temporary.write_text(text)
temporary.chmod(path.stat().st_mode & 0o777)
temporary.replace(path)
print("PIN-free FBE patch applied:", path)
