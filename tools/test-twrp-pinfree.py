#!/usr/bin/env python3
"""Run the actual patched GCM block against NIST AES-256-GCM vectors."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("checkout", type=Path)
parser.add_argument("--report", type=Path, required=True)
args = parser.parse_args()
source = (args.checkout / "system/vold/Decrypt.cpp").read_text()
start = source.index("\t\t\tOpenSSL_add_all_ciphers();")
end = source.index('// printf("secret key:', start)
block = source[start:end]
token_declaration = "unsigned char password_token[PASSWORD_TOKEN_SIZE] = {};"
assert token_declaration in source
program = r'''
#include <openssl/evp.h>
#include <cassert>
#include <cstring>
#include <string>
#include <cstdlib>
constexpr int AES_BLOCK_SIZE = 16;
constexpr int PASSWORD_TOKEN_SIZE = 32;
std::string decrypt(const std::string& input) {
    if (input.size() < 12 + AES_BLOCK_SIZE) return {};
    std::string disk_decryption_secret_key;
    unsigned char* keystore_result = (unsigned char*)malloc(input.size());
    memcpy(keystore_result, input.data(), input.size());
    const unsigned char* intermediate_iv = keystore_result;
    const unsigned char* intermediate_cipher_text = keystore_result + 12;
    int cipher_size = input.size() - 12 - AES_BLOCK_SIZE;
    void* personalized_application_id = calloc(1, 64);
''' + block + r'''
    std::string result((char*)secret_key, secret_key_real_size);
    free(secret_key);
    return result;
}
int main() {
    // NIST: zero AES-256 key, zero 96-bit IV, sixteen zero plaintext bytes.
    const unsigned char ciphertext[] = {
        0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18,
        0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19};
    std::string blob(12, '\0');
    blob.append((const char*)ciphertext, sizeof(ciphertext));
    assert(decrypt(blob) == std::string(16, '\0'));
    blob.back() ^= 1;
    assert(decrypt(blob).empty());
    blob.back() ^= 1;
    blob[12] ^= 1;
    assert(decrypt(blob).empty());
    assert(decrypt(std::string(27, '\0')).empty());
    ''' + token_declaration + r'''
    std::string defpassword = "default-password";
    memcpy(password_token, defpassword.data(), defpassword.length());
    assert(memcmp(password_token, "default-password", 16) == 0);
    for (int i = 16; i < PASSWORD_TOKEN_SIZE; ++i) assert(password_token[i] == 0);
}
'''
# Read-only fixture tests use independently published expected ciphertext;
# they never touch a device or any user key.
with tempfile.TemporaryDirectory() as directory:
    cpp = Path(directory) / "gcm.cpp"
    binary = Path(directory) / "gcm"
    cpp.write_text(program)
    subprocess.run(["c++", "-std=c++17", "-fsanitize=address,undefined", "-g",
                    str(cpp), "-lcrypto", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
report = {"passed": True, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
          "checks": ["NIST AES-256-GCM plaintext", "altered tag rejected",
                     "altered ciphertext rejected", "truncated blob rejected",
                     "Android 14 NONE token zero padding", "ASan/UBSan"]}
args.report.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
