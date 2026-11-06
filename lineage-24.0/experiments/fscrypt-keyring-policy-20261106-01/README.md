# Actual compiled-policy access for legacy fscrypt keyrings

Both final strict production/debug policies pass32 concrete key-class queries.
Required init/vold keyring write/search/setattr permissions already exist in the
Android17 platform. Init, zygote, system-server and application key searches are
allowed as required by the shared session/child-keyring path. Application key
read/write remain denied, including two realistic multi-category MLS contexts.
The checks use real libsepol decisions against the actual compiled policy and
confirm no permissive domains. No new key permission or assertion change is made.

This complements source/link and synthetic syscall tests. It does not exercise
kernel keyring inheritance, native encryption, hardware Keymaster, unlocking or
key-blob upgrades. No real keyring, key blob, signing material or user key is read.
See the adjacent production/debug job reports.
