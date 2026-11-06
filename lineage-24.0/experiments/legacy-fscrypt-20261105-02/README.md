# Device-scoped legacy v1 fscrypt keyring compatibility

Android17 removed filesystem-keyring fallback, the shared init session/child
keyring bootstrap and libkeyutils. The actual Samsung kernel lacks the add,
remove and key-status fscrypt ioctls. API28 and fileencryption=ice still select
v1/private127/CTS/PAD4; preserving parser support alone cannot install keys.

This proposal restores real inherited session-keyring use only under the
product's explicit legacy_fscrypt Soong flag. Init creates the real session and
fscrypt child keyrings before property threads or service forks, failing on
errors. The typed AOSP syscall wrapper source/notice is preserved in the scoped
libgta3xlwifi_keyutils library. Existing SELinux permissions suffice; no assertion
or grant change, fstab/encryption disable, key-generation bypass or fake success.

Vold retains the modern ioctl path and permits fallback only for actual ENOTTY,
v1 and raw keys. V2/wrapped policies and other ioctl errors never downgrade.
Legacy aliases use the existing descriptor hash and 72-byte kernel payload;
existing aliases are preserved and only newly inserted aliases are rolled back
on failure. Eviction unlinks all applicable aliases and performs real sync plus
inode-cache reclamation, reporting errors. Open files cannot be forcibly locked
by this old kernel API; native user-lock/cache/TEE behavior remains unvalidated.
Empty keys are rejected before copying their payload.

The final host probe legacy-fscrypt-host-20261105-07 passes 32 modern-profile and
56 legacy-profile cases, with fatal sanitizer errors and zero stderr. It uses
actual init, typed-wrapper and vold function bodies, Android17's real SHA512 and
KeyBuffer allocator, an independent descriptor digest, and the real Samsung UAPI
payload layout. Syscalls/keyrings/filesystem I/O are synthetic fixtures; no real
keyring or user key material is accessed. Early host05/06 reports are superseded:
their sanitizer recovery allowed an empty-key null-copy warning despite exit0.
Candidate02 adds the rejection; final07 makes sanitizer diagnostics fatal.

Source integration is locked in snapshot port-20261105-03 (1,243 projects,
16 patches; device e998435). A private-index reverse-apply proof recovers every
original parent patch byte-for-byte and verifies the new vold delta against its
clean HEAD. Unchanged frozen patches retain their reviewed whitespace only when
revision and complete patch bytes match; seven real Git fixtures enforce this.
Earlier capture attempts are preserved failures. Actual native module compilation
is legacy-fscrypt-native-20261105-01; inspect its exit/log and after-audit.
Original kernel/vendor inputs, Lineage21, TWRP, firmware, keys and data are intact.
No experimental kernel/network promotion, installation, release signing or flash.
