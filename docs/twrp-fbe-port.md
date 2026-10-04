# SM-T510 TWRP FBE port — tested PIN decryption

The installed LineageOS 21 userdata uses Android 14 file-based encryption
(`ice:aes-256-cts:v1`). This port works against the existing encrypted data;
no format or encryption disablement is part of the implementation.

## Proven findings

- Hardware Keymaster accepts the existing device-encryption blob in Android.
  A diagnostic `getKeyCharacteristics` call returns 0, with the same key bytes
  used in recovery. Credentials and key material are not printed by the probe.
- Recovery initially panicked because Samsung's secure-RPMB worker treated an
  `ERR_PTR` from `blkdev_get_by_path` as a block-device pointer. The kernel fix
  checks and propagates the error, rather than pretending access succeeded.
- The recovery worker also needs `sys_rawio`, search permission for the block
  directory, and access to the dedicated `mmcblk0rpmb` node. Policy permissions
  are recovery-only; the node uses a dedicated type to avoid granting access
  to arbitrary block-device contents. Global SELinux remains enforcing.
- Vendor Keymaster, Gatekeeper and MobiCore now start with the mounted vendor
  partition and framework HIDL manifest. Keystore2 starts after their inputs
  and OS properties are prepared, as the keystore user.
- Recovery boot-header OS/SPL must match the installed ROM's Keymaster inputs.
  This image uses 14.0.0 / 2026-09-01 compatibility metadata. Its userspace is
  still built from TWRP's Android 12.1 tree; this is not a security-patch claim.
- Failed DE initialization preserves the locked state, including when the
  user list is empty. Successful operations no longer dereference a missing
  optional upgraded key blob.
- The Android keystore DB must be snapshotted into tmpfs while recovery's
  keystore is stopped. Copy the source WAL if present; never overwrite a DB
  while its service is running, and never open the original DB writable.
- Recovery key initialization reads existing keys and does not create missing
  replacement keys or rewrite Android encryption mode/reference files.

## Runtime status

Candidate5 loads DE keys and presents a PIN dialog after adding legacy
`install_keyring` initialization. The first PIN attempts failed because the
Samsung Gatekeeper HAL opens its EFS context files writable and updates
verification state. After mounting EFS writable, the user entered the existing
PIN successfully. TWRP reported encrypted=0/decrypted=1, media directories were
accessible, and the CE accounts database returned its expected SQLite header.
Global SELinux remained enforcing. This is actual decryption evidence, not
merely a success label.

The final image includes EFS read/write mounting (system/vendor stay read-only)
and validates the Gatekeeper response status, token size and authorization
result. Provisioning files are not erased or replaced. The final image passed a full recovery reboot: CE storage was initially
unreadable, a deliberately wrong PIN was rejected by Gatekeeper (status -1),
and the correct PIN unlocked real CE storage. The original DE Keymaster blob
remained byte-for-byte identical. Saved preferences and `3.7.1_12` were retained.
LineageOS subsequently completed boot with file-based encryption still enabled,
readable CE storage, all 210 package records and an empty crash buffer. The user
confirmed that the existing apps and data work as expected.

The earlier cache-preferences and plain-version fixes remain enabled. Their
recovery-reboot tests succeeded; the version shown is `3.7.1_12`.

Raw device logs, databases, key blobs and provisioning data are private test
artifacts and must not be uploaded with the source.


## Installed image and validation scope

Image SHA-256: `391c36b92f65f39a87d476452195129a33e8f59a25566c367fa73a04cbcc7de7`.
Image size: 38,979,600 bytes, inside the 47,185,920-byte RECOVERY partition.
Transfer and exact-length partition readback hashes matched. The running
recovery ELF matched the packed ELF. Kernel input SHA-256:
`f170d1015157c6d82cc3880427245254640fcbf20ffc59538151bcf8d0273333`.

This establishes PIN-based user-0 FBE decryption on this SM-T510 / CWA1 with the
installed LineageOS 21 / Android 14 build and its 2026-09-01 Keymaster inputs.
Other credentials, users, firmware and security-patch inputs are untested;
this remains an unofficial development recovery, not a general stability claim.
