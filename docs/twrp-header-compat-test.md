# SM-T510 recovery header compatibility test — 2026-10-05

The installed ROM is LineageOS 21 / Android 14, with OS security patch input
2026-09-01 and existing PIN-protected FBE data. No new ROM, format or new
encryption keys were used for this test.

## Method

Start with the verified installed TWRP 3.7.1_12 image, SHA-256
`391c36b92f65f39a87d476452195129a33e8f59a25566c367fa73a04cbcc7de7`.
Keep its kernel and DTBO unchanged. A temporary diagnostic ramdisk:

- Allows the specific August/September header comparison while keeping the
  live recovery properties at the installed ROM's 14 / 2026-09-01 inputs.
- Sets `TWRP_HEADER_TEST_READ_ONLY_KEYS=1` for recovery Keystore2.
- Includes a diagnostic KeyMint compatibility library rejecting generate,
  import, wrapped import, upgrade, delete and delete-all key requests before
  they reach the hardware HAL. Normal existing-key operations are retained.

Two images share this exact ramdisk, kernel and DTBO. The only byte difference
is offset 44 of the boot header: patch month August versus September.
Repacking the original unmodified components reproduces the baseline image
byte for byte. Build completed successfully; library dependency names are
unchanged; ramdisk and complete images fit the original bootloader/partition
limits. Transfer and exact-length partition readback hashes matched.

| Image | Header patch | SHA-256 |
| --- | --- | --- |
| Older header test | 2026-08-01 | `784d469467c43b0461452b2523ddce8890591cec8a7ef6e84d9229c9d776cd75` |
| Matched control | 2026-09-01 | `3bae37dbaecb3a88b9ec9ad45a29b42b1da90ff58218041967e533fc53cdb929` |

## Results

With the August header, recovery, MobiCore, Keymaster, Gatekeeper and Keystore2
start. The live properties remain at the ROM's September level, and the test
guard is present in the running Keystore2 environment and mapped library.
Nevertheless, the existing systemwide DE key fails with Keymaster error -33
(`INVALID_KEY_BLOB`), leaving storage locked before user PIN verification.

With the matched September header, the otherwise identical image loads DE
keys and presents the PIN dialog. This isolates the header month as the cause
of the different DE result for this device/firmware/key combination.

The user tested one incorrect PIN followed by the correct PIN with the matched
control. Gatekeeper rejected the incorrect PIN, the correct PIN unlocked user-0
CE storage, and reading the CE accounts DB yielded its expected SQLite header.
All 15 inventoried original key files remained byte-for-byte unchanged. The
Android boot partition hash also remained unchanged.

The normal published TWRP image was restored, with matching transfer and exact
partition readback hashes. Diagnostic source guards were removed from the build
checkout; rebuilding its normal compatibility library reproduced the original
packed library byte for byte. LineageOS subsequently completed boot with FBE and SELinux enforcing, readable
CE storage, all 210 package records and an empty crash buffer. The original key
inventory was still unchanged, and the user confirmed normal apps/data operation.

## Scope and implication

This is evidence that simply removing the startup mismatch guard and copying
ROM properties does not make this recovery independent of the header patch
month on the tested SM-T510 / CWA1. A full recovery rebuild is not necessary to
change this metadata: it can be synchronized by a future ROM installer while
keeping TWRP code, kernel and ramdisk unchanged. That installer integration is
not implemented or tested by this diagnostic.

Other header values, Android major versions, bootloaders and credential types
are not covered. The test does not alter Android's actual security patch level.
Private keys, databases, provisioning data and raw device logs stay local.
