# LineageOS 21: /data emptied by e2fsck after an unclean shutdown (issue #6, 2026-11-28)

Report: https://github.com/oddhap/android_build_samsung_gta3xlwifi/issues/6
(LineageOS 21, SM-T510, MindTheGapps, Magisk 31.1: `init_user0_failed`,
thousands of files in `/data/lost+found`, user 0 FBE keys gone).

## Root cause

Not Magisk, not the kernel, not the eMMC. It is a mismatch between the boot-time
`e2fsck` and the Samsung kernel's FBE context format.

1. The Samsung 4.4 kernel is built with `CONFIG_EXT4_PRIVATE_ENCRYPTION` (Exynos FMP
   inline crypto, `fileencryption=ice`). `ext4_inherit_context()` sets
   `EXT4_POLICY_FLAGS_PRIVATE_ALGO` (0x04) in the encryption context of every
   non-directory inode it creates, never in directories. The kernel itself only
   compares the padding bits (`EXT4_POLICY_FLAGS_PAD_MASK`).
   On the tablet (debugfs, `/data/misc/vold/user_keys/de/0`):
   directory `c = 01 7f 04 00 …`, its file `version` `c = 01 7f 04 04 …` (32 bytes,
   Knox SDP field included).
2. Android 14's e2fsprogs 1.46.6 checks that every file in an encrypted directory
   has the same policy as the directory, comparing the full flags byte. Every
   encrypted regular file and symlink therefore fails with
   `Encrypted entry … references inode N, which has a different encryption policy`.
   With `-y` the entry is cleared; pass 4 then moves the inode to `lost+found`.
3. fs_mgr normally runs `e2fsck -y` without `-f`, so a cleanly unmounted /data is
   skipped. After an unclean shutdown it forces a full check. In the Magisk
   session the reboot did not unmount /data cleanly, so the next boot ran the
   full check and cleared every encrypted file, including the user 0 DE/CE key
   files → `init_user0_failed`. Any crash, panic or empty battery has the same
   effect on this build; Magisk only made it reproducible.
4. TWRP 3.7.1_12 ships e2fsprogs 1.45.4, which predates the policy check. That is
   why the reporter's `e2fsck -fn` in TWRP was clean.

## Reproduction (2026-11-28, tablet on LOS21 20261128 release-keys + MindTheGapps)

- Boot and recovery backed up first (boot sha256 6b947a30…).
- Magisk 31.1 (`89cefac0…`, official GitHub release) `boot_patch.sh` with the
  reporter's attempt 2 flags (`KEEPVERITY=true KEEPFORCEENCRYPT=true LEGACYSAR=true
  PREINITDEVICE=cache`): applied the defex patch at 0x1815E0 (`do_execveat_common+0x1f4`,
  the intended site) and `skip_initramfs → want_initramfs`. Flashed to `boot` only.
- Magisk boot OK, keys present. Live `e2fsck -fn` already showed 2652 policy
  complaints.
- Magisk app "additional setup" → reboot → TWRP. Boot log of the failed boot
  ([excerpt](old-build-boot-fsck-after-unclean-reboot-excerpt.txt)):
  1868 cleared entries, 2694 unattached inodes moved to lost+found (2694 files in
  `/data/lost+found`), `user_keys/de/0` empty. No other kind of error was repaired.
- Memory-overlap theory ruled out: kernel `0x800a0000–0x81c43000`, initrd at
  `0x89000000` (`/proc/iomem`, `/chosen`).

## Fix

`external/e2fsprogs` ([patch](../../lineage-21/patches/external_e2fsprogs.patch), recorded in
`lineage-21/notes/source-lock.json` on revision d37e9f0; source
`e2fsck/encrypted_files.c` e7d7bb63… → c9df17f3…): for v1 contexts, ignore 0x04 when
contents and filenames modes differ. Upstream 0x04 is
`FSCRYPT_POLICY_FLAG_DIRECT_KEY`, which a v1 policy may only use with equal modes,
so with different modes the bit can only be Samsung's marker. This mirrors the
kernel's own comparison and changes nothing for upstream policies.

Same fresh /data (format + first boot), unmounted in TWRP:

| e2fsck | policy errors | exit |
|---|---|---|
| LOS21 1.46.6 unpatched (`e2fsck_static` 44a8b665…) | 1961 | 4 |
| LOS21 1.46.6 patched (`e2fsck_static` 40027cdd…) | 0 | 0 (clean) |
| TWRP 1.45.4 | 0 | 0 |

Outputs: [unpatched](stock-e2fsck-fn-fresh-data-excerpt.txt) (excerpt),
[patched](patched-e2fsck-fn-fresh-data.txt).

## Build

[`run-e2fsck21.sh`](../../lineage-21/tools/run-e2fsck21.sh) checks that e2fsprogs has
only the reviewed change, that the test-only `debugfs_static`/`e2fsck_static` are not
in the product tree, moves the old build identity to `build-identity-before/`, runs
the normal `build-arm64-candidate.sh`, checks that the packaged `e2fsck` is the patched
one and that the image file set equals the release, then makes a local test-key OTA
(never published).

Result (2026-11-28): `gta3xlwifi.arm64.20261128.104453`, packaged `e2fsck` ad0821dd…,
file set identical to the release, local test-key OTA 9f5eecc2… (never published).

## End-to-end test with the fixed build

Data formatted in TWRP, local test-key OTA + MindTheGapps sideloaded (boot image
unchanged, 6b947a30…), first boot, then the same Magisk 31.1 sequence as above
(patched boot 9adbd4c3…):

- Live `e2fsck -fn` in the Magisk boot: 0 policy complaints (2652 before the fix);
  only the usual live-mount journal/bitmap/quota noise.
- Magisk "additional setup" → reboot. fs_mgr logged `was not cleanly shut down` for
  userdata and ran the full `e2fsck -y`: passes 1–5 with nothing repaired
  ([log](fixed-build-boot-fsck-after-unclean-reboot.txt)). The device booted to Android; `lost+found` empty,
  user 0 DE/CE keys present, Magisk daemon running.
- Original boot restored (6b947a30…), Magisk app and `/data/adb/magisk` removed,
  normal boot confirmed.

The release build is the same build signed with the release keys
([`sign-e2fsck21.sh`](../../lineage-21/tools/sign-e2fsck21.sh)); the signed system
image carries the same `e2fsck` binary (ad0821dd…).
