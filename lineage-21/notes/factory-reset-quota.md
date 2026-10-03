# Boot loop after TWRP Format Data

On 2026-10-03 a user-initiated TWRP Format Data exposed an Android 14 first-boot
regression. The formatted ext4 filesystem did not have quota enabled. During
initialization, Android 14's `fs_mgr::tune_quota()` enabled user, group **and
project** quotas by default. The stock Samsung 4.4 kernel supports user/group
quotas but excludes `EXT4_FEATURE_RO_COMPAT_PROJECT` (0x2000) from its supported
ext4 feature mask. Subsequent read/write mounts fail with:

```text
EXT4-fs (mmcblk0p33): couldn't mount RDWR because of unsupported optional features (2000)
```

Earlier testing reused already-initialized userdata with user/group quota, so
the `has_quota == want_quota` early return did not expose the new default. TWRP's
recorded format command used normal `mke2fs -t ext4 -b 4096 -I 512`; it did not
request project quota. Its Android 12 fs_mgr already defaults project quota off.

## Permanent fix

The device product sets `ro.gta3xlwifi.ext4_project_quota=false`. A small patch
in Android 14 system/core/fs_mgr uses this immutable property when selecting
the quota initialization command. User/group quota remain enabled. Every other
device retains Android 14's default behavior when the property is absent.

`apply-legacy-quota.py` records the source edit; the final change is included in
the exported system/core patch and verified against its pinned source index.
The actual filesystem/image verifiers check both the new property and the
compiled guard in the filesystem libraries loaded by system init. File encryption and signature checks remain in
place. A TWRP rebuild is not required for this fix.

## Repair existing unsupported userdata

In TWRP, confirm userdata is **unmounted** and identifies the reviewed physical
userdata partition before using tune2fs. Disable only project quota/project
features with `-Q ^prjquota -O ^project`, keeping an undo file outside userdata.
Then run `e2fsck -fn` and verify a read/write mount succeeds. This repairs
metadata without formatting the partition again.

The affected tablet passed all five read-only e2fsck phases and a real read/write
mount after this repair. Its user-triggered format had left only lost+found.
The repair undo file and raw logs are kept locally, outside the published source.

For the first-boot regression test, quota can be disabled on this already-empty
filesystem before booting the fixed ROM, without repeating the data format.
This recreates the recovery-format quota state. The new ROM must then initialize
real user/group quota, keep project quota absent, complete setup, and survive
a subsequent normal reboot. Runtime results are recorded separately; building
successfully alone does not prove the first-boot path works.

## Physical regression result (2026-10-03)

Candidate 8 was privately signed, installed by TWRP (updater RC 0), and read back
from the physical system partition. With quota initially absent on the empty
userdata filesystem, Android completed first boot and the user completed setup.
Root inspection confirmed user/group quota inodes 3/4, ext4 ro_compat 0x56b
(quota enabled, project absent), a read/write /data mount, active file encryption,
SELinux Enforcing, Trust signing level GOOD, and an empty crash buffer.
An ordinary ADB reboot completed with the same checks passing. Installed fs_mgr
library hashes match the verified new image. ADB was returned to unrooted mode.

No additional Format Data was performed during repair or regression testing.
The user's preceding format had already removed the old app data. Old undo files
must not be applied to the filesystem after Android has written new data.

See [first-boot and reboot evidence](quota-firstboot-check.json). The installed
ZIP is `lineage-21.0-20261003-UNOFFICIAL-gta3xlwifi-privatekeys.zip`, SHA-256
`a1046f97465d2ff7b8a7db03c4855ccd69a57eb6b6704f97abeb3598c8c0da20`.
This verifies the formerly failing initialization path and one normal reboot;
long-term stability and the remaining hardware tests are still incomplete.
