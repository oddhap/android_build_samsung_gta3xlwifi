# LineageOS 21: fixes ported from LineageOS 24 and Updater OTA support (2026-11-27)

Unsigned candidate `gta3xlwifi.arm64.20261127.194723` (LineageOS 21 / Android 14,
ARM64 + ARM32 apps, SM-T510). Base: the published LineageOS 21 device source
(9432fe4, Bluetooth audio release 2026-11-24) and integration aa5ee26.
Not signed, not published, not installed.

## Ported fixes

| LOS24 build | Problem in LOS21 | Change |
|---|---|---|
| 50 | `boot.oat` was compiled for CMC (`concurrent-copying=false`, `ro.dalvik.vm.enable_uffd_gc=true`), but the 4.4 kernel has no userfaultfd. ART then runs the CC GC and rejects the precompiled code. | `PRODUCT_ENABLE_UFFD_GC := false` (lineage_gta3xlwifi.mk) |
| 51 | `power/Power.cpp` disabled the touch/launch CPU/GPU boost until reboot after the first control failure. | LOS24 `Power.cpp`, `RetryBackoff.h` and test byte-identical (release requests, log main+system, retry after 1–60 s) |
| 53 | SD card as internal storage failed (issue #4, a LOS21 report): HEH filename mode, no adoptable flag, no `exfat` filesystem. | `ro.crypto.volume.options=aes-256-xts:aes-256-cts:v1`, `persist.sys.adoptable=force_on`, kernel sdfat `exfat` alias |

Not applicable: LOS24 builds 52/54 (Java stats journal, not present in LOS21; it
reads `xt_qtaguid` with interface names) and 48 (Android 14 HWUI still uses ashmem).
Android 14 grants `appdomain` ION read, so the LOS24 `updater_app` ION rule is not needed.

## Updater OTA support

- `lineage.updater.uri=https://raw.githubusercontent.com/oddhap/lineageos21_gta3xlwifi/ota/{device}.json`
  (81 bytes, under the 91-byte limit).
- Updater "Recent changes" overlay points at the GitHub releases.
- `releasetools.py`: before the unchanged vendor-unmounted guard, the OTA runs the
  LOS24 `recovery-vendor-quiesce.sh` (byte-identical, physically tested with the same
  TWRP): it stops TWRP's FBE helper services and unmounts `/vendor`, so an unattended
  Updater install can pass the guard. The guard still decides; nothing else changed
  (native backuptool backup/restore, header preflight/apply).
- `publish-ota-index21.py`: after a normal LOS21 release, verifies the signed ROM zip
  (whole-file signature, LOS21 release certificate `1e593d15…`, metadata), checks that the
  release asset matches (size, GitHub digest), and writes the LOS21 Updater format
  `{"response": [{datetime, filename, id, romtype, size, url, version}]}` to
  `gta3xlwifi.json` on the `ota` branch (the branch does not exist yet).
  Dry run unless `--publish`.
- Existing LOS21 installs have no URI. They must sideload this build once; later
  builds can then come through the Updater.

## Kernel

`build-kernel-exfat21.sh` copies `/srv/android/src/kernel-gta3xlwifi-dt2w` (audited
before and after, unchanged) to paths of the same length. The unmodified copy reproduces
the released Image `33c1a0d1…` byte for byte after substituting the build path back,
except for the 20-byte GNU build-id (a SHA-1 over the linked bytes, which contain the path).
The release string `4.4.302-gefbdbfa3-dirty` is retained. Then only `fs/sdfat/sdfat.c`
gets the LOS24 patch (`e3ffcd8e…`, result `46a0f992…`, 10 host cases): Image
`c7b4a44f…`, config identical, exported symbol CRCs unchanged.
Attempts a–e are preserved: script errors and the two reproduction differences.

## Build and checks

`run-fixes21.sh`: verifies the device tree against the published source, saves the
rollback inputs (`device-before.tar`, source lock, old build identity) and stages
8 files plus the kernel. It updates `kernel_sha256` in `source-inputs.lock.json`,
runs the host tests (retry, boost window, touch wake: PASS) and the normal
`build-arm64-candidate.sh` (EXIT 0).
`check-fixes21.py` on unsigned target-files (`resume-check21.sh`, attempt a had an
over-strict rule for boot image components) gives PASS:

- boot kernel `c7b4a44f…`, vendor image unchanged `80aaf6c7…`;
- the three system properties each appear exactly once, and product `enable_uffd_gc=false`;
- 171 oat/odex files `concurrent-copying=true`, 0 `false`. The 26 `boot-*.oat`
  components have no key/value store, which is normal; both primary `boot.oat`
  files are `true`;
- `libandroid_servers.so` contains the retry log lines and no longer contains "disabling boost";
- `mkfs.exfat`/`fsck.exfat`, the Updater changelog URL and the releasetools quiesce hash are correct;
- the local test-key OTA (never published) runs preflight → quiesce → guard → writes in that order.

## Release signing (2026-11-28)

`sign-fixes21.sh` signs with the existing LineageOS 21 keys (`sign-release.py`; the
328 signing files match the private manifest before and after; keys never copied).
Attempt a stopped at a wrong precondition file name (nothing changed). Attempt b
signed successfully but the vendor policy check found no read-only vendor mount (lost
on reboot); `resume-sign21.sh` first compares the raw vendor image byte for byte with
the vendor image in the signed package, then remounts it `ro,noload` as the
2026-11-24 job did. Result: vendor policy (runtime mode), native VINTF, all thirteen
offline checks, GApps capacity, `check-fixes21.py` on the signed target-files and the
signed OTA, and the Updater index publisher's OTA verification (whole-file signature,
release certificate `1e593d15…`, release-keys, BLOCK, SDK 34) all pass.

- `lineage-21.0-20261127-UNOFFICIAL-gta3xlwifi-arm64-privatekeys.zip`
  `cb902c61047cca3a23da924d7b0b63b0986e5200ed34be8357983dd79a1571c3` (914471146 bytes)
- `signed-target-files.zip` `36b7aa323d80984f2b84832dbd5e3dfd270af7049f05ce215fc0272a0ee89428`

The previous release outputs are kept in `artifacts/lineage21-fixes-20261127/release-before`.

## Publication

Released as `lineage-21.0-arm64-20261127` in
[oddhap/lineageos21_gta3xlwifi](https://github.com/oddhap/lineageos21_gta3xlwifi/releases)
(public asset name without `-privatekeys`). `publish-ota-index21.py --publish`
then wrote `gta3xlwifi.json` to the `ota` branch. Device source, the kernel patch,
these tools and reports are on the `lineage-21.0-arm64` branches.
Not tested on hardware: the owner's tablet runs LineageOS 24.
