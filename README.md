# SM-T510 native LineageOS and TWRP build integration

Native LineageOS 19.1 / Android 12L, without Google apps, for Samsung Galaxy Tab A
10.1 (2019) SM-T510 (`gta3xlwifi`). Separate TWRP 3.7.1_12 recovery. This is a
development port tested on one tablet, not an official or certified stable release.

| Repository | Branch | Contents |
| --- | --- | --- |
| [Device](https://github.com/oddhap/android_device_samsung_gta3xlwifi) | lineage-19.1 | Native product, overlays, power backend, policy, image packaging |
| [Kernel](https://github.com/oddhap/android_kernel_samsung_gta3xlwifi) | lineage-19.1 | Upstream source snapshot plus cleanup and functional fixes |
| [TWRP device](https://github.com/oddhap/android_device_samsung_gta3xlwifi_twrp) | twrp-12.1 | Recovery configuration, USB, fstabs, display and ramdisk geometry |
| [Vendor](https://github.com/oddhap/android_vendor_samsung_gta3xlwifi) | lineage-19.1 | Stock CWA1 blobs, file inventory and private stock-image assets |
| This repository | main | Pinned manifests, platform/kernel patches, build and validation tools |

## Tested state

Android setup and boot, Wi-Fi, both cameras, rotation, browser video and sound
were reported working. The installed power update passed interaction/launch
boost expiration, screen-off cancellation, battery-saver cancellation and
system-server restart cleanup tests with Android SELinux enforcing. A launcher
sample showed 50.2% to 21.3% janky frames; this is one device/workload observation,
not a general benchmark. Long-term battery life and stability remain unverified.
See [power implementation/results](docs/power-boost.md) and
[installed-build provenance](docs/native-provenance.json).

TWRP boots its menu automatically, supports touch/root ADB/software recovery
reboot and installed the ROM. Samsung hardware FBE decryption is unsupported.
The startup guard reports unavailable keystore and preserves locked data.
Recovery has unauthenticated ADB and TeamWin's recovery-domain policy differs
from Android's enforcing system policy. No backup/restore or MTP claim is made.

## Build environment and layout

The scripts preserve the project's standard Ubuntu 22.04 layout `/srv/android`.
Allow approximately 24 CPU threads, 64 GiB RAM and several hundred GiB of disk
for the two Android checkouts, toolchain, outputs and ccache. A smaller machine
needs fewer parallel jobs. Use a normal `builder` account owning `/srv/android`.
Do not run repo sync or Android builds as root.

Install the package list from `tools/provision-build-packages.sh` as root; its
qemu-guest-agent setup is only needed on the build VM. The tested compiler is
AOSP GCC 4.9 revision `961622e926a1b21382dba4dd9fe0e5fb3ee5ab7c`.
GitHub authentication is needed for these private repositories/releases:

```sh
gh auth login
gh auth setup-git
mkdir -p /srv/android
cd /srv/android
git clone https://github.com/oddhap/android_build_samsung_gta3xlwifi integration
python3 integration/tools/setup-source-checkouts.py --sync
```

The setup tool downloads Google's `repo` launcher if absent, initializes the
exact pinned project manifests, syncs upstream sources, clones the device trees
and kernel/vendor repositories, prepares the pinned GCC toolchain, downloads
matching vendor image/stock DTBO and the previously tested TWRP kernel/DTBO.
It refuses to replace populated checkouts. Existing build environments should
use the patch/check tools directly instead of rerunning setup.

The full upstream manifests are pinned to the original source revisions. The
GitHub fetch URL is explicit, so they also work when hosted in this repository.
`patches/source-projects.json` records each modified platform project and its
base. `*-complete.patch` captures the entire final diff for that project; do not
apply it in addition to the component patches touching the same files.

## Build native Android

```sh
cd /srv/android
python3 tools/apply-legacy-network.py
bash build-kernel-smoke.sh
python3 tools/stage-native-device.py
bash build-native-rom.sh
```

The published kernel branch already contains its seven intentional source fixes.
The kernel power patch helper accepts those already-applied patches; otherwise
it only patches the recorded upstream base. The build regenerates DEFEX outputs.
The latest ROM was built from upstream HEAD plus uncommitted changes; a new
committed kernel build changes Git version text and may change timestamps and
checksums. The old kernel SHA in provenance documents the installed build, not
a universal expected checksum for every rebuild.

Source sync/platform patches and kernel preparation must finish while builds are
stopped. The native staging tool checks the vendor image checksum and kernel
artifact checksums, generates the model-specific DTBO and stages stock policy
metadata. The ROM keeps the original physical partitions and stock vendor image.
`build-native-rom.sh` applies SystemUI and power integration patches idempotently.

Validation tools include `verify-native-images.py` (use `--kernel-sha` for the
newly built kernel), `verify-power-package.py`, `check-native-vintf.py` and
`check-stock-vendor-policy.py`. Read their arguments and expected build-exit-file
paths before running. Some assertions intentionally pin the installed snapshot;
update them only after reviewing and recording any new expected artifact.
Compilation and offline checks alone do not establish hardware stability.

## Build separate recovery

```sh
cd /srv/android
bash build-twrp.sh
python3 verify-twrp-image.py
```

The recovery tree has the previously tested, source-built kernel/DTBO staged from
private release `tested-recovery-inputs`. Their hashes are pinned in the verifier.
The kernel repository also has a `twrp-12.1` branch containing only the dtc
and camera lifetime fixes, matching the recovery source changes. To rebuild it,
use that branch and run `SMT510_POWER_BOOST=0 bash build-kernel-smoke.sh` with the
same GCC and defconfig. Build and stage Android first or use a separate workspace
to avoid replacing Android's kernel artifacts with the recovery baseline.
Record new hashes before changing the recovery verifier. Its release asset is retained so
the tested recovery can be rebuilt without substituting an untested kernel.

`build-twrp.sh` applies the recovery-only FBE startup guard and adds real file
dependencies to TWRP's library-relink copy step. The image verifier checks packed
ELF dependency closure, current libraries, `/etc` symlink, Android `/misc` fstab,
model, kernel/DTBO and a compressed ramdisk smaller than 16 MiB. XZ prevents
initrd from overlapping the bootloader's DTB location. The Samsung trailer is a
packaging marker, not an official signature.

## Licensing and source attribution

New build tools/configuration are Apache-2.0 unless their file notices say
otherwise. Kernel sources retain GPL and upstream per-file notices. Platform
patches inherit their upstream files' licenses; a patch bundle does not relicense
LineageOS, AOSP or TeamWin. Legacy networking backports are attributed in
[patch notes](patches/lineage-19.1/README.md). Proprietary Samsung/vendor binaries
retain their owners' terms; no open-source license is granted to those blobs.

No SSH credentials, access tokens, device identifiers, raw personal logs,
ccache, toolchain binaries or Android build output are committed here.
