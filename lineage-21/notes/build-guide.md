# Native LineageOS 21 port for SM-T510

This is Android 14, ARM32 userspace with the existing ARM64 Samsung kernel.
It does not use a GSI, Google services, dynamic partitions or an A/B conversion.
The current platform source reports the 2026-09-01 security patch level. That
does not imply that the old Samsung kernel/vendor firmware has the same fixes.

The build uses an independent Ubuntu 22.04 checkout at
`/srv/android/src/lineage-21.0`. Preserve the working Android 12 checkout,
installation ZIP and tested TWRP recovery as rollback inputs.

## Reproduce the platform changes

Copy this integration directory to `/srv/android/ports/lineage-21`.
The original source manifest is saved in `notes/lineage-21.0-source-manifest.xml`.
`notes/pinned-build-manifest.xml` has identical project revisions and absolute
remote URLs so that a standalone local manifest can be used in a fresh checkout.
Run `bash tools/sync-pinned-platform.sh` only against an empty checkout.

Stage the device repository into `device/samsung/gta3xlwifi`. Run
`python3 tools/stage-native-device.py` after restoring the verified baseline
inputs under `/srv/android`: `vendor-stock/images`, extracted CWA1 vendor files,
and the original source-built `artifacts/kernel-smoke` kernel/config/DTBOs.
`python3 tools/fetch-baseline-kernel.py` downloads and checks the exact baseline
kernel inputs from the private `lineage21-baseline-kernel` release. Existing
different inputs are rejected. GitHub CLI must be authenticated to the account.
The device repository excludes large prebuilt inputs; staging checks their
checksums. The baseline kernel build tools and private vendor release are in
the existing integration/kernel/vendor repositories. Do not use the rejected
ramdisk experiment under `notes/rejected-ramdisk-research`.

Run `python3 tools/apply-pinned-patches.py` to apply the ten final platform
patches. It checks every revision, patch checksum and application before writing
source. `--check-only` verifies the current tree without modifying it.
The incremental development helpers are retained for review; they are not
additional patches to apply after the final exported patches.

Build with `bash tools/build-rom.sh bacon`. It selects
`lineage_gta3xlwifi-ap2a-userdebug` and retains a single build timestamp across
incremental retries. The original kernel, stock vendor and physical system root
are preserved. The optional network, cgroup and GPU-memory probes have `installable: false` and are not
part of the product package list.

## Verify before a hardware installation

Capture the build's exit code in `/srv/android/logs/lineage21-rom-build-final.exit`.
Run `verify-native-images.py`, `verify-native-layout.py`, `verify-port-package.py`, `check-native-vintf.py`
and `check-stock-vendor-policy.py --runtime-mode`. The image verifier checks the
expanded sizes, boot headers, Samsung trailers, original kernel/vendor/DTBO,
recovery layout and OTA metadata. The layout verifier checks actual ext4
features against the original kernel and verifies /init plus the three Samsung
boot files inside the physical system image, rather than relying on staging
files in the unused boot ramdisk. The package verifier checks the Android
version, packaged power backend, networking selector, absence of the probe and
Google service APKs, and OTA partition references.

Generated platform SELinux tests remain enabled. Actual stock vendor CIL links
with Android init's normal runtime flags while SELinux remains enforcing. A
separate strict cross-version neverallow diagnostic fails on the old Samsung
vendor policy; the Android 12 baseline fails that diagnostic too. This is a
remaining vendor limitation, not proof of full security equivalence.

## Evidence and remaining physical tests

Host tests cover real firewall policy generation and rollback state, and Samsung
qtaguid parsing/error behavior with mocked boundaries. The optional ARM32 packet
probe installs IPv4/IPv6 rules on the tablet's original kernel and verifies real
IPv4 allow/deny packets in scoped private chains. It cleans its own chains and
the test UID/UDP hook. IPv6 packets have not been exercised. These tests ran on
Android 12 and do not demonstrate Android 14 Binder or service operation.

Before calling the port usable, verify Android 14 boots with SELinux enforcing,
both cameras, rotation, Wi-Fi/reconnect, browser video/audio, charging, USB/ADB,
sleep/wake and overnight idle. Check actual DNS, per-app data usage, data saver
and always-on VPN lockdown. Verify CPU/GPU boost resets after its bounded window
and during screen-off/battery saver. Encryption and recovery interaction also
need physical validation. Do not label the build stable until these tests pass.

## cgroup v1 compatibility

The immutable `cgroups.gta3xlwifi.json` product file selects the device-only
process tracking backend. Its mandatory cpuacct controller is mounted at /acct,
with controller ownership assigned after mount. The mountpoint is prepared
without ownership changes because /acct initially belongs to the read-only
Samsung system root; ownership is applied only to the mounted controller. Process creation, signaling,
cleanup and memory cgroup errors are preserved. Cleanup uses real cgroup.procs
and bounded EBUSY retries, since this kernel has no v2 cgroup.events/cgroup.kill.
The current v2 lifecycle remains unchanged on other products. The device task
profiles retain CPU root scheduling and use supported cpuset groups for affinity,
instead of the unsupported schedtune controller. Cached-app v2 freezing is not advertised as supported.

`tests/cgroup-probe.cpp` is an optional on-device test. It creates one isolated
UID's cgroup, forks a descendant into its own Unix process group, and checks
that the actual library kills both processes and removes the empty groups.
It refuses to touch an existing test UID and has bounded timeout cleanup.
It is not packaged in the ROM. The physical lifecycle test passed on candidate 4;
see boot-candidate4-summary.json.

## Second-stage filesystem mounts

Stock vendor init mounts cache, EFS and userdata on fs. The root device init
only adds hardware/data-directory setup; its root fstab supplies first-stage
vendor/product mounts. Repeating mount_all from both scripts produces EBUSY
and prevents init from receiving FILE_ENCRYPTED and creating the session FBE
keyring required by the 4.4 kernel. No format or encryption bypass is required
to correct this ordering error. Encrypted file data mounts successfully and candidate 5 completes Android boot;
full credential/encryption and recovery testing remains pending.

## Stock audio HAL and GPU metrics

The vendor registers audio core/effects HIDL 4.0. Android 14 retains the version
4 client branches but only builds/probes version 5 and newer by default. This
port builds those current client sources for 4.0, includes the client in the
device product and adds 4.0 to both native/Java version lists. No old framework
or fabricated vendor HAL version is used. GPU work-per-UID BPF accounting is
unavailable when ro.kernel.ebpf.supported=false; the service skips map setup
and leaves statistics uninitialized rather than publishing fabricated values.
Rendering and the bounded power boost are separate and unchanged.

## Kernel RT group scheduling and graphics property

The 4.4 kernel enables CONFIG_RT_GROUP_SCHED and retains a finite root RT
budget of 950000 us per 1000000 us. New CPU scheduling subgroups start at
zero RT budget; joining them prevents Bluetooth SCHED_FIFO startup. Device
performance profiles now join CPU root and the supported cpuset affinity
groups. RT permissions and the original root budget remain enforced; no
unlimited RT setting or Bluetooth scheduling failure bypass is used.
The exact hwc.exynos.vsync_mode property is labeled graphics_config_prop,
with composer read access. No property value or broad default_prop access
is changed. Candidate 6 runtime tests confirm automatic Bluetooth ON with no crashes, CPU
root placement and the original finite budget; the temporary subgroup budget
is reset to zero. No vsync property read denials are observed after boot and
power testing. See notes/boot-candidate6-summary.json.

GPU memory reads in libmeminfo also require a kernel capability guard. Under
image-app load, AppProfiler.reportMemUsage calls Debug.getGpuTotalUsageKb and
the unsupported BPF map constructor aborts system_server. Both per-process
and aggregate GPU readers return unavailable when the kernel capability is
false; Debug already represents this as -1. No fake memory total or accounting
subtraction is introduced. An optional noninstalled probe exercises all three
GPU APIs and ordinary RAM accounting. Candidate 7 boots and the actual-library probe passes all three GPU APIs and
ordinary RAM accounting. A local memory summary and 16-scroll Wall You workload
pass without system-server restart. Longer tests and camera performance remain
pending; see boot-candidate7-summary.json and wall-you-scroll-candidate7.json.

The installed browser initially retained POLICY_REJECT_ALL from the Android
12-to-14 network-policy migration. Its block-all bit was removed through the
network-policy service after the user reported failed browsing; restricted
mode remains on and other UID policies are preserved. The user confirmed
browsing works afterwards. Other migrated app policies should be reviewed
through Settings when needed, rather than globally disabling enforcement.
Actual bulk allowlist updates included INVALID_UID (-1) from package
enumeration. The legacy backend omits that non-application sentinel, applies
all valid UIDs transactionally and still rejects other negative values.
Host tests verify real app allow/deny defaults and preservation on bad input.

The optional `gta3xlwifi-meminfo-probe` is noninstallable and has no Make
installation target. Build its ARM32 binary output declared in the generated
Soong ninja file (the dependency-variant suffix is generated), rather than
assuming an installation target. Run it via rooted ADB after installing the
matching ROM library, then remove the temporary executable. It checks all
three GPU-query APIs remain unavailable and ordinary RAM accounting works.

## Private signed updates

Use the [private signing and certificate migration guide](signing.md) for builds
installed after the key migration. Plain development `bacon` builds use test keys.

## Booting after a factory reset

The SM-T510 kernel supports ext4 user/group quota but not project quota. The
final system/core patch and `ro.gta3xlwifi.ext4_project_quota=false` must both be
present before booting newly formatted data. An older Android 14 port enables
project quota by default and makes the filesystem unmountable. See
[the diagnosis, repair and regression test](factory-reset-quota.md).

## Wi-Fi-only and usage compatibility cleanup

The current device configuration disables mobile data, SIM hardware and the
shared vendor image's unused IMS feature. Product init stops the modem
service before class main and stops mobicore in the shutdown event.
The device also labels exact charger type files and skips absent blkio groups.
Platform patches now include packages/apps/Settings and packages/services/Telephony
(12 pinned projects in source-lock.json), plus the optional CPU reader guard in
frameworks/base. The TeleService application enabled and persistent flags use
a static capability resource, disabled by the Wi-Fi-only device overlay.
See [rationale and limits](usage-compat.md). After private signing, run
`verify-usage-compat.py` in addition to the normal image/layout/package checks;
it inspects the physical product image, init syntax, compiled framework guard
and reviewed Settings/TeleService artifacts. Physical runtime/reboot checks remain required.

## Release identity and package caches

`build-release.sh` records a new UTC build number and timestamp before compiling
and signing a release. `build-rom.sh` reuses that recorded identity for partial
builds of the same candidate. Keep these two files with the artifact when
recording a build; do not reuse their values for a changed release. Android keys
its package parser cache on partition fingerprints, and APK mtimes in these
images are deliberately fixed. Reusing a fingerprint can retain stale manifest
flags after a full OTA. Signature verification also checks the explicit build
number against the signed system fingerprint and OTA metadata.
