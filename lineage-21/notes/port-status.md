# SM-T510 LineageOS 21 development port

Status: candidate 12 boots Android 14, preserves the current setup through update
and ordinary reboot, and retains file encryption and SELinux enforcing. Current
crash/ANR/native tombstone checks pass. The user reports working rotation, both
cameras, brightness, Wi-Fi browsing, browser video/audio, Bluetooth, microSD and
USB-OTG. Camera startup has brief latency. These are scoped checks and user
reports; complete hardware and long-term stability validation remain incomplete.

The Android platform is the current LineageOS lineage-21.0 branch, downloaded
independently from the working LineageOS 19.1 checkout. Android userspace remains
ARM32 because the Samsung graphics libraries are ARM32; the kernel remains ARM64.
No GApps, GSI or partition layout changes are planned.

Initial adaptations:
- Separate device configuration under lineage-21/device/samsung/gta3xlwifi.
- Native bounded CPU/GPU boost uses the Android 14 AIDL NDK power enums and
  upstream android.hardware.power-ndk_shared defaults.
- Samsung's bootloader adds skip_initramfs and a physical system root. Android 14
  removed the obsolete BOARD_BUILD_SYSTEM_ROOT_IMAGE variable but unconditionally
  combines root and system when producing system.img. The original SAR boot
  path is therefore retained; a proposed ramdisk opt-in is unnecessary and is
  not included in this port.
- Kernel 4.4 has no enabled eBPF syscall/cgroup networking support. Common legacy
  Connectivity patches silently ignore firewall operations; these are not a
  sufficient replacement for actual filtering. A real legacy backend or kernel
  backport is required before a functional/safe networking claim.
- Encryption, VINTF, stock vendor SELinux compatibility and physical image sizes
  require Android 14 validation. Existing Android 12 test reports do not validate
  Android 14.

Reference checkouts on build VM:
- /srv/android/src/lineage-21.0 (platform source sync)
- /srv/android/source-audit/lineage21/connectivity-legacy
- /srv/android/source-audit/lineage21/netd-upstream
- /srv/android/source-audit/lineage21/netd-ul
- /srv/android/source-audit/lineage21/build-ul
- /srv/android/source-audit/lineage21/kernel-qcom-4.4

Only selected, reviewed compatibility changes should be carried into fresh
upstream projects; an old fork must not replace current security patches wholesale.

Current progress (2026-10-03):
- Source sync completed; exact manifest saved under
  /srv/android/artifacts/lineage-21/lineage-21.0-source-manifest.xml.
- Targeted builds pass the complete Tethering APEX, netd, networking JNI and
  statistics, PowerManager JNI, API/ABI checks and generated SELinux tests.
- Native networking uses actual iptables/qtaguid filtering and counters. It
  covers all nine child chains, the global firewall, data saver, UID/iface rules,
  VPN lockdown, ingress discard, socket tags and DNS blocking.
- DNS/socket callbacks are registered explicitly across the APEX boundary.
  The final APEX contains both private callback exports and the DNS dependency.
  Private integration symbols do not alter the public SDK headers.
- The compiled OEM Binder descriptor remains com.android.internal.net.IOemNetd;
  JarJar exclusions match both the service and its unsolicited-event listener.
- Host policy/rollback and parser/error tests pass. Physical packet tests on the
  running Android 12 kernel install IPv4/IPv6 rules and verify real IPv4 allow/
  deny behavior. IPv6 packets and Android 14 Binder operation are not yet tested.
  Every private test chain/hook was removed; SELinux remains enforcing and ADB
  was restored to unrooted operation.
- A device-only m4 guard avoids duplicate ISO9660/UDF genfs labels while retaining
  the actual Samsung vendor labels. Stock vendor CIL links with Android init's
  normal runtime flags. The diagnostic strict cross-version link fails with
  legacy Samsung neverallow conflicts; the Android 12 baseline also fails this
  strict check. This limitation remains documented rather than changing vendor
  rules or disabling generated platform policy checks.
- All seven platform patches apply against clean pinned source indexes. The full
  bacon build completed with the original verified kernel/vendor/DTBO.
- Full ROM/image/ZIP and stock-vendor VINTF checks pass. A separate physical
  system-image inspection caught Samsung init/fstab/ueventd files in the unused
  boot ramdisk. These now target TARGET_COPY_OUT_ROOT; the corrected build and
  actual image-layout verification pass.
- Recovery fstab uses /system for Android 14 OTA tools; the boot fstab and
  kernel-only physical system root are preserved.
- The device FCM 3 matrix omits the obsolete optional Wi-Fi offload HAL, absent
  from actual vendor manifests and removed from Android 14's interface metadata.
- A product-specific framework fragment declares stock vendor's System SDK 28
  resource contract. All 57 vendor APKs are resource-only overlays without DEX;
  native HALs retain VNDK 30. The vendor compatibility matrix is unchanged.
- Fifth candidate: lineage-21.0-20261003-UNOFFICIAL-gta3xlwifi.zip.
  SHA-256: 44cb64925e2d665ef2853d0206043a8a95d097841680ed59abbe47e3627999cc.
  Expanded images fit the physical partitions. The actual ext4 images use
  incompat 0x42 / ro_compat 0x7b, supported by the original kernel.
- TWRP installed the candidate successfully (updater RC 0); boot readback matches
  the reviewed image and tested TWRP is unchanged. First Android 14 boot loops
  with a black screen and no ADB. The kernel log confirms successful partition
  mounts and policy load, followed by cgroup v2 process-group ENOENT failures.
- The second candidate uses real v1 cpuacct groups for process creation,
  signaling and cleanup, with bounded EBUSY retries. Controller ownership is
  assigned after mount. Unsupported v2/blkio/schedtune descriptors stay unusable;
  existing CPU/cpuset task controls remain real. Cached-app v2 freezing remains
  unsupported. Device task profiles use the actual CPU controller directories.
- ARM32 BoringSSL self-test triggers are retained in a regular device init file;
  init's O_NOFOLLOW rejects the upstream zygote32 symlink. Upstream test services
  and failure handling remain enabled.
- The second full build and all offline checks pass. TWRP installation and boot
  readback pass. Its boot log shows pre-mount lchown on the read-only /acct
  mountpoint failed before cpuacct could mount. A third candidate prepares the
  mountpoint without changing ownership, then assigns ownership after a real
  successful v1 mount. Mount and post-mount errors remain fatal. The optional lifecycle
  probe compiled for ARM32; runtime tests have not yet run.
  Encryption and stability are not validated. Offline checks do not establish
  physical behavior.

- The third full build completed successfully. Image/ZIP/layout/package checks
  pass, including the actual libprocessgroup_setup.so in system.img matching
  the rebuilt library (SHA-256 99d682eaa89a4f82c37b98199a03792fb13c8450bc21209582ab6039e03f250d).
  A targeted syscall-model regression test checks read-only mountpoint ordering
  and mount/post-mount error propagation; this is not a physical boot test.

- Third hardware boot: ueventd and apexd-bootstrap run successfully; four
  bootstrap APEX packages mount and the ARM32 vendor/platform BoringSSL tests
  exit 0. The next stop is enablefilecrypto_failed: duplicate mount_all commands
  for cache/EFS/userdata produce EBUSY and suppress queue_fs_event, leaving the
  legacy fscrypt keyring uncreated. A fourth candidate delegates second-stage
  mounts to stock vendor init once. Root fstab retains first-stage mounts.
  No data format or encryption bypass was used.

- Fourth full build and image/ZIP/layout/package checks pass. The actual system
  root init matches the new source and contains no duplicate mount_all.
  Hardware boot testing is pending.

- Fourth hardware boot: encrypted data mounts once, ADB and Android 14 ART/
  SystemServer run, SELinux remains Enforcing. The real cgroup lifecycle probe
  passes creation, inherited membership, an escaped descendant SIGKILL and
  cleanup. Boot does not complete: watchdog traces show main waiting for audio
  policy, while audioserver dereferences a null factory (stock HAL 4.0 is not
  probed). GPU service also aborts in an unavailable BPF map.
- Fifth candidate work: current Android 14 HIDL client sources build for 4.0;
  native and Java HAL version lists include 4.0. The optional GPU BPF accounting
  checks the kernel capability property before opening maps. Targeted media
  builds pass; the full ROM build and physical testing are pending. All nine
  platform patches apply against clean pinned indexes.
- Remaining observed issue: composer repeatedly reads unlabeled legacy property
  hwc.exynos.vsync_mode, generating access denials. This has not been changed
  in the fifth candidate. Performance and complete hardware tests remain pending.

- Fifth full build completed successfully (09:21). Image/ZIP/layout/package
  checks pass, including exact media library bytes inside the actual ext4
  image, HIDL4 factory exports and the GPU BPF capability guard.
  Physical boot and audio verification remain pending.

- Fifth physical boot completes (sys.boot_completed=1) with audio and GPU
  services running. Audio mixer outputs exist; GPU work statistics report
  unavailable. Wi-Fi, an external IPv4 ping and DNS resolution/ping pass.
  Bluetooth reaches ON in a scoped diagnostic after a temporary RT subgroup
  budget, and stays ON when moved to CPU root. The temporary subgroup value
  must be confirmed reset after reboot.
- Sixth candidate keeps the original root RT budget, places CPU scheduling
  in root and uses supported cpuset groups for performance affinity. The
  exact legacy vsync property uses the existing graphics_config_prop type
  with composer read access; no value or broad default_prop access is changed.
  Source and generated SELinux checks pass so far; full build/image/runtime
  and physical function testing remain pending.

- Sixth full build completed successfully (10:31). Image, actual ext4 layout,
  package, native VINTF and stock-vendor runtime policy checks pass. Nine
  platform patches match clean pinned source indexes. Packaged profiles
  preserve CPU root scheduling; the exact vsync property label is present.
  ROM SHA-256: 733e56c6db1982b9d10d1b9ddca6e0f3cbddb5b428780a862108dca13b00aff7.
  Physical installation/testing is pending; data is not formatted.

- Sixth physical installation succeeds (TWRP updater RC 0). Boot and new
  task-profile bytes match readback; the exact vsync property label is present.
  Android 14 completes boot with encrypted file data and SELinux Enforcing.
  Bluetooth starts automatically, joins CPU root/cpuset foreground and records
  zero crashes. Root RT budget remains 950000/1000000 us; the temporary
  foreground budget is reset to 0. No vsync property denials or crash-buffer
  entries are observed after boot and power tests. IPv4 Internet/DNS pass.
- Real cgroup lifecycle test passes again. Touch boost reaches CPU
  1248000/1352000 kHz and GPU 545000 kHz; actual app-launch logs reach
  1248000/1560000 and 676000 kHz. Expiry, screen-off cancellation, wake idle
  and battery saver cancellation pass. CPU aggregate idle returns to
  449000/936000 kHz and the independent GPU request to 0. Battery overrides,
  saver and diagnostic logging are restored. See boot-candidate6-summary.json.
- Both cameras, rotation, browser media, Bluetooth pairing, Wi-Fi reconnect,
  charging, credential/recovery behavior, overnight idle and Android 14
  per-app firewall/VPN/IPv6 validation still require physical tests.

- User confirms rotation, sound, camera, brightness and browsing after a scoped
  browser policy repair. Camera feels laggy. Migrated browser POLICY_REJECT_ALL
  was removed; restricted networking mode remains active and other app policies
  are preserved. The legacy bulk-rule backend rejected INVALID_UID (-1) in the
  actual framework package list. It now omits that non-application sentinel
  while applying every valid UID; other negative values remain errors. Host
  allow/deny/rollback/parser tests pass.
- Under Wall You/image use, system_server aborts in libmeminfo GPU memory BPF
  construction during AppProfiler.reportMemUsage; later memory reports repeat
  the failure and the framework restarts. The kernel itself stays up. The tablet
  is in tested TWRP. Candidate 7 adds a kernel capability guard to both GPU
  memory readers, retaining the existing unavailable result. Targeted build
  and optional actual-library probe, full ROM and hardware tests are pending.

- Candidate 7 targeted build passes libmeminfo, netd and the optional ARM32
  memory probe (16 seconds). Both GPU-reader guards apply idempotently. Ten
  complete platform patches pass clean pinned-index application checks.
  The full ROM is building; current device-input code revision is
  38fe8f491e6ba959824cd6c11ef5965f1163b17f.

- Candidate 7 full build passes (05:07). Image/ZIP, actual ext4 layout and
  package checks pass. System libmeminfo SHA-256 is
  01750da3da1c07806e4736bdaebeaf611ecfff3cca5bf6b2d5bc292cedd0746d,
  matching the newly compiled capability-guarded library. ROM SHA-256 is
  97be7701d2cc9e62954abd71d6e10b9bf1124ecaca9fe6b0a2497d8e5b450694.
  Stock kernel/vendor/DTBO and system_ext policy are unchanged. Installation
  and actual-library/runtime validation remain pending.

- Candidate 7 installation succeeds (TWRP updater RC 0). Boot, libmeminfo and
  netd bytes match readback. Android completes boot with encrypted file data
  and SELinux Enforcing. The noninstalled probe executes as adb shell: all
  three GPU queries return unavailable without abort and normal RAM reads
  work. It is removed afterwards. A full -a memory dump exceeds the default
  10-second timeout; the --local --oom summary completes with normal RAM
  status. System-server PID remains unchanged and the crash buffer is empty.
- The actual restricted allowlist update includes INVALID_UID and now returns
  success. Restricted mode remains active and browser block-all policy stays
  cleared. Bluetooth is ON with zero crashes and root RT budget unchanged.
  User Wall You stress testing and longer observation remain pending.

- Automated Wall You/Picsum stress: 16 scroll gestures leave the app resumed,
  system-server PID unchanged and boot animation stopped; the crash buffer
  is empty. App PSS reaches 888197 KiB and RSS 946888 KiB in this sample.
  This is a short concrete workload, not a complete memory-leak or long-term
  stability test. The user's original workload and longer observation remain
  useful; camera lag is still an open performance observation.

## Private signing update (2026-10-03)

Candidate 7 has been signed with project-owned APK/APEX/OTA keys and installed
without formatting data. Build type remains userdebug; signing tags are now
release-keys. Trust reports signing level GOOD (0). The 204 package records and
UIDs survive, as do the three third-party signature records. Boot completes,
SELinux is enforcing, file encryption is active, Bluetooth reaches ON, and
browser page rendering/DNS pass. System-server PID 4347 remains unchanged and
the crash buffer is empty during these checks. All earlier platform fixes and
the tested boot image are unchanged. This does not establish long-term stability.

The user reports camera lag is mainly brief initialization after app opening.
The camera implementation has not been changed. See [signing](signing.md),
[signature checks](release-signature-check.json), [migration checks](privatekeys-app-migration-check.json)
and [runtime checks](privatekeys-runtime-check.json).

Installed ZIP SHA-256:
`c40cb6e5ec4ad0b610236160849348a20fdcce0c34ddac1e2ce145ba4b57a020`.

## Factory reset initialization fix (2026-10-03)

A user-initiated TWRP Format Data exposed unsupported ext4 project-quota
initialization in Android 14 fs_mgr. Candidate 8 disables project quota only for
this device, retaining real user/group quotas. The existing empty filesystem was
repaired in place, without formatting it again. The privately signed candidate
passed image/layout/package/signature checks and TWRP installation (updater RC 0).

Physical regression testing began with quota absent, matching the recorded
TWRP format state. Android initialized user/group quotas with project absent,
completed setup, and survived an ordinary reboot. Both checks retained
read/write /data, file encryption, SELinux Enforcing, Trust signing level GOOD
and an empty crash buffer. Runtime fs_mgr library hashes match the built image.
The build remains userdebug with release-keys. The stock kernel/vendor and the
previously tested power, networking, media and memory fixes remain unchanged.
The user's format removed old apps/data; this test does not claim their retention.

Installed ZIP SHA-256:
`a1046f97465d2ff7b8a7db03c4855ccd69a57eb6b6704f97abeb3598c8c0da20`.

See [diagnosis and repair](factory-reset-quota.md),
[first-boot/reboot results](quota-firstboot-check.json),
[image layout checks](quota-native-layout-check.json), and
[private signature verification](quota-release-signature-check.json).
Long-term stability and the remaining hardware tests are still pending.

## Wi-Fi and usage cleanup (2026-10-04)

Candidate 12 disables the unused phone application in its compiled manifest,
stops the absent modem daemon before class main, and gates optional per-thread
CPU/battery measurements on actual capability. Supported CPU/cpuset profiles
remain active; absent blkio profiles retain default scheduling. Four exact
health sysfs files receive the existing battery label. A shutdown hook avoids
Samsung MobiCore's broken SIGTERM handler before EFS unmount.

Release builds now receive distinct recorded build identities. This corrects
stale manifest flags cached across earlier candidates with reused fingerprints.
The installed release automatically replaces its old package cache and retains
all 210 package/UID records through update and normal reboot. Both final boots
pass encryption, key availability, SELinux, signing, artifact readback and
empty crash-buffer checks. The final reboot has zero current-boot ANR/native
tombstones, successful EFS unmount and a 2414 ms init shutdown. Browser rendering
passes. The user-authorized earlier data format removed old data; the final
update performs no format and preserves the subsequently completed setup/apps.

ZIP SHA-256: `80ac25b60c744836dbb225dfb81f64ce9ef1fc40e31557b67e8fe284c30c5286`.
Build number: `gta3xlwifi.20261004.132339`.
See [details and limits](usage-compat.md) and
[physical results](usage-runtime-check.json). Full hardware and long-term
stability validation remain incomplete.

## Additional user hardware checks (2026-10-04)

The user reports successful Bluetooth, microSD and USB-OTG tests. These reports
add practical coverage without certifying all codecs, peripheral types, storage
formats, suspend/resume behavior or prolonged operation. Recovery FBE decryption
remains unsupported; setting an Android PIN does not make Samsung keystore
available in TWRP. See the recovery settings update in the build repository.
