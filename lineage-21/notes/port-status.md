# SM-T510 LineageOS 21 development port

Status: full Android 14 ROM build and offline checks pass. The first two hardware boots failed during process-group setup; the fourth candidate runs Android 14 with encrypted data, ADB and enforcing SELinux but remains in the boot animation waiting for audio. A fifth candidate restores the current HIDL 4 client and skips unsupported GPU BPF metrics.

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
