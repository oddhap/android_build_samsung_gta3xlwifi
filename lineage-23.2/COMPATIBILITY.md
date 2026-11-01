# LineageOS 23.2 / SM-T510 compatibility work

Updated October 21, 2026. This is an initial source port, **not a bootable release**.
No Android 16 image has been installed or physically tested. The working 21 ROM,
TWRP, source checkouts, keys and user data are preserved.

## October 23: isolated FunctionFS per-inode labels, authorization retained

[Combined capability experiment](experiments/kernel-functionfs-20261023-01/)
implements bit12/GENFS/per-inode labels on top of NNP02 in ONE original-base
patch; **do not also apply the NNP-only patch**. Context=/NONE/unknown behavior
reject per-file labeling. Unimplemented capability-name gaps are skipped, not
advertised. Existing POSIX/owner/MAC/transition/associate gates remain. A real
extracted-hook audit underflow for non-null/size0 is fixed by checking size;
syscall reachability/tablet exploit is not proven.

**340 mount comparisons / 896 actual VFS+SELinux authorization paths PASS**
Mac/Linux ASan/UBSan/Werror; fixtures, not namespace/AVC/USB execution. Actual
policy binaries set bit12 and genfs root functionfs; queried init relabel grants
are absent and are NOT added. New full kernel **exit0 18:13:51 UTC**, unchanged
config. Actual mount/label/load capability references, FFS/VFS/NNP/qtaguid links
and exact ELF→Image **25,411,320 bytes / 7250adb995df7cc2d599f38f5829cf92bec9679a2dbe914c264741f604c1c6f9** pass.
[Evidence](reports/kernel-functionfs-20261023.json). Source audit **18:15:39 UTC**
PASS1,168/13, no promotion or prebuilt change. Not whole loader/enforcement proof.
Other active capabilities (especially extended socket classes), strict281/367/
proposed279, live USB/reload/concurrency, full networking, HAL/APEX/FBE/recovery/
OTA/signing/approved backup/rollback/hardware testing still prevent flashing.

## October 23: isolated NNP/nosuid capability + mount-namespace backport

Both real user/userdebug diagnostic policy binaries set bit5, previously absent
from 4.4 capability loading/exec semantics. [Revision02](experiments/kernel-nnp-transition-20261023-02/)
adds explicit bit5/process2 AVC authorization with both permissions when required,
original bounded fallback/errno and no removal of ordinary exec checks. All 56
old class/permission tables remain fixed. Bit4 remains unnamed, not fake cgroup
label support. Foreign mounts require nosuid checks; current USER_NS=n has modern
mount-helper-equivalent decisions. USER_NS=y explicitly fails compilation.

**16,384 decision cases / 8,192 actual load-helper bitmap combinations PASS**
Mac/Linux sanitizers; actual objects/AVC/namespaces remain fixtures, not execution.
Complete fresh kernel **exit0 17:54:53 UTC**, unchanged config. Actual ELF contains
namespace/AVC/bounded/capability/callsite links and class57; exact Image rebuild
**25,411,320 bytes / 88b9a98b42caa89f9848c7d44a89da58b23538b4ecb57c7d29ab9cd40ff9c4a5**.
[Evidence](reports/kernel-nnp-transition-20261023.json). Original prebuilt untouched.

This is not whole policy-loader/enforcement proof, all other enabled policycap
semantics, real namespace/exec/reload race testing or full networking readiness.
Strict failures remain 281/367 (proposed metadata279). FBE/HAL/APEX/recovery/OTA/
signing/approved hardware backup/rollback/runtime validation still block flashing.
Source audit PASS **17:55:47 UTC**, unchanged snapshot06 / 1,168/13.

## October 23 next step: private UWB type collisions isolated in staged metadata

The [two-file delta](experiments/vendor-uwb-namespace-20261023-01/) alpha-renames
only Samsung-private UWB CIL symbols and one context field. Endpoint names,
versioned public/platform policy and every vendor allow/neverallow are preserved.
Byte-exact inverse/Git replay pass. Strict compilation with the same other input
hashes **still fails 279 diagnostics**, down from 281; two exact identities are
removed and none introduced. This is not a new vendor image or permission bypass.

Actual binary unconditional TE comparison across **505 domains / 2,020 queries per
policy** finds no newly granted add/find pairs in the four UWB target mappings.
Framework registration isolation is restored, but 28/4 legacy pairs narrow; caller,
hardcoded-label and HAL compatibility must be reviewed. Constraints, conditional
policy and live enforcement are outside this inspector. **18 fixture tests PASS**
on Mac/Linux. Source audit PASS **17:07:15 UTC**, snapshot 06 unchanged. Original
production input still fails 281 and archived complete userdebug still 367.
[Evidence](reports/vendor-uwb-namespace-20261023.json). No security/flash approval;
image labels/xattrs/cache invalidation, full networking and runtime/install work remain.

## October 23: policy version 30 was not sufficient binary compatibility evidence

Actual compiled Android 16 policy contains **92 userdebug / 91 user nlmsg-kind-3
records**, capability bit 9 **off**. Extracted actual Samsung code treats their
first byte as an old M ioctl driver, consumes **41 of 42 bytes** and contaminates
subsequent records via its global compatibility mode. Original mismatch is a
retained exit-1 result. An [isolated three-file reader fix](experiments/kernel-policy-reader-20261023-01/)
preserves inactive native encoding; the real loader **rejects active netlink_xperm
with EOPNOTSUPP**. No modern enforcement capability is advertised. No neverallow
or policy permission is edited; ancient ambiguous M-driver-3 support is not claimed.

Each real-policy-derived record suite passes **25 controls/cases** with ASan/UBSan;
8,192 fixture capability combinations verify the actual guard and call ordering.
These are not whole-policy loading or kernel execution. Complete independent
kernel build passes **16:29:25 UTC** (same baseline config); qtaguid native/compat
pointers, reader disassembly and exact ELF→new Image correspond. The Image stays
outside Android prebuilt/ROM. Source audit PASS **16:36:09 UTC**, snapshot 06 unchanged.

Fresh production **user policy-only build** succeeds but actual-vendor strict
linkage **still fails 281 diagnostics**, versus existing complete userdebug's
367. Production diagnostic binary has zero permissive domains. Fewer variant
conflicts are not source security fixes; -N linkage still is not approval.
Vendor/private namespace collision review, other unsupported policy capabilities,
whole loader/enforcement, networking, runtime/HAL/APEX/FBE/recovery/OTA remain open.
[Full evidence and remaining limits](reports/policy-kernel-reader-20261023.json).

## October 22 evening: explicit kernel support for socket-owned tags

[Final isolated experiment](experiments/qtaguid-persistent-20261022-02/) adds a
private no-pointer native/compat ioctl (0x7151), requiring global root plus
CAP_NET_ADMIN, an own empty session and nonpassive driver. Ordinary process-owned
semantics remain default. Opted-in INET/INET6 tags are detached from process
lifetime, survive session exit/PID reuse and retire via existing explicit untag/
UID deletion/inet file-release. Non-INET creation/promotion is rejected before
allocation. Ref/UID resources retire safely across shared refs and retag. Netd's
raw transport requires ACK with no old-kernel fallback.

**45,953 host assertions**, using 23 extracted actual kernel functions, and
**1,825 transport assertions** pass with ASan/UBSan. Locks/credentials/tree/driver
operations are fixtures; real host sockets/dup are used only on the transport
side. This is **not kernel execution, concurrency, buffered-close or hardware proof**.
An actual Netd ARM64 CFI object compiles. Complete independent kernel build passes
(exit 0, 21:13:05 UTC), unchanged baseline config; native/compat fops pointers,
command/capability code and exact reconstructed new Image are checked.

The new 25,410,936-byte Image is diagnostic, not in Android prebuilt/target-files.
Distinct build/manifest kernel revisions and complete touch/input prerequisites
are recorded, with all failed attempts retained. This addresses the structural
process-exit tag loss in the opt-in implementation, **not other policy recovery,
real permissions/stats budgets, complete packet engine, Java/loader or readiness**.
Historical accounting rows remain subject to required real budgeting. Exact
ioctl/sysfs SELinux access and strict vendor-policy/HAL/APEX/FBE/recovery/OTA
validation remain unresolved; no checks or BPF readiness are bypassed.
[Full evidence](reports/qtaguid-persistent-20261022.json). Post-work source audit
PASS 21:14:13 UTC: unchanged 1,168-project / 13-patch snapshot 06, no source promotion.

## Earlier October 22: existing kernel socket cleanup and isolated real I/O transport

The earlier final-socket cleanup suspicion is now narrowed by **actual binary
proof**: `inet6_release -> inet_release -> qtaguid_untag(sock, true)` is linked
into the preserved vmlinux. Original objcopy reconstruction in new scratch gives
the exact selected Image SHA. Relevant preserved/locked kernel sources match.
The stored tagging PID is used to remove the tag and release its sock reference;
no new kernel patch/build was needed for this hook. This is **offline proof, not
physical lifetime/concurrency or A16 kernel-conformance validation**.

The [new transport experiment](experiments/qtaguid-socket-20261022-01/) performs
real bounded proc tag/untag command I/O, verifies genuine sysfs/procfs and misc
identity, rejects passive-mode fake success and pins a CLOEXEC socket duplicate
through validation/write. **1,607 assertions PASS** with ASan/UBSan and real host
sockets/FD reuse; driver I/O is a fixture. Actual Netd ARM64 CFI object PASS, not
a linked Netd owner or full ABI/runtime validation. No source promotion.

**Restart persistence is still a concrete blocker:** closing a process qtaguid
device session clears its tags, including still-live app sockets. The final-close
hook does not solve this. Ordinary endpoint permission/CLAT/budget checks are
also not provided by this trusted raw transport. Exact new sysfs SELinux accesses
are unproven; no broad allow rules added. Full packet/owner/Java/loader and strict
vendor-policy/FBE/recovery/OTA validation remain open. See
[October 22 evidence](reports/qtaguid-socket-20261022.json). Source audit PASS
20:21:28 UTC: unchanged 1,168-project / 13-patch snapshot 06.

## October 21 networking work: policy semantics and complete DNS helper links

The isolated [UID-policy value experiment](experiments/uid-policy-20261021-01/)
now covers all **12 A16 firewall chains**, per-user appId exemptions, independent
metered allow/user-deny/admin-deny, Data Saver and exact framework/DNS reason
queries. It validates replacements before candidate mutation. It is not a kernel
installer or live Netd owner, and success does not indicate packet enforcement.

Validation: **192 API/state checks**, source-bound constants and **526,888
comparisons against extracted actual native A16 DNS logic**, with ASan/UBSan,
PASS on Mac/Linux. **8,336 comparisons against extracted actual Java reason/query
methods** also PASS on the VM. Map/SDK environment is fixture metadata. These do
not compile/run the four Android accounting regressions or prove Android behavior.
The production source compiles with actual `libnetd_server` ARM64 CFI flags:
one object, not a linked or installed Netd backend.

The earlier DNS helper experiment now **links as complete ARM64 CFI/APEX31 and
ARM32 CFI shared libraries**, outside TOP. No undefined-symbol/version/warning
checks are removed. Dynamic old exports, SONAME and dependencies match baseline;
the only added versioned export is private `ADnsHelper_setLegacyCallbackV2`.
**Full header ABI and runtime remain unproven.** Original-source ARM32 dependency
build `dns-shared-deps-01` passed (44 actions, exit 0, 21:28:16 UTC).

No network experiment is applied to the image. The missing kernel/Netd owner,
readback/rollback/restart persistence, interface/VPN/LNA, permissions/socket
lifetime, quota/CLAT, Java/API and loader integration remain real blockers.
Old blanket loopback/core rules cannot be replayed as A16 equivalents. Kernel
qtaguid socket references and current-tgid ownership also require lifecycle
proof/fixes before claiming automatic foreign-socket cleanup from a long-lived
Netd device FD. See [detailed evidence and limits](reports/network-policy-20261021.json).
Post-work audit PASS 21:29:36 UTC: unchanged 1,168-project / 13-patch snapshot 06.

## Latest full-image result: complete diagnostic target-files, not a test ROM

**`full-platform-03` completed successfully** at 20:39:15 UTC, October 21:
exit **0**, 29m21s, targets `target-files-package otatools`. Snapshot
**`bringup-20261021-06`** has 1,168 locked projects and **13 reviewed patches**;
post-build audit PASS at 20:48:42 UTC. No full build is currently running.

`full-platform-02` had failed after 51m25s (29,432/33,922 last logged actions):
Make forced `webview`, `Backgrounds`, and `PhotoTable` to system, while Soong
retained product metadata/install paths. Snapshot 06 fixes actual Soong module
placement through product-scoped Java defaults; no certificate check or physical
partition limit was disabled. Only the device patch changed from 05; three new
projects are WebView patches, Backgrounds and PhotoTable.

Actual verification: **4,455 APK metadata records** agree, with only the three
expected partition fields changed. Old/new APK signatures verify and certificate
hashes are unchanged. Sixteen checker host regressions pass on Mac/Linux.

The **2,243,385,767-byte target-files archive** passes CRC for all 8,045 entries.
Its generated system/product images expand to the exact existing partition
sizes (3,196,059,648 and 327,155,712 bytes). Offline image checks confirm the
Samsung `/init -> /system/bin/init` layout, ARM64 init, selected compiled
libraries and configs, and ext4 INCOMPAT `0x42` / RO_COMPAT `0x7b` flags supported
by the pinned kernel sources. Boot packaging retains the expected Image hash,
v1/OS16/Samsung board/trailer and zero ramdisk. Vendor and DTBO hashes are unchanged.

**These are not runtime or installation approvals.** The experiment remains
outside the image, so the missing legacy networking backend is a known boot
blocker. Strict policy verification was rerun: still FAIL, 367 neverallow
diagnostics; all eight platform/system_ext/product CIL/mapping inputs were
hash-checked against the actual generated images. Diagnostic `-N` linkage is
not a strict pass. FBE, full post-APEX/runtime/HAL and recovery/OTA compatibility
remain unproven; Android-14-only installation/recovery guards remain unchanged.

The isolated production `NetworkStatsFactory.java` also compiles with actual
Soong SDK/compiler flags (exit 0), but this is not a full linked module or Java
regression build/run. See [latest status](reports/progress-20261021-evening.json),
[image archive](reports/target-files-20261021.json),
[actual filesystem checks](reports/native-layout-20261021.json), and
[image-policy correspondence](reports/image-policy-input-check-20261021.json).

## Earlier diagnostic full build and isolated networking work (history)

`full-platform-01` failed after 3h31m17s at kernel configuration, after
128,444/162,326 actions. With kernel sources present, Lineage ignored the mere
prebuilt declaration and attempted an unintended source rebuild. Samsung's
ANDROID_MAJOR_VERSION selector was unset, producing recursive sdcardfs Kconfig
inclusion. Snapshot **`bringup-20261021-05`** explicitly selects the previously
source-built, hash-pinned Image with `TARGET_FORCE_PREBUILT_KERNEL := true`.
Only the device patch changed from snapshot 04; all 1,168 projects and ten
patches passed audit at 06:23:30 UTC. No compiler/security checks were weakened.
The kernel is still **not rebuilt or proven conformant for Android 16**.

`full-platform-02` began at 06:23:35 UTC, October 21, requesting
`target-files-package otatools`. At 06:41 UTC it was running, with 5,595/33,922
remaining-build actions logged. This incremental percentage is not an overall
ROM-readiness percentage. Inspect the current log and `.exit` before starting
another build. These are diagnostic packaging targets, not approved installation
artifacts; the Android-14-only OTA/recovery guards remain intact.

[Isolated networking experiments](experiments/networking-20261021-01/) contain
13 selected changed/new files, not applied to the active build. A real qtaguid
parser passes 36 host cases; the DNS callback gate/resolver branch passes 35,
on both Mac and Linux. Twelve stats and eight DNS native object compilations
pass actual Soong flags for both ABIs, including CFI/APEX31 variants. This is
compile-only, not module linking or runtime proof. Four new Java accounting
regressions have not been compiled/run. The authoritative firewall/socket/API/
loader integration is still absent; never bypass BPF readiness as a substitute.
See [current build status](reports/progress-20261021.json) and
[networking evidence](reports/networking-20261021.json).

## Reproducible starting point

- Initial sync completed October 19 at 18:41 UTC, with 1,167 clean,
  revision-locked checkouts audited by `tools/audit.py`.
- Official manifest: `lineage-23.2`,
  `eabe68377217a88c81fa933db0136ea4146ff369`. Platform sources were synchronized
  October 19, not refreshed blindly during bring-up.
- The added AOSP VNDK 30 project raises the port manifest to **1,168 projects**.
- Current exact revisions and **thirteen** reviewed patches:
  `snapshots/bringup-20261021-06/{port-manifest.xml,source-lock.json,patches/}`.
  Snapshot 01 preserves the first nine; snapshot 02's Bionic scan buffer failed
  the libc stack-frame check and is historical, not the current replay target.
- `tools/audit-port.py` checked all 1,168 checkout HEADs, commit/tree objects,
  exact working-tree patch contents and internal-only object alternates.
  `port-audit.json` explicitly distinguishes clean trees from the thirteen reviewed
  patched trees; ignored binary inputs remain a separate checksum check.
- Device, kernel and vendor start at the 21 reference commits. The Image,
  DTBO and vendor inputs retain the published hashes; the kernel has **not**
  been rebuilt for Android 16.

Patch replay (after checking out the snapshot's exact base revisions):

```sh
python3 tools/apply-port.py TOP snapshots/bringup-20261021-06
```

The tool checks every base revision and patch checksum before changing a tree.
Identical already-applied patches are accepted; unrecognized edits or untracked
source files are refused. This does not sync sources, sign anything, or flash.

## Implemented first-stage changes

| Area | Observed problem in actual 23.2 sources | Change |
| --- | --- | --- |
| VNDK 30 | All included official manifests omit v30; product configuration fails with `VNDK version 30 not found`. v31-34 snapshots and `apex_vndk` support remain. | Add an independent checkout of AOSP `platform/prebuilts/vndk/v30` at `b2a975dfb122d37c37af780be63a9faf8d76d143` (also the peeled `android-14.0.0_r75` tag and the working 21 snapshot). Add `com.android.vndk.v30` to the VNDK APEX definitions. No ABI spoofing. |
| Audio | `FactoryHal.cpp` tries AIDL and HIDL 6/7, not 4. Samsung exposes HIDL 4.0. HIDL 4.0 interfaces/conversion utilities still exist. | Restore the real HIDL 4.0 client using current common client sources and keep the Java/native version lists synchronized. Compilation and runtime behavior still need validation. |
| Cgroups | v2 hierarchy/event assumptions remain; Android 16 moved descriptor parsing into `libprocessgroup/util/util.cpp` and introduced v2 system/app paths. | Product-gated cpuacct v1 lifecycle, real signaling and bounded EBUSY cleanup, with error propagation. Read the product descriptors in all clients; do not create v2 system/app paths for v1. |
| Cgroup mounts | cpuset now unconditionally uses `cpuset_v2_mode`, absent from this Samsung kernel. Default memory controller moved to v2. | Preserve supported v1 controllers; use `noprefix` on this product, restore the memory v1 descriptor at `/dev/memcg`, and apply ownership after mounting `/acct`. Unsupported controllers remain unavailable, not simulated. |
| ext4 quota | `fs_mgr::tune_quota` unconditionally requests project quota. | Preserve usr/grp quota; respect the existing `ro.gta3xlwifi.ext4_project_quota=false` product property to avoid making `/data` incompatible. |
| GPU accounting | Optional GPU BPF map users do not respect the product's eBPF capability property. | Report counters unavailable (`false`) in libmeminfo; do not wait for unsupported GPU BPF accounting in GpuWork. Rendering and Mali libraries are not replaced. |
| SELinux genfs | Lineage and stock vendor both label ISO/UDF roots. | Retain the existing product-specific M4 exclusion for those duplicate Lineage rules only. No neverallow checks or SELinux enforcement disabled. |
| Recovery helper | The hash-only static ARM32 helper cannot access current BoringSSL static library visibility. | Add only its source package to `libcrypto_static` visibility. **Its Android-14-only safety contract is intentionally unchanged.** |
| Spawn FD hygiene | Kernel 4.4 lacks `close_range`, used by CLAT/tethering's `POSIX_SPAWN_CLOEXEC_DEFAULT`. | Keep the syscall fast path; on ENOSYS/EINVAL, enumerate actual child FDs with raw getdents64 and set CLOEXEC. No allocator after fork/vfork, no RLIMIT-only scan; errors fail closed. Actual dup2 actions and parent FD flags are preserved. |

## Host/configuration findings

- `aosp_current` resolves to **bp4a** in `build/release/release_config_map.textproto`.
  `lunch lineage_gta3xlwifi bp4a userdebug` succeeds: Android 16,
  `BP4A.251205.006`, native ARM64 plus ARM32. The device lunch menu uses that target.
- Absolute `OUT_DIR` caused a Soong error in `continuous_instrumentation_metric_tests`
  when resolving `perfetto_trace_processor_shell`. `OUT_DIR=out` fixes it without
  removing tests; this is still the separate 23.2 checkout's output directory.
- The compiler cache must exist **before product configuration**: nsjail otherwise
  creates an empty regular file at its bind source. The empty placeholder has
  been archived and replaced with the intended independent directory. Setup and
  the build runner now create/check the cache directory.

## Tests and current compilation

- Bash/Python/XML syntax checks pass.
- Ten host cleanup scenarios test the **actual extracted v1 cleanup function**:
  successful removal, EBUSY retry, single-attempt/timeout behavior, missing
  hierarchy, signaling/permission errors and memory-controller cleanup.
- Four path assertions verify that v1 does not inherit v2 app/system directories.
- Seven real-Git patch-replay tests pass on both Mac and VM: replay/idempotence,
  local edit preservation, untracked files, revision mismatch, patch corruption,
  path traversal and duplicate entries.
- These injected-syscall host tests do **not** test real Android cgroup mounts,
  process lifecycles, FBE, rendering or networking.
- The Soong and Make/Ninja build graph has been generated successfully.
- `native-policy-03` reached native compilation, then stopped on the compiler
  cache bind-source problem described above. It did not finish the target set.
- **`native-policy-04` completed successfully**, exit 0, on October 20 at
  **17:50:42 UTC**. All **17,467 actions** completed in **22 minutes 9 seconds**.
  Completed targets: `libaudiohal@4.0`, `com.android.vndk.v30`,
  `gta3xlwifi_recovery_header_sync`, `selinux_policy`, `libprocessgroup`,
  `libprocessgroup_setup`, `libfs_mgr`, `libmeminfo`, `gpuservice`.
  The log and exit marker are under the separate 23.2 logs directory.
  **This is a successful targeted compile, not a complete ROM, actual-vendor
  policy/VINTF validation, or runtime hardware/encryption proof.**

## Actual-vendor/runtime follow-up

See [the detailed evidence and reproducible commands](reports/vendor-runtime-20261020.md).

- Extracted the checksum-verified **actual hybrid vendor image**, without mounts;
  all 41 SELinux/VINTF metadata files match the staged stock copies.
- `vendor-metadata-02`: **exit 0**, 1,985 actions, completed 18:31:50 UTC.
- Current static-metadata VINTF check: **COMPATIBLE / exit 0**, actual vendor plus
  real kernel config and inherited legacy FCM 3. This is **not** unmodified
  Android 16 kernel conformance or complete post-APEX validation; the activated
  APEX inventory does not yet exist. Kernel-FCM-version warnings are retained.
- Actual-vendor strict policy link: **FAIL**, compiler exit 255, **367 neverallow
  diagnostics**. Init-style `-N` linkage succeeds as a separate diagnostic only;
  the checker still returns failure. No source/enforcement setting was changed.
  Inherited permissive domains are `su` and `backuptool`, not newly added domains.
- **42 Linux host tests pass** on extracted production spawn helpers and dup2
  actions: real fork/vfork/exec, ENOSYS/EINVAL, high FDs above lowered soft/hard
  limits, parent flag preservation, intended inheritance, actual procfs checks,
  and fail-closed errors.
  Two Bionic native tests were added but have not run on the tablet.
- **Six CLI safety tests pass** on Mac/VM, including that runtime diagnostic
  success cannot override strict neverallow failure.
- `bionic-linker-01` stopped on the 4 KiB buffer's excessive stack frame, not on
  missing kernel APIs. The buffer is now 1 KiB; frame checks remain enabled.
  **`bionic-linker-02` completed successfully**, exit 0, 9,065 actions, 18:46:21
  UTC (8m03s): libc/linker/linkerconfig, both-ABI Bionic test binaries and ABI
  comparisons. This built snapshot 03; tests were not run on hardware.
  **`bionic-linker-03` also completed successfully**, exit 0, all **157 incremental
  actions**, **18:51:34 UTC**, 4m14s, for snapshot 04's extra procfs checks.
  Thus the latest patch state passes the requested cross-build; Android tests
  have not run on hardware. No job from these attempts remains running.

## Prioritized remaining work / no-go gates

1. **Complete actual-vendor security/contract validation.** Initial actual-vendor
   linkage and static VINTF checks are now recorded above. Review the strict
   cross-version neverallow conflicts and effective policy/security implications;
   repeat full VINTF with complete target-files/activated APEX metadata. A normal
   init-style link or platform-only policy build is not a full security pass.
2. **Real networking backend.** Current
   `packages/modules/Connectivity/bpf/loader/NetBpfLoad.cpp` explicitly rejects
   old kernels (4.9 minimum at its first check, then newer 4.14/4.19/5.4/5.10
   requirements according to platform level). `bpf/netd/BpfHandler.cpp` also
   requires modern kernel/cgroup support. The old networking patch does not
   apply: native BPF/DNS/netd files have moved, and the Java BpfNetMaps,
   NetworkStats and ConnectivityService APIs changed. Port iptables/qtaguid,
   accounting, UID/firewall rules, DNS access decisions and CLAT together with
   tests. Do not bypass the checks with false success or declare 4.4 supported
   just because user space compiles. A newer Samsung-driver-capable kernel is
   an alternative substantial project, not a generic-kernel swap.
3. **Bionic/ART/kernel execution.** ART still contains concurrent-copying/read
   barrier code and kernel capability selection; the generated product enables
   `ArtUseReadBarrier`. Verify the actual built runtime and both application
   ABIs. A real spawn-specific `close_range` fallback is now implemented and
   host-tested for Connectivity's native ClatCoordinator/netd TetherController
   callers; finish the cross-build and prove it under real Android policy and
   procfs. The public syscall itself remains unavailable on kernel 4.4. Fallback
   access/EMFILE failures stop the child rather than leak descriptors.
   ART's pidfd execution path has a fallback, but this is not a full syscall,
   Binder, seccomp or memory-management compatibility audit.
4. **Graphics/HALs.** Gralloc2 mapper/allocator fallback code remains in 23.2;
   that is encouraging source evidence, not Mali acceleration proof. Verify
   ARM32 TEE/HAL LLNDK symbols/namespaces and both graphics ABIs against real
   images, then rendering/readback and hardware on the tablet.
5. **FBE/recovery/OTA.** Current libfscrypt still parses `ice`/v1 for old shipping
   API levels and has corresponding tests. That does not prove Samsung
   Keymaster/Gatekeeper/MobiCore compatibility with Android 16. The existing
   `releasetools.py` and header helper still reject Android 16 intentionally.
   Do not widen the guard just to emit a flashable ZIP. Validate DE/CE and
   recovery, then port non-A/B hooks to `bootable/deprecated-ota` and validate
   installation/rollback behavior.
6. **Full images and release candidate.** Port the native power/wake integration,
   Wi-Fi-only behavior and selected app-layout patches as needed. Measure all
   fixed partition limits. Build target-files/OTA only after the critical gates;
   use the existing keys, unique build identity and adapted signature/image/
   VINTF validators. GApps remains optional and must be Android 16 ARM64.
7. **Physical test gate.** SHA-checked rollback inputs and fresh private data/EFS
   backup, explicit owner approval for installation/destructive operations,
   followed by controlled boot, encryption, networking, graphics, hardware,
   power and downgrade tests. No such installation is authorized by this report.
