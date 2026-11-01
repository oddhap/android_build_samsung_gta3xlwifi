# LineageOS 23.2 bring-up for SM-T510

## Latest status — October 21, 2026

**First complete diagnostic target-files build succeeded:** `full-platform-03`,
`target-files-package otatools`, exit **0**, 20:39:15 UTC, 29m21s.
Snapshot **`bringup-20261021-06`** locks 1,168 projects and **13 exact patches**;
the post-build audit also passed at 20:48:42 UTC. No build remains running.
Kernel/DTBO/vendor inputs are unchanged; the existing source-built bring-up
kernel was retained, not rebuilt or certified for Android 16.

The CRC-verified target-files archive is **2,243,385,767 bytes**, archived under
`/srv/android/artifacts/lineage-23.2-arm64/diagnostic-full-platform-03/` on the VM.
It includes complete system/product/boot/recovery/vendor/dtbo/cache images.
Declared physical partition bounds, Samsung system-as-root, ARM64 init,
selected actual libraries/configurations and ext4 feature compatibility with
pinned kernel sources pass offline checks. It is **not a TWRP installer,
release-signed candidate, boot-tested or installation-approved ROM**.

The prior APK layout failure is fixed with product-scoped Soong defaults, not
by disabling Make/Soong checks: all **4,455 metadata records** agree and actual
before/after APK signatures verify with unchanged public development certificates.
Strict checks against actual vendor still **FAIL: 367 neverallow diagnostics**,
now reconfirmed against policy inputs read from the generated images.

Networking changes remain [isolated experiments](experiments/networking-20261021-01/),
not included: 36 qtaguid and 35 DNS host cases and 20 native object compiles pass.
The production Java factory now compiles in isolation with real Soong SDK flags;
the four new Java regressions are still uncompiled/unexecuted. Complete
firewall/socket/loader/API integration remains a known boot blocker. Full
APEX/runtime/HAL/FBE and safe OTA compatibility remain open. **Do not flash.**
See [current status and artifact evidence](reports/progress-20261021-evening.json).

## October 23: FunctionFS labels + empty-context audit boundary fix

[Combined five-file capability patch](experiments/kernel-functionfs-20261023-01/)
contains NNP02 plus explicit FunctionFS bit12/GENFS/per-inode labeling; **replaces,
not stacks on**, NNP-only. Context=/NONE/unknown mounts cannot be relabeled per
file. Existing owner/POSIX/MAC gates remain; no new policy grants. An extracted
production audit underflow for non-null/size0 is fixed by a size guard; not a
proven live syscall exploit. Sanitizer reproduction retained.

**340 mount/oracle + 896 actual VFS/SELinux authorization paths PASS** Mac/Linux
sanitizers/Werror; object/AVC/parser/lock fixtures, not kernel/USB execution. NNP
16,384/bitmap8,192 regressions still pass. Full fresh kernel **exit0 18:13:51 UTC**;
actual capability12 mount/label/load and VFS/FFS/NNP/qtaguid links verified.
Exact ELF→Image **25,411,320 bytes / 7250adb995df7cc2d599f38f5829cf92bec9679a2dbe914c264741f604c1c6f9**.

Audit PASS **18:15:39 UTC**, unchanged snapshot06 / 1,168/13. Original prebuilt/
vendor/DTBO remain intact. Actual queried init relabel TE is NOT granted; no
permissions forced. Remaining policycaps/strict policy/networking/USB/runtime/
FBE/recovery/install validation still block flashing. **NOT FLASH READY.**
[Evidence](reports/kernel-functionfs-20261023.json).

## October 23 next kernel step: NNP/nosuid + foreign-mount protection

[Final isolated revision02](experiments/kernel-nnp-transition-20261023-02/) implements
capability bit **5 / process2**, both-required AVC permission checking, original
bounded fallback, capability reload/reset and foreign-mount namespace detection.
Preserved USER_NS=n config; unsupported USER_NS=y fails compilation explicitly.
All 56 old class/permission tables and ordinary exec checks remain unchanged.

**16,384 extracted decision cases + 8,192 load-helper combinations PASS** Mac/Linux
ASan/UBSan/Werror, separate from **full kernel exit0 17:54:53 UTC** and actual ELF
namespace/AVC/bounded/capability/callsite proof. Exact ELF→Image reconstruction:
**25,411,320 bytes**, SHA `88b9a98b42caa89f9848c7d44a89da58b23538b4ecb57c7d29ab9cd40ff9c4a5`.
These are fixtures/link proof, **not kernel/AVC/exec/runtime approval**.

Source audit PASS **17:55:47 UTC**, unchanged snapshot06 / 1,168/13. Original
prebuilt still used. No security pass, full networking/backend, remaining policy/
capability/runtime/install validation and owner-approved hardware plan remain.
**NOT FLASH READY.** [Evidence](reports/kernel-nnp-transition-20261023.json).

## October 23 next step: isolated private UWB namespace split

A [two-file metadata patch](experiments/vendor-uwb-namespace-20261023-01/) separates
Samsung's private UWB types from Android 16. It preserves every vendor rule and
neverallow, with byte-exact inverse and actual Git forward/reverse replay.
Strict production-policy diagnostics go **281 → 279**, no new identities; still
FAIL, not approval. No actual vendor image or active Android input is changed.

The source-locked libsepol inspector compares **505 domains / 2,020 queries per
binary**. No new unconditional service_manager add/find pairs appear in the four
UWB type mappings. The accidental platform_app framework-registration grant is
removed; legacy pairs narrow and require client/runtime review. Constraints,
conditional state and live kernel/endpoint behavior are not proven.
**18 fixture tests PASS Mac/Linux.** Source audit PASS **17:07:15 UTC**, unchanged
snapshot 06 / 1,168/13. Original user policy remains 281; complete userdebug images
remain 367. Full networking/security/runtime/install blockers still prevent flashing.
[Evidence and integration limits](reports/vendor-uwb-namespace-20261023.json).

## October 23: actual policy-record reader incompatibility fixed in isolated kernel

Actual Android 16 version-30 policy includes native nlmsg-kind-3 records with
netlink_xperm capability **off**. The preserved Samsung reader's Android-M
heuristic consumes **41 of 42 bytes**, switches encoding and misaligns the next
record. A [three-file isolated fix](experiments/kernel-policy-reader-20261023-01/)
parses the inactive modern encoding and **rejects an active unsupported netlink
capability**, rather than pretending modern enforcement exists. No policy or
neverallow rule is removed. The old reader remains a recorded failure.

Production and userdebug actual-record suites each pass **25 cases**; the extracted
real capability guard passes **8,192 fixture combinations**. Complete independent
kernel build passes **16:29:25 UTC**, same config, 25,443,704-byte Image with exact
ELF reconstruction verified. **Not actual kernel execution or whole-policy load**;
new Image is NOT in Android prebuilt/ROM. Source audit PASS **16:36:09 UTC**:
unchanged snapshot 06 / 1,168 projects / 13 patches, no promotion.

A fresh isolated **user policy-only build** passes (2,546 actions), with no
permissive domains in actual-vendor diagnostic linkage, but strict linkage still
**fails 281 diagnostics**. Original complete userdebug images still fail 367.
The difference is a build-variant comparison, not 86 security fixes. Complete
networking, strict policy/runtime/FBE/recovery/OTA still block flash readiness.
[Evidence, tooling failures and limits](reports/policy-kernel-reader-20261023.json).

## October 22 evening: source-built opt-in socket-owned tag kernel

The [final persistent-tag experiment](experiments/qtaguid-persistent-20261022-02/)
adds a root/CAP_NET_ADMIN-gated private ioctl, legacy behavior unchanged by
default, inode-file lifetime ownership without process-list cleanup, safe retag
and ref retirement, and kernel-side INET/INET6 family rejection. The transport
requires a real native/compat-compatible ACK, with no old-kernel fallback.
**45,953 assertions** from extracted production kernel functions and **1,825
transport assertions** pass under ASan/UBSan. Kernel/driver primitives are fixtures,
not real device/race testing. Actual Netd ARM64 CFI object compilation also passes.

**Complete independent kernel build PASS**, exit 0 21:13:05 UTC, unchanged
baseline config. The new 25,410,936-byte Image has linked native/compat ioctl
pointers and byte-identical ELF reconstruction validated. It is diagnostic output,
**not installed in Android prebuilt/ROM**, with explicit distinct build-source
provenance. Existing Image/DTBO/vendor, full-platform-03 and preserved 21/TWRP/data
remain untouched. Source audit PASS 21:14:13 UTC: unchanged 1,168/13 snapshot 06.

No complete networking/backend readiness is claimed: live owner, permissions/CLAT/
budgets, 12-chain packet enforcement, VPN/LNA/interface, quota, Java/loader and
strict policy/FBE/recovery/OTA still block deployment. No BPF readiness is forged.
See [build/source/ELF evidence and remaining limits](reports/qtaguid-persistent-20261022.json).

## Earlier October 22: qtaguid transport and actual kernel final-close evidence

[New isolated qtaguid transport](experiments/qtaguid-socket-20261022-01/) now
implements real device/proc command I/O with sysfs/passive-mode checks, stable
duplicated socket FDs, full tag encoding and fail-closed error/short-write paths.
**1,607 host assertions PASS** with ASan/UBSan, real IPv4/IPv6 TCP/UDP and FD reuse;
driver/sysfs/proc I/O is a fixture, not hardware validation. Actual Netd ARM64 CFI
object compilation PASS; no linked/wired Netd owner or authorization endpoint yet.

The suspected missing final-close hook is resolved: **it already exists in the
preserved linked vmlinux**, for both IPv4 and IPv6. Reconstructing Image outside
preserved directories matches the exact baseline digest. No kernel patch/build
was needed. This does **not** solve Netd restart persistence: device-session
cleanup discards its tags even for live app sockets. Permissions/budgets, that
restart behavior, full packet/backend integration and SELinux access remain
unproven. No BPF readiness bypass or promotion into the ROM was added.
Post-work audit PASS **20:21:28 UTC**: still 1,168 projects / 13 exact patches.
See [source, binary and test evidence](reports/qtaguid-socket-20261022.json).

## October 21 isolated networking increment

The [new UID-policy experiment](experiments/uid-policy-20261021-01/) implements
candidate values for **all 12 A16 firewall-chain APIs**, including per-user core
exemptions, separate metered allow/user-deny/admin-deny and exact reason bits. **192
API/state checks and 526,888 extracted native-DNS oracle comparisons** pass on
Mac/Linux with ASan/UBSan. Linux additionally passes **8,336 extracted Java
reason/decision comparisons**. Map storage and fixed A16 SDK metadata are fixtures;
these are not Android module/JUnit or packet-enforcement tests.

The prior experimental DNS helper now also **compiles and links completely for
ARM64 CFI/APEX31 and ARM32 CFI** outside TOP. Strict linker flags are retained;
existing versioned exports, SONAME and dependencies are unchanged, with only the
private V2 callback export added. Full header ABI and Android execution remain
unproven. The new policy source compiles with real primary-ABI Netd CFI flags,
but no linked Netd owner, kernel installer or readiness integration exists yet.
The experiments are not applied to the ROM. Post-work source audit PASS at
21:29:36 UTC: still 1,168 projects / 13 exact patches. See
[network-policy evidence and remaining implementation boundaries](reports/network-policy-20261021.json).

## Previous targeted results — October 20, 2026

Status on October 20, 2026: **source sync complete; first port patches captured
and first targeted native/policy build completed successfully**. Initial sync and audit
completed October 19 at 18:41 UTC (exit 0), with 1,167 clean, independent,
revision-locked checkouts. The VNDK 30 addition raises the port to 1,168 projects.
Product configuration succeeds as Android 16 / LineageOS 23.2, ARM64/ARM32,
using `bp4a`. `native-policy-04` completed all 17,467 build actions with exit 0
on October 20 at 17:50:42 UTC (22 minutes 9 seconds).

Follow-up: actual-vendor static VINTF is compatible within the inherited legacy
FCM profile, but **strict cross-version policy verification fails** (367
neverallow diagnostics); init-style linkage is a separate successful diagnostic.
Full post-APEX/kernel/runtime validation remains open. A real spawn FD-hygiene
fallback now passes **42 Linux host tests**. `bionic-linker-02` successfully
built the runtime and both-ABI Bionic tests (9,065 actions). `bionic-linker-03`
also completed successfully for added procfs safeguards: exit 0, 157 incremental
actions, 18:51:34 UTC. No build from these attempts remains running. At that checkpoint no full target-files build existed.

See [the concrete compatibility report and priorities](COMPATIBILITY.md),
[actual-vendor/runtime evidence](reports/vendor-runtime-20261020.md),
[current thirteen-patch snapshot](snapshots/bringup-20261021-06/) and
[`tools/build-bringup.sh`](tools/build-bringup.sh).

Verified host: Ubuntu 22.04.5 x86_64, 24 vCPU, approximately 62 GiB RAM and
31 GiB swap. `/srv/android` had approximately 589 GiB available before setup.
The existing 21 kernel, DTBO and vendor input hashes matched the source lock.
Preserved 21/TWRP checkouts and signing keys were not changed. The earlier
`Operation not permitted` SSH failure no longer blocks this session.

The target is a source-built ARM64/ARM32 device port for `gta3xlwifi`, based on
the working LineageOS 21 release `gta3xlwifi.arm64.20261015.191854`. The platform
branch is explicitly `lineage-23.2`; the setup never selects a newer release.

## Launch the prepared setup

From the Mac project directory, in a terminal with working SSH access:

```sh
bash tools/setup-lineage23-remote.sh
```

This uploads the three setup files and starts a detached job on the build VM.
The SSH private key is used only by SSH/SCP and is not uploaded. Follow progress:

```sh
ssh -i .private/build_ed25519 builder@192.168.0.124 \
  'tail -f /srv/android/logs/lineage-23.2-arm64/setup-latest.log'
```

The process exit code is written to `logs/lineage-23.2-arm64/setup.exit`. After
a package installation or sync failure, inspect the log and run the launcher
again. Source sync retries up to five times, with delays of 60, 240, 540 and
960 seconds; it never uses force-checkout/reset flags. The detached job survives
SSH disconnection, but not a VM reboot. Missing packages are installed only if
passwordless `sudo` is available;
otherwise the job prints the package list and stops. Install those packages in
an interactive SSH session and restart it. Git author identity must already be
configured. The setup does not edit global Git, shell or Java configuration.

| Location under `/srv/android` | Purpose |
| --- | --- |
| `src/lineage-23.2-arm64` | Independent source checkout and `out/` |
| `ports/lineage-23.2-arm64` | Setup code, captured manifest HEAD and `env.sh` |
| `artifacts/lineage-23.2-arm64` | Locked manifest, input hashes and setup report |
| `logs/lineage-23.2-arm64` | Detached setup log and exit status |
| `ccache-lineage-23.2` | Separate compiler cache, maximum 30 GiB |

The initial disk check requires 450 GiB free. This is a planning allowance,
not a measured size for this device. Preflight on October 19 confirmed approximately
589 GiB free after disk expansion; recheck before compilation.
Platform checkout objects are independent of the preserved 21/TWRP trees and
their shared reference cache. Repo's own object sharing inside the new checkout
is allowed. No existing source tree, output, firmware, key or backup is removed.

The official manifest branch HEAD is fetched at first execution, retained for
resuming that setup, and used to initialize Repo. Projects use the revisions
selected by that manifest when synchronized. After synchronization,
`platform-manifest.xml` locks each project to its actual commit. `audit.py`
checks every checkout HEAD, commit/tree object, clean working tree and object
alternate before the completion marker is written. Subsequent setup launches
leave a completed checkout alone; upstream refreshes are a separate operation.

Device/kernel/vendor projects start at the exact known Android 14 baseline
commits in `tools/gta3xlwifi.xml`. The kernel Image, DTBO and hybrid vendor are
copied from the working 21 device tree only after checking all three SHA-256
values against the published source-input lock. These are **unvalidated Android
16 inputs**, not a newly compiled kernel. Stock metadata is copied and compared
file by file. Platform patches from 21 are not applied by setup.

## Findings and first porting work

[COMPATIBILITY.md](COMPATIBILITY.md) records the implemented VNDK/audio/cgroup/
quota/accounting changes, host tests, current build attempt and remaining gates.
The highest-priority unresolved runtime issue is real legacy networking against
23.2's reorganized BPF/netd/DNS/Java stack. FBE/recovery and the Android-14-only
installer guards are also unresolved; they have not been bypassed.

The added VNDK 30 input is pinned in `tools/legacy-vndk.xml`. The original setup
launcher intentionally remains a baseline-source setup, not an automatic
application of all bring-up patches.

Actual configured limits from `BoardConfig.mk`:

| Partition | Bytes |
| --- | ---: |
| boot | 33,554,432 |
| recovery | 47,185,920 |
| system | 3,196,059,648 |
| vendor | 343,932,928 |
| product | 327,155,712 |
| cache | 159,383,552 |

## First compilation after source preparation

Use a fresh Bash shell on the VM:

```sh
source /srv/android/ports/lineage-23.2-arm64/env.sh
source build/envsetup.sh
list_releases lineage_gta3xlwifi
```

The verified selection for this source lock is
`lunch lineage_gta3xlwifi bp4a userdebug`. Make sure the independent compiler
cache directory exists before sourcing envsetup/product configuration.
`build-bringup.sh LABEL [MODULE ...]` takes an exclusive build lock and records
`LABEL.exit`. It compiles only the requested targets; no signing or flashing.
Check the current build log before launching another attempt. Diagnostic
`target-files-package otatools` builds may reveal additional compile/package
blockers, but do not override failed security checks or approve installation.
Use the checkout's bundled Java toolchain. A `bacon` ZIP alone is not a release
signed with the owner's keys. No Android 14 GApps package is suitable for 23.2.

No device installation is part of this environment setup. Android 16 recovery,
data preservation and downgrade behavior remain untested. Keep the 21 ROM,
recovery, vendor, existing signing keys and private backups available.

## Primary references

- [Official 23.2 manifest](https://github.com/LineageOS/android/blob/lineage-23.2/default.xml): Android 16 tag `android-16.0.0_r4`, default `lineage-23.2`, deprecated OTA project present when inspected October 19.
- [23.2 envsetup](https://github.com/LineageOS/android_build/blob/lineage-23.2/envsetup.sh): product/release/variant lunch syntax and `list_releases`.
- [AOSP host requirements and packages](https://source.android.com/docs/setup/start/requirements): x86_64 Linux, source/build disk allowance and bundled toolchains.
- Local baseline: `../BUILD_ARM64.md`, `../docs/gapps-arm64-build.md`, `../lineage-21/notes/source-inputs.lock.json`, `../lineage-21/notes/source-lock.json` and `../../device/`.

Initial source sync, audit and input staging completed successfully. Host tests
and build results are tracked in [COMPATIBILITY.md](COMPATIBILITY.md); they do
not establish boot, runtime hardware support, Android 16 FBE or a signed release.
