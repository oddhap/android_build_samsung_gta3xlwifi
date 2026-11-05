# LineageOS 24.0 device port — Samsung SM-T510

Active development target: LineageOS 24.0 / Android 17, ARM64 with ARM32 apps,
`gta3xlwifi`, physical non-A/B partitions. This is an unfinished source-built
device port. No installation candidate is approved.

The official manifest was inspected at
`b51a0c449a3279ca55fb6d4d91d2143e42e2fff5` (`android-17.0.0_r1`).
The official `aosp_current` release alias resolves to `cp2a` in the inspected
build/release revision `c85f4aebe46714235599a9bd6430a0fe30c6e8d5`.
Use the alias in a fresh build shell rather than the old `bp4a` target.

The initial 23.2 port patches compiled successfully on Android 17 in
`native-policy-20261101-01` (exit 0, followed by full source audit). Selected
ARM/ARM64 ELF outputs are recorded in the reports; this is build/link evidence.

Active snapshot **port-20261103-07** locks 1,243 projects and **15 exact patches**.
It adds a source backport of policy 30.0 compatibility data and generator modules,
with the frozen API30 source copied verbatim from the pinned prior platform.
The framework advertises 30.0 only for gta3xlwifi. Device inputs are separately
pinned by commit. Dedicated compatibility compilation and structural tests passed;
strict actual-vendor policy is not approved. A diagnostic full build has succeeded;
installation remains blocked.

The cgroup port retains cpuacct v1 process groups, mounts real supported v1
controllers, skips v2 subtrees only for this product, loads product profiles last,
and returns `EOPNOTSUPP` for the new clone-into-v2 API. Its Android 17 zygote
callers and runtime behavior require further investigation. Host cleanup/path
checks are separate from Android execution. Optional GPU BPF accounting still
reports unavailable, rather than invented counters. Existing safety/installer
and strict SELinux checks remain enforced.

## Current build status — November 3

The first full `target-files-package otatools` build completed exit 0 in 4h46m51s
(183,167 Ninja actions), followed by the complete source after-audit. Its 2.31GB
archive is preserved by digest. Samsung image/header/kernel/vendor/DTBO geometry
and selected ARM32/ARM64 ELF checks passed, but OTA metadata incorrectly selected
A/B. Device `2f649d06fec3318926c61aaf7a5fa3f40aa9f266` explicitly sets non-A/B.

That non-A/B attempt reached packaging but failed when stock recovery-patch
creation tried writing a replacement recovery into an absent generated VENDOR
filesystem. The hybrid device preserves its actual vendor image and installed
TWRP. Snapshot07 adds product-scoped preservation metadata, omits multistage
support, skips generated recovery-replacement resources and rejects two-step OTA
options for this product. Other products retain their exact generator outputs
in host fixtures. Eight layout tests and five preservation test groups pass on
Mac/Linux. The generic non-A/B OTA recovery-patch assertion and Android14-only
device installer guard remain in place: no installable OTA is created.

Snapshot07 audits 1,243 projects and 15 exact patches; only build/make changed
since snapshot06, and all project revisions are identical. The ensuing build was
`full-targetfiles-preserve-20261103-02`, followed by `post-preserve-20261103-02`;
both are complete as recorded below. Inspect logs/exit files and build.lock
before editing TOP. The post job validates layout/geometry, archives the result
and runs static packaged-APEX/actual-vendor VINTF checks after successful build.

The first archive passes the AOSP `apexd_host` offline simulation with **39** real
factory packages and the actual MTP vendor. All 39 payloads are ext4. The actual
VNDK30 package contains 287 ARM32 and 287 ARM64 ELF libraries with matching
class/machine IDs. This is neither full ABI nor device activation/mount proof.
The carried legacy FCM3 kernel profile is not unmodified Android17 kernel
compliance. See [full-build evidence](reports/full-build-20261103/).

Strict production/vendor policy still fails with 322 diagnostic blocks. Kernel
policycap enforcement, complete legacy networking and Android17 FBE/recovery/
installer/rollback checks remain gates. No experimental kernel/network code is
in the active prebuilts. No signing keys or tablet partitions are touched.

## Completed non-A/B package checkpoint

`full-targetfiles-preserve-20261103-02` completed exit 0 in 8m01s with the full
1,243-project/15-patch after-audit. `post-preserve-20261103-02` also completed
exit 0: physical non-A/B metadata, image geometry and input identities, absence
of automatic recovery replacement resources, selected multilib ELF checks and
39-package offline factory APEX/actual-vendor VINTF all passed. The preserved
archive digest is `5d6d30884abdf5c9cd2ea1680961005f681598a508bcb0937d6ebb27bebc3b45`.
See reports/nonab-preserve-20261103. No installable OTA, runtime or flash approval.

A read-only declaration audit is saved in experiments/kernel-surface-20261103-01.
It identifies additional kernel review areas; table entries do not prove hooks.
No kernel source, configuration, Image or device was changed by that audit.
The owner renewed the flashable-test-candidate goal on November 3. The isolated
kernel work below resumes that effort; the Android build inputs remain pinned.

## Workspace and server

Local workspace: `/Users/oddi/Documents/Samsung-Lineage24`.
Main Git checkout: `integration/`; device checkout: `device/`.
The local `archive/` retains prior handoff, selected source/work files and a
compressed copy of server port inputs; private keys are not copied or published.
SSH uses the existing key in the old workspace, through SSH only.

Server paths use `lineage-24.0-arm64` under `/srv/android/{src,ports,artifacts,logs}`.
Compiler cache: `/srv/android/ccache-lineage-24.0`.
The explicitly requested migration deletes the five old 23.2 directories only,
after checking the 13 active patch hashes and absence of protected-tree object
alternates into 23.2. LineageOS 21, its Git reference cache, TWRP, original kernel,
firmware, signing material and device data remain protected.

Setup pins the manifest HEAD, all modified platform project revisions,
device/kernel/vendor baselines and real VNDK30. It syncs independent objects,
records a full locked manifest, audits clean sources, stages hash-bound binary
inputs, applies the port and audits the full patched tree. It then runs inherited
host regressions and product configuration. Logs and exit files distinguish all
stages. A clean-source sync marker alone is not a successful port validation.
No ROM is signed, installed or flashed by setup.

## Remaining compatibility gates

The inherited [isolated experiments](experiments/) remain work in progress.
The final networking/kernel graph also has a new Android 17 isolated rebase;
old Android 16 diagnostics and counts are historical. Regenerate policy,
networking and runtime evidence against Android 17. No experiment Image is
promoted into the device prebuilts. Keep the combined FunctionFS/NNP patch graph.

Strict actual-vendor SELinux, whole-kernel policycap semantics, legacy networking,
zygote/cgroups, Bionic/ART/Binder, HAL/APEX/both ABIs, graphics, Samsung TEE/FBE,
recovery/OTA and physical partition sizing remain gates. Existing Android 14
GApps and recovery encryption results are not Android 17 validation. No neverallow
or enforcement bypass is authorized. Hardware installation requires a concrete
candidate, verified private backup/rollback plan and separate owner approval.

## November 1: selected MTP vendor input

The owner explicitly selected the updated LineageOS 21 vendor image containing
the FunctionFS MTP USB init fix. Sparse SHA-256:
`a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a`.
The device OTA input guard and setup now pin that same digest; the Android 14
installer restriction remains. The observed initial failure was an input hash
mismatch after successful sync and clean audit of all 1,243 projects. The failed
exit files are archived in the server logs before recovery. Only the reviewed
device commit is updated, followed by a fresh full clean audit, input staging
and the normal patched-tree validation. Android 14 MTP transfer evidence is
recorded separately and does not certify Android 17 USB functionality.

The active snapshot is now `port-20261101-02`: full Git object IDs make exact
diff hashing independent of repository size and `core.abbrev`. All 13 patch
hunks are unchanged from snapshot 01. Eight replay-safety tests pass, including
changed abbreviation settings; checksum, revision, untracked-file, local-edit
and path/duplicate rejection checks remain. Historical snapshot 01 is retained.

## First Android 17 native compilation

`tools/build-bringup.sh NEW_LABEL [MODULE ...]` performs a full source audit and
checks all three binary input digests before starting the named module build.
It holds build.lock, refuses reused labels and audits again on successful exit.
The default target set covers Samsung Audio HIDL 4.0, real VNDK30, cgroups,
filesystem/memory/GPU support, Bionic/linker/linkerconfig and platform policy.
It does not package or sign a ROM or contact the tablet. The first attempt is
`native-policy-20261101-01`; inspect its log/exit and report before further work.
Do not modify sources until the build has stopped. Platform-policy compilation
alone does not establish strict compatibility with actual Samsung vendor policy.

## Actual-vendor checks and policy30 source backport

`vendor-metadata-20261101-01` built checkvintf, manifests and matrices successfully.
The extracted MTP vendor image is hash-verified in sparse and raw form. The
initial actual-vendor VINTF check fails: policy30 was dropped from the platform,
and five legacy HAL instances no longer appear in current framework matrices.
No requirements were removed and no artificial activated-APEX inventory was made.

An isolated 30.0 mapping composition reaches strict policy checking but fails
with 407 neverallow diagnostics. See experiments/policy30-20261101 for exact
inputs, repro tool and limits. The ensuing source backport restores 413 exact
reference files, adapts existing 31.0 generator modules for 30.0 and selects the
real map modules in the device product. No current allow/neverallow rule is
edited. Snapshot03 was an incomplete capture stopped by frozen-file EOF style;
snapshot04 preserves the original bytes and complete hash audit. Security checks
and exact source comparisons are unchanged.

`policy30-build-20261101-01` compiles the maps and upstream compatibility tests.
The upstream structural compatibility test is distinct from the strict actual-
vendor neverallow probe; success there cannot approve Samsung policy or boot.
Legacy HAL metadata restoration, strict conflict resolution, full networking,
kernel policycaps and Android execution remain outstanding.

## Verified compatibility compilation and remaining strict failure

`compatibility-build-20261101-03` completed exit 0, followed by a successful
full audit of 1,243 projects and 15 exact patches. Snapshot05 adds the actual
Treble30 test modules; the earlier unknown-target failure is retained. Device
commit `9c13bd07a68ec7857d8cbd5e4df075fdd966e433` restores the pinned legacy
FCM5/6 contracts and their retired kernel modules without dropping requirements.

The actual MTP vendor metadata check now reports COMPATIBLE / exit 0. Activated
APEX inventory is still absent; this covers currently built metadata only. The
strict actual-vendor policy check still fails with 407 neverallow diagnostics.
No allow/neverallow, enforcement setting or original vendor image was changed.
Evidence is in [reports/compatibility-20261101](reports/compatibility-20261101/).

`tools/build-user-policy.sh policy-user-20261101-01` is running against snapshot05
in a fresh `out-policy-user-20261101-01`, using the same build lock and source
audits. This is a production-policy comparison, not a ROM or a security fix.
Inspect its exit file before interpreting results or starting another build.

A serialized `continue-diagnostic-build.sh` continuation waits for that policy
runner's successful exit and after-audit, records the strict actual-vendor result
from its isolated output, checks build lock/free space, then runs
`full-targetfiles-20261101-01` (`target-files-package otatools`) against snapshot05.
It stops on prerequisite/tool errors and labels the package diagnostic. A strict
policy failure remains a failure even if full compilation succeeds. It generates
no OTA and performs no release signing or tablet access. Inspect both continuation
and full-build logs/exit files; a queued continuation is not a started full build.

The [guarded netlink candidate](experiments/kernel-netlink-20261101-01/) has exact
partial-tree provenance and sanitized host helper/AVC fixture checks. It remains
isolated, with capability9 rejected by the policy loader, and no new kernel Image.

## November 2: production-policy result and corrected continuation

The original production-policy build completed exit 0 (18m11s) with the full
1,243-project/15-patch after-audit. Its continuation stopped before starting any
full build: `selinux_policy` did not install the selected policy30 map modules in
the isolated output, and the actual-vendor checker correctly rejected the missing
input. `full-targetfiles-20261101-01` was never started.

`build-user-policy-maps.sh policy-user-maps-20261102-01` explicitly builds the
five map modules plus policy in that unchanged, audited production output. A new
`continue-diagnostic-build-20261102-01.sh` waits for its success, checks the actual
production/vendor combination, then starts `full-targetfiles-20261102-01`. The
continuation now also records its own exit. All original results are retained.

The [UWB namespace experiment](experiments/vendor-uwb-namespace-20261101-01/) was
rechecked against the actual Android 17 userdebug policy: 407 to 405 strict
diagnostic blocks, exactly two removed and none added. Only vendor CIL changes
among the ordered policy inputs. This remains an isolated metadata candidate,
with no runtime/effective-permission or image integration approval.


## November 3: isolated mmap enforcement and complete kernel compilation

The renewed test-candidate work adds an actual `FILE__MAP` hook check in an
[isolated candidate](experiments/kernel-mmap-20261103-01/). Sanitized host checks
of actual helper bodies pass on Mac and Linux. The complete independent kernel
build also passes, with exact preserved config, 60,331-file tracked-source
before/after audits and unchanged protected inputs. All 8,408 exported symbol
CRCs match the original. These static checks do not establish live enforcement
or module ABI compatibility. No experimental Image enters Android prebuilts.

The common-prefix insertion moves permission bit positions and needs the full
header/kernel rebuild recorded here. Netlink capability9 rejection remains;
coherent policy generation across netlink/AVC reloads and other active policycap
hooks are still required. Actual compile commands do not define Samsung
CONFIG_ALWAYS_ENFORCE in either the preserved AVC or this standalone build.
Strict vendor policy, complete networking and Android17 installer/FBE/rollback
remain open. The built ROM and kernel remain diagnostic, with no installable OTA.


A subsequent [generation-binding candidate](experiments/kernel-xperm-generation-20261103-01/)
returns EAGAIN when an access vector and freshly computed extended permissions
belong to different policy generations, before cache insertion or permissive
handling. Initial policy publication is protected by the policy write lock.
Mac/Linux sanitized fixtures and a second complete standalone kernel build pass,
including full tracked-source/protected-input audits and identical config/export
CRCs. This does not yet bind the complete netlink skb to one policy mode and
generation. Capability9 remains rejected, and Android prebuilts are unchanged.


## November 3: whole-skb netlink snapshot candidate

The [netlink snapshot candidate](experiments/kernel-netlink-snapshot-20261103-01/)
captures one policy generation/mode per skb, uses immutable message tables and
checks both cached and freshly computed base/extended AVC decisions against that
generation. Successful paths revalidate before returning; reloads return EAGAIN.
The legacy kernel-SID exemption is preserved. No policy lock spans AVC or audit.

The complete standalone kernel build and Linux fixtures pass with full tracked-
source/protected-input audits and unchanged config/export CRCs. Mac/Linux test
inputs and results match. Data-only target compilation supplies actual UAPI
constants to host fixtures. This is not live reload, boot or hardware validation;
capability9 rejection remains and no Image is promoted to Android prebuilts.
Active extended socket classes and other enabled enforcement gaps are next
kernel work, alongside the unchanged strict vendor-policy/network/installer gates.


The [extended socket candidate](experiments/kernel-extsock-20261103-01/) now ports
the actual classifier and create/label/bind integration for this legacy UAPI,
including ICMP and enabled Phonet. It appends 26 classes without moving existing
class/permission IDs, loads real cap2 and corrects its sysfs name. Exact cap-off
selection and supported-UAPI modern selection pass host comparisons. SCTP stays
disabled and enabling it stops compilation until its extra hooks exist.
The whole kernel and Linux fixtures pass with preserved config/export CRCs and
complete tracked-source audits; Mac/Linux source hashes/results match. This is
not live protocol or boot validation. Inotify, prlimit and perf mediation still
need work; no experimental Image or weakened policy enters the ROM.


The [prlimit candidate](experiments/kernel-prlimit-20261103-01/) completes the
source path from syscall read/write flags through preserved DAC, a real initialized
and registered LSM chain, and SELinux getrlimit/setrlimit mediation. The original
hard-limit body is unchanged; native and compat syscall tables share the updated
body. Whole-kernel compilation and Mac/Linux actual-body fixtures pass with full
source audits, preserved config and identical original exports/CRCs. This remains
an isolated diagnostic candidate. Enabled inotify and perf mediation, strict
vendor policy, complete networking and Android17 installer/FBE remain gates.


## November 4: enabled inode-watch mediation

The [notify candidate](experiments/kernel-notify-20261104-01/) mediates both enabled
inotify and dnotify paths through a real LSM/SELinux watch/watch_reads check.
Inotify authorizes its canonical mark target and preserves path/fd release on
errors; dnotify authorizes before allocation and preserves watch removal. The
inode-only profile rejects unsupported mark/permission modes, and enabling
FANOTIFY stops compilation until those paths are implemented. Common file bits
move; the complete kernel/header rebuild and export checks are recorded.

The whole kernel and Linux fixtures pass with full source audits and preserved
config/export CRCs. Mac/Linux fixture sources, runner and results match. The
complete inotify syscall and dnotify authorization prefix use fixture backends;
no live watch/boot or full mark-lifecycle validation is claimed. Perf, strict
vendor policy, complete networking and Android17 FBE/installer remain gates.


## November 4: perf event mediation and module ABI review

The [perf candidate](experiments/kernel-perf-20261104-01/) adds actual operation
and event-owner LSM/SELinux checks, including failure-unwind and unconditional
label cleanup. Whole-kernel compilation and Mac/Linux actual-body fixtures pass
with complete source audits and unchanged config. Adding the owner-label pointer
changes 1,104 of 8,408 export CRCs. The rebuilt KUTF module passes 43 static
import CRC checks; optional Gator fails MODPOST on an unexported walk_stackframe,
also absent from original exports. No module check is bypassed. These limited
results do not establish runtime ABI or boot compatibility. The candidate stays
isolated; strict policy, networking, capability9 and installer/FBE remain gates.


The [firmware candidate](experiments/kernel-firmware-20261104-01/) registers real
SELinux firmware_load mediation at the enabled legacy file/user-helper hook,
retaining FD-use checks, loader cleanup and common IMA dispatch. Whole-kernel
compilation and Mac/Linux actual-body loader fixtures pass with complete source
audits and preserved config/firmware. All vmlinux CRCs match the perf parent;
its ABI changes remain. This is isolated compilation/static evidence, with no
Image promotion, boot or hardware validation and no installation approval.


The [actual Android17 binary inspection](experiments/policy-binary-20261104-01/)
confirms active netlink_xperm (bit9), 1,342 ioctl and 95 netlink extended records.
The original extracted reader fails on these records; the candidate passes 25
record cases. Its capability9 load rejection remains, so this is not whole-policy
load approval. Strict actual-vendor policy still fails with 322 diagnostic blocks.
All 1,243 project/15 patch audits remain exact; historical Android16 capability-
off results are explicitly separate from this new evidence.


A [complete policydb reader host probe](experiments/policydb-host-20261104-01/)
now executes the actual Samsung parser and data structures. The unmodified active
Android17 diagnostic reaches cap9 rejection and Samsung's subsequent panic path.
Only a separate one-bit-off, non-installable data control parses completely with
counts matching independent Android17 libsepol; five truncations also stop. No
production guard/macro or policy is modified. This narrows format compatibility
without approving active policy loading, AVC enforcement, boot or installation.


## November 5 checkpoint: implemented active-capability profile

The [new isolated capability candidate](experiments/kernel-capabilities-20261104-01/)
replaces the old blanket cap9 rejection with a supported-bit profile and rejects
every unimplemented/unknown active bit. This follows actual parsed-policy,
SID/mapping/services/AVC/netlink comparisons against Android17 libsepol. Whole-
kernel compilation passes, as do definitive tests using the unmodified diagnostic
binary and real capability decoding: 6,291,456 AVC and 3,145,728 single-packet
checks plus compound/error/generation cases, with zero oracle differences.

The old candidate's cap9 panic reports remain valid historical observations;
this new candidate has passed that parser gate. Native cache/concurrency, full
security_load_policy publication and hardware/boot remain unproven. All 60,331
source/protected audits pass, config/firmware stay exact and exports match the
firmware parent (the perf ABI changes remain). No experimental Image enters
Android prebuilts. Strict vendor policy still fails with 322 diagnostic blocks;
networking/BPF, module ABI and Android17 FBE/installer/rollback remain gates.


The [vendor metadata narrowing candidate](experiments/vendor-policy-tightening-20261105-01/)
keeps all assertions, separates two private Samsung UWB type names, and removes
one legacy system_server sys_module allow forbidden by Android17. Production
strict diagnostics decrease from 322 to 319, with exactly three resolved and no
new diagnostic assertion identities. All other ordered policy/ compiler inputs
are identical and full source audits match. This is isolated text metadata, not
a rebuilt vendor image or strict-policy approval. Original vendor stays pinned.


An [isolated diagnostic boot packaging check](experiments/diagnostic-boot-20261105-01/)
uses official Android17 tools, reproduces the original image byte-for-byte, and
then replaces only the kernel. The resulting 25,454,608-byte image fits the
33,554,432-byte boot partition, retains SAR/header/trailer/enforcing metadata and
passes the ramdisk check. All original header/padding bytes except kernel size
and digest match. This image remains outside Android prebuilts and target-files,
explicitly marked NOT_FLASHABLE. Packaging is not boot, FBE/TEE, ABI, network,
strict-policy or installation approval. No installable test ROM exists yet.
