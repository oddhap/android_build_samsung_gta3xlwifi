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

Active snapshot **port-20261106-04** locks 1,243 projects and **17 exact patches**.
It includes the device-scoped legacy v1 fscrypt keyring source integration;
actual init/vold module compilation and multilib keyutils checks have passed, as recorded below.
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


## November 5: clarified platform-policy migration and strict results

The owner clarified that Android17 platform and Samsung vendor assertions remain
required, while the obsolete Android11 platform component is ported. This decision
is also recorded in the workspace AGENTS.md and handoff. It does not authorize
an assertion-disabling compiler flag or a policy-security approval based on counts.

A [current public-contract audit](experiments/public-policy-contract-20261105-01/)
blocks blind replacement: 92 required legacy symbols are missing, and six shared
compiler-generated attribute names have different expression definitions. The
[isolated platform port](experiments/platform-policy-port-20261105-03/) therefore
retains legacy symbol identities, explicitly replaces obsolete platform behavior
with unchanged Android17 CIL, and ports old platform classifications out of shared
attribute assignments. The old Android11 public assertions are explicitly retired
with their platform component; this is not an all-historical-assertions-retained
claim. All 131 Samsung vendor neverallow and two neverallowx statements, plus
all current Android17 platform assertions, remain textually unchanged and checked.

Strict results: **319 -> 79 -> 77 -> 72 diagnostic blocks**, still secilc255 /
checker1. Runner0 means the experiment completed. Full before/after source audits
match: 1,243 projects / 15 exact patches. All other compiler inputs and the compiler
hash stay identical. The final verbose strict run records all **638 matching grant
records** for the 72 conflicts; its success is diagnostic collection, not policy
approval. Current-platform grants also appear in some conflicts, which require
semantic classification/compatibility work rather than just deleting vendor allows.

The historical report field `permissions_added: false` in the first stagers means
no allow statement was added. Attribute changes can affect complements; it is not
an effective-permission monotonicity proof. The current tool uses the precise
field `allow_statements_added`; archived tool sources/reports remain unchanged.
No candidate metadata enters active sources, snapshots, cache hashes or the MTP
vendor image. Networking/BPF, module ABI, FBE/installer/rollback and hardware gates
remain. No installable ROM, security approval or device operation is produced.


## November 5: obsolete MLS access retired and restricted property owners added

The [legacy access proposal](experiments/legacy-policy-access-20261105-03/) retires
an old platform mlsvendorcompat assignment and four related app-data grants, as
required by Android17's unchanged prohibition on this MLS escape. Seven exact
old vendor allows for vold debugging/Binder, shell execution and setupwizard
writers are also removed. Strict diagnostics decrease **72 -> 67**, with no new
diagnostic assertion identities. All 5,917 current assertion/constraint records
are retained; eleven allow statements are removed across the two compiler inputs.

A [property inventory](experiments/vendor-property-ownership-20261105-01/) records
118 exclusive vendor-private property types, including 98 without direct owner
membership. Missing/mixed context evidence is not assigned a public owner. The
[reviewed 32-type proposal](experiments/vendor-property-owners-20261105-01/) adds
vendor-restricted ownership for actual vendor-namespaced context labels with no
direct known core/broad writers, plus one explicit non-init core writer assertion.
No allow or public property scope is added. Strict diagnostics remain 67 because
other unowned types still trigger the shared assertion. Attribute/effective writer
closure and runtime behavior are not proved by this direct inventory.

The [app-private-data narrowing proposal](experiments/app-data-tightening-20261105-01/)
removes three old forbidden operations without changing labels or MLS domain
classification. Strict diagnostics decrease **67 -> 65**, again with no new
diagnostic assertion identities. All **5,918 assertion/constraint records** remain,
including the new property writer restriction. Final verbose strict diagnostics
record **494 matching grant records** for the remaining 65 conflicts, untruncated.
No -N compile is performed in these proposals. Secilc255 remains failure;
runner0 is experiment completion only.

Each completed proposal has matching full before/after audits of 1,243 projects
and 15 exact patches. Unchanged compiler inputs and hashes are verified. Exact
tools, selected statements, property context evidence, patches and inventories
are archived. Two early legacy-access attempts stopped safely before staging on
same-basename input guards; full system-path selection fixes the issue. The
active snapshot, images, signing material, recovery and tablet remain unchanged.
No flashable ROM, kernel promotion, security approval or hardware validation is
produced. Property ownership, scoped legacy app/network rules, HAL/BPF behavior,
network backend, module ABI and Android17 FBE/installer/rollback remain open.


## November 5: sandbox boundaries and complete property ownership

The [sandbox file proposal](experiments/sandbox-file-access-20261105-01/) removes
only forbidden open/tombstone/APK mutation permissions: strict **65 -> 62**. An
[official frozen-policy build](experiments/frozen-policy-oracle-20261105-01/)
provides Android11 classification evidence only, not Android17 validation. The
[ASEC client proposal](experiments/asec-clients-20261105-01/) intersects the old
source with 43 ABI-visible legacy/vendor app clients: **62 -> 60**. It preserves
the old source attribute and all targets/permissions; three unmapped frozen
private clients are explicitly recorded. It does not establish runtime coverage.

A complete positive property-attribute closure finds 66 remaining unowned types,
all exclusively vendor-declared. The [restricted owner proposal](experiments/vendor-private-property-owners-20261105-01/)
assigns them vendor-restricted ownership by private declaration origin, expanding
the existing restricted group from 32 to 98. No public scope or new allow is
added. All 524 property types now have an owner in this graph. An independent
real Android17 compiler oracle validates the exact positive graph both
[before](experiments/property-closure-oracle-20261105-01/) and
[after](experiments/property-closure-oracle-20261105-02/), with 66 and zero unowned
properties respectively and no membership differences. This is not AV/MLS runtime
or whole-policy security validation. Product ownership is the actual M4 alias
of system ownership; type aliases are resolved, not silently ignored.

The restricted owner boundary exposes old core-writer conflicts: **60 -> 61**.
The [reviewed writer proposal](experiments/property-writer-tightening-20261105-02/)
removes 25 forbidden set grants, proving every concrete source is non-init core,
including the two-member platform_app API30 alias: **61 -> 58**. Non-core writer,
init and read grants remain. Private sources policyloader_app/vramdiskd are core
in this policy and included; hardware behavior remains untested. All **5,918
assertion/constraint records** remain, with no added AV permission or permissive
declaration. Source/permission replacements have explicit subset witnesses.

Final verbose strict diagnostics contain **58 conflicts / 204 matching grant
records**, untruncated. Secilc255 remains failure; runner0 is experiment completion.
Every proposal has matching full 1,243-project/15-patch before/after source audits
and unchanged compiler/other input hashes. All candidates remain outside active
sources/snapshots/prebuilts/images/cache hashes. No -N real-policy compile, signing,
flashing or device operation occurs. Remaining SELinux, actual network/BPF backend,
HAL/ABI and Android17 FBE/installer/rollback still block a flashable test ROM.

## November 5: strict policy compiler passes in isolated staging

The production `legacy-property-views-20261105-01` proposal now compiles with
strict neverallow checks enabled (exit 0, zero normal or extended assertion
failures). The userdebug proposal `staged-debug-policy-20261105-03` also compiles
strictly and has no permissive domains. Debug LLKD tracing excludes app domains;
codec2 debug TCP access to su is removed; su and backuptool are enforcing.
Current Android17 and Samsung vendor assertions remain enabled. All changes
remain isolated metadata proposals, with full 1,243-project/15-patch audits;
they are not yet integrated images or a boot-approved installation candidate.

Historical diagnostic counts before the new shared parser counted ordinary
neverallows only and omitted one neverallowx conflict. Compiler exit255 always
remained failure. That extended ioctl grant (SIOCGIWESSID) has since been removed;
new reports count ordinary, extended and total assertions explicitly. Historical
reports are preserved rather than overwritten.

The actual strict policy binaries are now being exercised by the kernel host
regression and installed-context validation tools. Real networking/BPF startup,
kernel modules, zygote/cgroups, FBE/TEE, installer/recovery preservation and full
candidate packaging remain gates. No signing, flashing or device changes occur.

The complete assertion-preservation comparison now confirms all **5,918**
assertion/constraint records through every production stage: 59→29→28→23→18→12→0
strict diagnostic blocks. No assertion is removed, no permissive domain added,
and every replacement AV permission has an explicit source/target intersection
or permission-subset witness. Reports and exact tools are archived under each
proposal directory. This is compiler/static evidence, not runtime approval.

The subsequent actual-context validation exposed three Samsung private app-data
labels missing Android17's required app_data_file_type classification. The
`vendor-app-data-types-20261105-02` proposal restores that classification and
removes the newly exposed forbidden system_server create/unlink/open access to
attiqi private data. Production and regenerated userdebug policies compile
strictly again; `staged-debug-policy-20261105-04` has no permissive domains.

`strict-policy-contexts-20261105-02` completes exit0 with full before/after source
audits. Each profile passes **20** actual installed/staged context checks,
including property_info_checker, combined app contexts with processed Android17
seapp neverallows, binary context validation for Keystore2/TEE, and exact positive
key/TEE type membership in hash-bound strict compiler inputs. Those classification
attributes can be optimized away in the binary; their absence is not patched
around in production policy. Earlier checker failures are archived. Identical
legacy duplicate property/GNSS specifications produce warnings but pass the real
tools. This does not validate on-device label selection or access behavior.

Before that final app-data classification change, both strict policy binaries
passed the actual kernel-reader/services/AVC/netlink host regression with zero
Android17 libsepol differences. The final binaries need fresh regression after
the isolated Gator kernel/module build. See [startup source review](reports/startup-source-review-20261105.md)
for the actual fork/cpuacct and in-kernel LMK paths; it does not claim runtime proof.


## November5: real legacy fscrypt source integration

The [legacy fscrypt proposal](experiments/legacy-fscrypt-20261105-02/) restores the
actual init session keyring and v1 raw-key install/evict API missing in Android17.
It keeps encryption and current SELinux rules, and never converts unsupported v2,
wrapped-key or permission errors into success. The final synthetic syscall/real
code probe passes 88 cases with fatal sanitizer handling and matching Samsung
UAPI payload layout; it does not exercise actual encryption or TEE keys.
Snapshot port-20261106-01 audits 1,243 projects/16 patches, with exact composition
proof and pinned device e998435. Actual init/vold compilation passed.
No ROM is flash-ready and no original kernel/vendor/recovery/data input changes.


## November 6: native legacy fscrypt linked and inspected

`legacy-fscrypt-native-20261106-01` completed exit 0, including complete before/
after audits of 1,243 projects and 16 exact patches. Moving the device-scoped
keyutils dependency to common `init_defaults` fixed final init linkage. The
four runtime inputs remain byte-identical to the fatal-sanitizer host07 probe
(88 cases). Earlier Soong type/link failures remain archived.

[Native output evidence](experiments/fscrypt-native-evidence-20261106-01/report.json)
checks actual installed ARM64 init/vold ELF files and the expected legacy code
strings. Android `ld.lld -r` independently linked both actual keyutils archives
without forcing their target: ARM32 and ARM64 ELF identities and required symbol
definitions passed. This is source/build/link evidence; actual keyrings, userdata
unlock, TEE, locking, recovery compatibility and rollback remain untested.
No kernel/vendor input was replaced and no installation candidate was produced.


## November 6: preserve userdata on init recovery errors

[The scoped init guard](experiments/init-data-preservation-20261106-01/) rejects
recovery wipe requests before bootloader-message writes or shutdown. Mount and
unlock failures remain errors. Current init callers for mount, directory-policy
and vold initialization failures are covered; encryption and SELinux are intact.
100 actual-function host cases passed with fatal UBSan on Mac/Linux. Native init
rebuilt successfully, the guard is present in the installed binary, and actual
init/vold plus ARM32/ARM64 keyutils verification passed again.

Current snapshot **port-20261106-02** retains all 1,243 project revisions and 16
reviewed patches; only the system/core patch changed since snapshot01. Full
before/after source audits and private-index patch-composition proof pass.
This is a data-preservation guard, not hardware unlock/TEE/recovery/rollback
validation or a flashable-ROM claim.


## November 6: integrated accounting build and filtered-table fix

[Real qtaguid accounting](experiments/network-stats-native-20261106-02/) passed
complete isolated native linking and complete actual Java module typechecking
(101 sources/306 classes), then the ordinary project build and full source audits.
Actual ARM64 expanded-APEX library, real ARM32 archive and Java JAR checks pass.
Four new Android regression tests remain unexecuted on Android.

[The access fix](experiments/network-stats-access-20261106-01/) restores the real
procfs group initialization missing from Android17 and refuses silently filtered
detailed tables. 37 fatal-sanitizer real-reader/kernel-predicate fixture cases
pass, along with the real init verifier and strict compiled-policy permission
queries. Its project build completed exit0 in4m45, followed by complete source
and actual ARM32/ARM64/installed-init output verification.

Current snapshot **port-20261106-04** pins1,243 projects and17 exact patches.
Device commit87313db changes only the group/mode setup; only Connectivity's patch
changes from03. The original kernel, selected MTP vendor and DTBO remain intact.
No networking readiness, loader, firewall-owner or LNA/DNS bypass was introduced.

The isolated transport SELinux proposal passes both strict profiles without
removing any assertion/constraint. Actual permission/genfs and private-ioctl
boundary probes pass. The [checked-chain I/O component](experiments/checked-uid-chains-20261106-01/)
passes84 synthetic I/O cases and actual netd ARM64 CFI object compilation. It
still needs a complete authoritative backend and dual-stack lifecycle. Neither
experiment is selected into Android images. No ROM is flash-ready.

## November 6: isolated leased packet barrier

[The kernel proposal](experiments/kernel-netpolicy-20261106-01/) supplies a
process-owned, initially held packet-barrier match with one IPv4/IPv6 state.
The complete isolated Image/module build passed with unchanged configuration,
all 118 Gator/43 KUTF imports and full candidate/protected source hash audits.
44 actual-function host fixture cases cover ownership, close and grace ordering.
[Its builtin xtables extension](experiments/xtables-guard-20261106-01/) passes
complete actual ARM64 iptables linking, registry machine-code verification and
full Android source audits. Neither proposal is selected into Android images.

Explicit isolated lease-device policy proposals pass strict production/debug
compilation, preserving all 5,918/5,881 existing assertions and constraints.
17 permission queries per profile, actual genfs/file-context checks, four ioctl
contradiction failures and both neighboring-ioctl denial assertions pass. No
policy input is automatically replaced. Verified packet attachments, owner
transport, the complete Android17 networking backend and installation/FBE/
rollback integration remain required. No flash-ready ROM is produced.

[The real lease transport](experiments/netpolicy-lease-transport-20261106-01/)
passes65 syscall-fixture cases and actual netd ARM64 CFI object compilation.
[The composed two-family transaction](experiments/dualstack-uid-chains-20261106-01/)
passes62 fatal-sanitizer cases and compilation/linking of all three components
against the actual Android interface. It verifies all six guard hooks, actual
both-family snapshots and final rule readbacks; failed/unverifiable recovery
keeps the barrier held. These remain isolated components, without hook setup or
full backend/service integration, and do not establish real packet behavior.

A read-only [old diagnostic filesystem inspection](reports/gapps-space-diagnostic-20261106.json)
finds1220MiB free in system and116.7MiB in product. The preserved archive digest
matches. This does not establish final-ROM space or Android17 GApps support.
No GApps package is selected and no A/B conversion/repartitioning is performed.

[Explicit missing-hook setup](experiments/dualstack-uid-setup-20261106-01/)
extends the isolated transaction with opt-in installation and exact preservation
of existing root rules. 90 host fixture cases and combined actual netd CFI object
verification pass, including full source audits. Default mode only verifies.
Real Controllers startup/restart integration must preserve guards atomically when
exclusive root chains are rebuilt; installing them after an unguarded flush is
insufficient. No service or readiness integration is selected yet.

[Atomic Controllers guard preservation](experiments/controllers-guard-20261106-01/)
passes960 actual-function command comparisons and a complete isolated ARM64 CFI
netd binary link. It adds the held guard in the same exclusive filter-root rebuild
transaction, retaining other command sequences and original dependencies. Full
source audits pass. The complete owner still must acquire the lease before
Controllers startup; no main/service/backend/readiness wiring is applied here.

[The independent appId match](experiments/kernel-appid-20261106-01/) implements
per-user UID modulo100000 using the real Samsung socket-UID/INPUT lookup path.
22 host fixture cases and343599 comparisons against the actual Android17
system-UID predicate pass. Full isolated Image/modules build passes with unchanged
config and Gator/KUTF CRCs, full kernel/protected and Android reference audits.
[Both private xtables extensions](experiments/xtables-appid-20261106-01/) now link
together into the whole ARM64 iptables binary, with actual registration machine
code and full source audits. No packet execution, owner/backend readiness or
Android prebuilt promotion is inferred from these build results.

[Actual networking source contracts](experiments/network-contract-20261106-02/)
confirm that both selected local-network and loopback permission flags are enabled
in real generated framework code. Existing IPv4/IPv6 kernel INTERNET-group checks
and Android17's group assignment also remain. This does not implement the missing
provider or validate native device execution. Real BPF map/startup gates remain
unchanged, and the public Netd AIDL version18 must not be repurposed.
