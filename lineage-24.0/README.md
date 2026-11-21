# LineageOS 24.0 device port — Samsung SM-T510

Active development target: LineageOS 24.0 / Android 17, ARM64 with ARM32 apps,
`gta3xlwifi`, physical non-A/B partitions. This is an unfinished source-built
device port. The first physical test installation has completed; its first Android17 boot failed and is being repaired.

**Physical boot milestone and remaining blockers.** Snapshot22 reached
`sys.boot_completed=1` with SELinux Enforcing and user 0 unlocked after a
guarded ownership correction of a pre-existing empty lock-settings database.
HWUI render aborts and later system-server watchdog resets prevented stable use.
Snapshot24 passed the complete build and OTA checks with scoped ION read access
for the five observed clients.
The source policy and Samsung vendor link retained all 5,881 assertions and
passed 153 permission queries. A separate LMKD candidate addresses the observed
in-kernel backend reaching userspace PSI and BPF monitoring at boot completion
or daemon restart. Its host regression and compiled artifact checks passed.
Snapshot25 includes both corrections and passed the full build, after-build
audit, 39-APEX VINTF inspection, OTA signature and all three block-stream checks.
Physical installation and all 17 critical readbacks passed. Android 17 completed
startup with SELinux Enforcing and CE storage available. The system_server,
netd and LMKD processes held their PIDs for 180 seconds and Launcher and Settings
started. Wi-Fi failed when the legacy vendor supplicant could not drop root or
prepare its configuration. Snapshot26 starts that service under the Wi-Fi UID.
The installed build completed boot and the owner confirmed Wi-Fi scanning.
Password entry triggered an IME crash involving a failed hardware bitmap copy
and a separate EGL partial-update abort. The installed snapshot27 retains
software bitmaps when hardware copies fail, disables partial updates on this
Mali device, and ports the LineageOS 21 minimum-backlight mapping. On the
tablet, the Lights HAL received level 4 at minimum, 0 with the display off,
and 4 after wake. Snapshot27 completed boot and kept system_server, netd and
lmkd stable for 180 seconds with SELinux Enforcing and CE available. LatinIME,
Calculator, Clock, Calendar and Twelve still abort without a render surface.
The logs show ordinary app processes receive EACCES from the Samsung ION
allocator. Snapshot29 will restore the narrowly scoped read-side ION
permissions on this device. The isolated Android 17/Samsung policy link kept
all 5,881 assertions and constraints and passed 110 queries for each of the
baseline and candidate, with no new permissions for isolated, run-as or
shell domains.

Snapshot26 retains the exact LineageOS 21 MTP vendor init file and passed a
16 MiB physical upload/download with matching checksums. Wi-Fi password
association remains unverified. The owner confirmed double-tap wake fails on
snapshot26 with the setting enabled. Both touch-driver controls are present.
The shipped system-server JNI lacks the product-scoped LineageOS 21 bridge to
the device power library. Snapshot28 restores that bridge. The host touch
and boost regressions passed. Snapshot29 will include both the touch bridge
and app rendering change. Snapshot28 is kept as an offline build while the
app fixes are validated. The charger service and its assets are already
packaged, and powered-off charging has yet to be tested on Android 17.

**Snapshot22 full build and all package checks pass.** Complete1,243-project /
22-patch before/after audits, product checks including actual constructor
bytecode and service JAR extracted from the real CAPEX payload, fresh contexts,
39-APEX VINTF, CMS/signature/CRC and all three OTA block streams pass. The archive
is1,041,046,682 bytes, SHA256
`373327541ed3f44ac86e4768b771a47e099fa597d12b64ec28784aec3390a2d0`.
Physical installation and all 17 critical readbacks passed.

Snapshot21 is installed/read back and fixes CLAT JNI registration and optional
aconfig container handling: netstats starts and genuine post-fs flag init exits0.
It then aborts constructing the BPF-only local-network note-op observer.
Snapshot22 confines that observer to its supported backend. Current upstream
packet code produces these observations only on kernel >=5.10; kernel4.4's
legacy backend has no such stream. Permission flags and real enforcement
implementation stay unchanged; no fake FD, event or BPF readiness is supplied.
Local-network note-op observation is explicitly unavailable, a known limitation.
Sixteen actual constructor-selection cases and64 AOSP packet control-flow cases
pass. The device is in preserved TWRP. Normal boot, actual networking and complete
CE/FBE are still unverified.

**Snapshot21 passes the full build and all package checks; physical installation
is in progress.** All1,243 projects /22 exact patches match before and after the
build. Product checks02, fresh contexts, rebuilt native JNI and dynamic Rust
implementation, 39-APEX VINTF, CMS/signature/CRC and all actual OTA block streams
pass. The original failed product check01 incorrectly required a changed daemon
executable; its actual implementation is in a rebuilt shared Rust library.
That failure remains recorded; checks02 verify the real DT_NEEDED dependency,
changed packaged library and JNI extracted from the actual compressed APEX.
The local archive is1,041,046,636 bytes, SHA256
`94397d62a7ce5fd8f3ddbd97c70372c948749810e986124b285927a0a03cd073`.
Fresh physical prewrite guards pass; existing DE0 keys, userdata, kernel, vendor,
policy and TWRP are retained. Installation readbacks and normal boot are pending.

**Latest physical status (November17): snapshot20 reaches genuine flag storage,
then aborts during native CLAT registration.** Authenticated early Android17 ADB,
SELinux Enforcing, the real cache-backed metadata mount and platform/mainline
flag files are confirmed. AdvancedProtection starts successfully. The next blocker
is an unconditional BPF permission verification in libservice-connectivity while
this device selects the existing userspace CLAT/accounting backend. The repair
must retain shared daemon checks and all modern BPF checks for their backend.
A separate optional-vendor aconfig override-loop error is also being corrected.
The device is back in preserved TWRP; normal boot, network and complete FBE remain
unverified. Historical candidate notices below describe earlier stages.

**Snapshot20 passes all build/package checks and is being installed (November17).**
Snapshot19 displays the boot animation and resolves the previous ION/ashmem
failures, then AdvancedProtection stops because genuine aconfig storage is absent.
The protection flag exists and is true; no flag or service is disabled.
Snapshot20 provides a real labeled metadata view from a dedicated new directory
on the existing cache filesystem, before aconfigd's supported post-fs retry.
Existing cache content, userdata, partitions and recovery are retained. Compiled
CIL inputs, kernel and vendor are byte-identical; fresh context/bootstrap checks,
51 additional policy queries, all prior product checks, 39-APEX VINTF, signature,
CRC and actual block streams pass. The downloaded archive is1,041,038,809 bytes,
SHA256 `d5ec56af9a4ee2c12bfb7995fdd93f3709bfd73d6dabb155c71cc86026614810`.
Physical installation/readbacks and normal Android17 boot remain pending.

**Snapshot19 full build and all package checks pass; physical installation is in progress.**
All1,243 source projects /21 exact patches, seven actual installer hook cases,
strict policy/context checks and93 effective permission cases, 39-APEX VINTF,
signed container/CRC and all three block streams pass. The downloaded archive is
1,041,032,878 bytes, SHA256
`6a0f8bdb7804b78df6ba93fbb3315cdb77fd1abbc5a6e9993f89b1fa495d2060`.
Fresh physical preflight passes with enforcement and persistent DE0 metadata
retained. Installation readbacks and normal Android17 boot remain pending.

**Snapshot19 full ROM build is running after the complete strict policy checks pass.**
The actual source policy build, strict Samsung link and source audits pass,
retaining all5,881 assertions/constraints. All20 context checks and93 effective
permission queries pass. The fresh vendor cache preserves every other original
entry and its security metadata. Its exact digest is already bound in the OTA
guard and tested against actual accepted/tampered images before ROM packaging.
The device is in preserved TWRP; the next physical boot has not occurred yet.

**Snapshot17 proves early authenticated Android17 ADB works; next policy fix is building.**
SELinux remains Enforcing, `/dev/ion` has its correct label, and SurfaceFlinger runs.
Live logs identify bootanim's missing ION read access and system_server aborting in
ApplicationSharedMemory because libcutils ashmem open is denied. The actual retained
vendor API is28 and the kernel lacks the memfd_class capability file. An isolated
strict candidate adds the observed bootanim access and Android17's upstream
old-vendor libcutils ashmem open rule. All 26 effective permission queries pass,
including continued denial of direct ashmem-device access and generic device
access. Snapshot18 builds that explicit source adaptation. No forced memfd or
fake vendor API is introduced. The device returned to preserved TWRP via ADB;
userdata and enforcement remain intact. Normal Android17 boot is still unproven.

**Snapshot17 is physically installed and all readbacks pass (November17).**
Actual sideload/updater exits0. Boot, the fresh vendor policy cache, all13 critical
files including ION contexts/policy and early USB ADB init actions, and the intact
preserved TWRP match. System/product were read back with read-only mounts and
unmounted before normal boot. Userdata and DE0 keys were retained; no format was
performed. Normal boot is now being monitored with live authenticated ADB logging.
No successful Android17 boot, hardware graphics/network or complete FBE is claimed.

**Snapshot17 complete build and package checks pass (November17).**
All 1,243 source projects /21 exact patches, seven actual installer-hook cases,
strict ION/label/ADB checks, 39-APEX VINTF, signed container/CRC and all three actual
block streams pass. The downloaded test archive is 1,041,028,373 bytes, SHA256
`2de7de50b8124d2992f7bc2e0f01096015c8c150817cc9f68aaeecc03ff8efa0`.
Physical preflight and installation readbacks are required for this new image.
No normal Android17 boot, working network or full FBE validation is claimed.

**Current candidate: snapshot17 (November17), correcting the exact OTA vendor binding.**
The complete snapshot16 build, source audits, every product check including ION
and early authenticated ADB, and 39-APEX VINTF pass. OTA generation correctly
rejects its stale vendor digest pin after the reviewed policy-cache update.
Snapshot17 changes only that digest to the already verified vendor image;
the strict guard and geometry checks remain intact. A test reproduces the actual
old rejection, accepts the reviewed image through AOSP's real sparse parser, and
rejects tampered bytes. Product hook tests now include the positive real vendor
case. The complete snapshot17 build and package checks are running. No snapshot16
installation occurred, and userdata and recovery remain intact.

**Current source candidate: snapshot16 (November17), building the complete ROM.**
The actual corrected ION policy build and strict vendor link pass, retaining all
5,881 assertion/constraint records, with 20 context checks, 36 effective permission
queries and actual combined file-label lookups. A fresh vendor cache composition
preserves every other Lineage21 MTP vendor file and security metadata. Snapshot16
also enables the existing authenticated USB ADB transport from init, before UI is
available. It retains `ro.adb.secure=1`, `ro.debuggable=0`, the vendor's sole configfs
ownership and the existing SELinux policy. No TCP listener is added. The actual
init parser accepts the configuration. The full build and package checks must
finish before another physical test; no successful Android17 boot is claimed.

**Latest physical diagnosis (November17): snapshot13 loads the genuine legacy
mapper, then graphics allocation fails because `/dev/ion` is labeled `device`
and the three graphics clients lack the retained legacy ION read interface.**
The clean RenderEngine tombstone and Mali allocator error are retained privately;
public installation evidence records their hashes. Snapshot14 proposed an exact
character-device label and scoped read access for the three concrete graphics
clients. An isolated strict compile and 36 actual policy permission queries pass,
including denials for generic device nodes; eight actual label lookups pass.
The first actual source build rejected private vendor type names in system_ext.
Snapshot15 uses the public HAL server attributes, verified to contain exactly the
same two retained vendor services. The corrected isolated compile and all 36
queries pass; the actual source policy build and fresh checks are in progress.
No normal boot, functioning graphics, networking or complete FBE is claimed.

**Current status (November17): snapshot11 reaches graphics startup; snapshot13 installed and read back.**
Actual snapshot11 installation/readbacks passed and normal netd/zygote start.
SurfaceFlinger repeatedly aborts with `gralloc-mapper is missing` (matched physical
libui BuildId `1d6d4d54e6a2e1e13a76a5f597afff81`). The preserved vendor declares
mapper2.0 passthrough in both ABIs and contains the actual AArch64 implementation.
The device did not select libui's existing legacy-HAL support.

Snapshot12 selected that support but failed before compilation because the new
Soong select requires a boolean and the setting was registered as a string.
Snapshot13 uses the existing production `soong_config_set_bool` helper. Actual
Make macro execution reproduces the type difference; 96 actual mapper-constructor
fixture cases preserve modern preference and mandatory successful HAL loading.
No mapper source, API property, vendor, kernel, SELinux or encryption is changed.
The complete snapshot13 build, production dual-ABI compiler flags and rebuilt
libui identities, all product checks, 39-APEX VINTF, CMS/CRC and every block stream
pass. Installation completed with updaterRC0 and all ten critical file readbacks;
boot/vendor and preserved recovery match. Data was retained. The next normal
Android startup is being observed. No normal Android17
boot, actual networking or complete CE/FBE validation is claimed.

A clean-data snapshot10 test creates persistent DE0 key files and init_user0
exits0. The netd null-global crash is gone. Netd now fails closed with EPROTO:
exclusive INPUT/FORWARD construction installs guards, nonexclusive OUTPUT does
not, but the production caller uses the default VerifyOnly startup mode.
Snapshot11 explicitly selects the existing InstallMissing path while the kernel
lease is held; it preserves foreign rules and verifies all six actual root images.
A regression replays actual Controllers choices/caller and real guard/startup
code: original missing-OUTPUT failure reproduced, fixed six-root verification,
held failure injection and nonduplication pass. Other policy, kernel, vendor,
crypto and boot-failure assertions remain unchanged. The full audited build, all fresh product checks, VINTF with 39 factory APEX
packages, signed CMS/CRC and every OTA block stream pass. The downloaded archive
hash and exact physically tested installer binary identities also match.
The unflashed candidate SHA256 is
`ba33d249da112b669065c38fadeaabe7a05d278902b02a809654f4dc2fcad67f`
(1,041,177,297 bytes). A CE policy EINVAL message in the physical
log still requires follow-up; user0 EXIT0 is not full encryption validation.

**Newest physical diagnosis:** snapshot09 starts LMKD using the actual in-kernel
low-memory-killer interface and again completes file-crypto initialization.
Its next blocker is a real netd oneshot SIGSEGV: the test path constructs a local
Controllers instance, while the unmodified restore helpers dereference the unset
global gCtls. Matching physical tombstone/build-ID and symbolization identify
NetdConstants.cpp:39 from main.cpp:130. The boot failure guard correctly reboots.
Snapshot10 initializes the global instance before those callbacks, matching normal
netd lifetime. UBSan reproduces the original bug; fixed identity and all fixture
failure paths pass. No provider checks, policy, crypto or networking readiness are
bypassed. Snapshot10 full audited product build, all product checks, VINTF with 39 factory
APEX packages, signed ZIP/CMS/CRC and all block streams pass. Fresh physical
preflight guards pass; installation completed with updaterRC0. Physical boot,
vendor, unchanged recovery and all eight critical files including new netd match.
Fresh snapshot10 logs identify an earlier user0 FBE initialization failure: an
existing DE0 directory has no version or key files. The automatic recovery-wipe
guard refuses data deletion. A secondary DECON shutdown IRQ fault follows the
fatal reboot. The captured sequence does not reach the netd self-test. An
owner-authorized clean-userdata retest of the identical ROM is now in progress;
no acceptance of missing keys or encryption bypass was added.
No normal Android17 boot, working networking or complete FBE claim is made.

**Latest status (November16, supersedes historical notices below):** snapshot07
installed successfully and reached actual file-encryption initialization (EXIT0),
but normal boot fails when LMKD reads absent platform API version metadata.
Snapshot08 adds genuine upstream version-comment data without a loader service
or readiness actions, and removes false kernel capability assumptions on Linux4.4.
Its full build exposed an APEX zero-minimum compiler warning treated as an error.
The complete after-audit passed; that failed build was never installed.

Snapshot09 simplifies the predicate to the actual cached kernel version comparison
in every compilation mode. The full production-Clang header regression reproduces
the snapshot08 APEX failure and passes both modes with the fix. The unchanged
metadata parser still aborts on missing/malformed metadata or invalid SDK values.
Full source selection audits, the complete product build, all target-file checks,
39 factory-APEX VINTF checks, signed OTA integrity and all block streams pass.
Snapshot09 installed with updaterRC0 and all seven critical file readbacks,
boot/vendor hashes and preserved recovery verified. Userdata was retained.
The owner reports Samsung logo followed by reboot; fresh crash logs are pending. There is no successful normal Android17 boot,
network or complete user-encryption validation yet. Enforcement, assertions,
real capability checks and all installation guards remain required.

**Current candidate invalidation and replacement (November16):** the previous
OTA `aa681b3199d1072948e6cc9c835019513c34c96545fd414639dc4366fe4cbc58`
must not be installed. Its static installer actually aborted in the preserved
Linux4.4 TWRP before preflight because upstream Bionic required MADV_WIPEONFORK.
The same missing syscall feature affects the selected ROM kernel.

Active snapshot is now **port-20261116-04** (1,243 projects /21 exact patches).
Two reviewed Bionic sources use blocking kernel getrandom for every requested
byte only when a genuine serialized MADV_WIPEONFORK probe returns EINVAL.
No userspace entropy/cache is inherited across fork; entropy, allocation and
other probe errors remain fatal. Supported kernels retain the original generator.
Eight host modes pass, including fork/threads and explicit syscall failures.
Actual new libc and ARM32/ARM64 static installer builds pass. On the physical
preserved TWRP, the new read-only recovery preflight passes and updater reaches
its normal argument rejection without abort. SELinux remains Enforcing.
The complete replacement ROM/package and all fresh package checks pass.
These results do not establish Android17 boot, networking or encryption behavior.

The owner has explicitly authorized the physical test flash and userdata deletion.
Only the reviewed recovery OS-header byte was adjusted; the full partition was
read back and verified against the expected bytes. Existing TWRP kernel/ramdisk
are preserved. The replacement ROM has now been installed with updater RC0,
and the owner-authorized clean userdata format completed. Boot/vendor readbacks
match the exact new payload; the complete recovery readback is unchanged.
The old TWRP wrapper logged a missing sideload path after minadbd had completed;
this is recorded separately from the successful updater and actual readbacks.
First Android17 boot physically bootlooped; see the current diagnosis below. Private device reports,
rollback images and ROM binaries are not published. Older candidate and approval
statements below are historical and superseded by this notice.

**Current boot blocker:** snapshot04 installed successfully and readbacks passed,
but the physical device bootloops. Persisted last_kmsg shows repeated PID1 deaths
before USB/ADB. The actual SAR ROOT/init points directly to Android17 dynamic
second-stage init, whose main requires a stage argument. Bootstrap linker and
actual init dependency listing pass in read-only recovery tests. Snapshot05 now
selects a device-only static current-platform first stage and root-link/product
composition. It reuses existing A17 mounting/SELinux handoff code unchanged.
All1,243 projects/21 exact patches are audited; kernel/vendor/policy/FBE inputs
are unchanged. A complete new build and fresh package checks are in progress.
Neither snapshot04 nor the untested05 composition is a working-ROM claim.

**Latest physical progress:** snapshot05 installed with updaterRC0 and physical
static-stage link/hash verification. It reaches first-stage init, loads current
SELinux policy and enters second stage. The next real blocker is missing /acct
on immutable system root: real cpuacct setup fails and prevents ueventd/bootstrap
apexd process groups from being created. Snapshot06 adds only the existing
BOARD_ROOT_EXTRA_FOLDERS acct entry. A new actual target-files check requires the
directory and unchanged real controller contract; no policy/kernel/vendor change,
no fake successful mount and no encryption disablement. The replacement build
is running. The tablet remains in preserved TWRP with new crash logs secured.

**Current encryption blocker:** snapshot06 passes all package checks and installs
with physical /acct directory/context and kernel/vendor/recovery readbacks. The
new physical boot reaches real cgroups, ueventd, bootstrap APEX, vold and keystore;
audit records remain permissive=0. Vold then SIGSEGVs in the wrapped metadata-key
predicate, which dereferences an absent /metadata fstab entry. Snapshot07 changes
only this null check, preserving all actual file-encryption settings and existing
metadata flag semantics. UBSan reproduces the original actual function failure;
seven fixed-entry cases pass. A new complete product build is running. Successful
normal boot or FBE is not claimed; no encryption or policy bypass is introduced.

**Current LMKD blocker:** snapshot07 advances past the vold null dereference;
the actual file-encryption initialization command exits0. Full CE/user boot is
not yet proven. LMKD aborts in libmemevents global initialization because the
unchanged platform API-version parser requires netbpfload.rc, while this port
excludes the incompatible BPF loading service. Snapshot08 installs only the
byte-identical upstream version-comment line plus an explanatory comment: no
actions, service or BPF-ready property. Kernel capability comparisons now verify
the actual cached kernel meets the assumed platform minimum before relying on
that minimum; older kernels use the actual version comparison. Host tests retain
all parser aborts and supported-kernel results, and eliminate the4.4->5.8 false
positive. Kernel/FBE/vendor/SELinux inputs are unchanged; stock LMKD's real
in-kernel LMK path remains. A new full build is running. No BPF readiness is faked.

The official manifest was inspected at
`b51a0c449a3279ca55fb6d4d91d2143e42e2fff5` (`android-17.0.0_r1`).
The official `aosp_current` release alias resolves to `cp2a` in the inspected
build/release revision `c85f4aebe46714235599a9bd6430a0fe30c6e8d5`.
Use the alias in a fresh build shell rather than the old `bp4a` target.

The initial 23.2 port patches compiled successfully on Android 17 in
`native-policy-20261101-01` (exit 0, followed by full source audit). Selected
ARM/ARM64 ELF outputs are recorded in the reports; this is build/link evidence.

Active ROM and packaging snapshot is **port-20261116-04**, locking1,243 projects
and21 exact patches. The new signed test OTA is1,039,530,367 bytes, SHA256
`aa9b39e49d749fecb28a818d4f0ba0bff38f9e02b0ed2b7dd9e5e4f95d18d5fa`.
See experiments/runtime04-ota-build-20261116-01/readiness-report.json and its
bound reports. The complete product build passed128 actual steps in14:15,
with complete before/after source and binary-input audits. Fresh geometry,
multilib, strict policy/CIL/cache identity, six installer hooks, four ext4 images,
39-APEX VINTF, whole-file CMS/CRC and actual OTA block streams all pass.
All5,881 platform/vendor assertions and constraints remain; no permissive domains,
policy overrides or neverallow bypass are introduced. Kernel7ece8d6f, vendor2b40b8c7
and DTBO are unchanged. The OTA helper/updater exactly match the physically
executed snapshot04 binaries. Package checks alone are not boot/network/FBE proof.

The retained aa681b... candidate reports below and in historical experiments are
invalidated by the real Bionic startup failure. Do not install that older ZIP.
The new installer writes only system/product/vendor/boot and retains its genuine
read-only recovery and vendor-unmounted guards. Userdata formatting was a separate
owner-authorized TWRP operation, rather than a new OTA wipe/repartition command.
No private signing material, rollback image or ROM binary is published.

The previous network module build completed exit 0, including post-R8 Binder
identities, min31 AIDL16 ordinals, ten actual iptables registry entries and
installed native ELF outputs. See network-composition-build-20261115-01 and
network-composition-outputs-20261115-02.
It includes the device-scoped legacy v1 fscrypt keyring source integration;
actual init/vold module compilation and multilib keyutils checks have passed, as recorded below.
It adds a source backport of policy 30.0 compatibility data and generator modules,
with the frozen API30 source copied verbatim from the pinned prior platform.
The framework advertises 30.0 only for gta3xlwifi. Device inputs are separately
pinned by commit. Dedicated compatibility compilation and structural tests passed;
the current strict vendor policy and full product now compile successfully.
Recovery/FBE preparation remains separate from host validation.

The cgroup port retains cpuacct v1 process groups, mounts real supported v1
controllers, skips v2 subtrees only for this product, loads product profiles last,
and returns `EOPNOTSUPP` for the new clone-into-v2 API. The current Java/native zygote callers were reviewed: they use the legacy
process-group API, and native zygote actually uses fork. Live cgroup mounting,
profile application and cleanup still require device testing. Host cleanup/path
checks are separate from Android execution. Optional GPU BPF accounting still
reports unavailable, rather than invented counters. Existing safety/installer
and strict SELinux checks remain enforced.

## Native Binder identity after packaging — November 15

Actual A17 jarjar renamed all three private OEM Binder descriptors, breaking
agreement with native netd. Inactive private-aidl-jarjar-20261115-02 preserves
only these interface/nested-class names through the existing exclusion mechanism.
A fresh15-source compile, actual generator/jarjar transforms and javap verify all
three native descriptor matches and16 ordinals after packaging, with1243/17
audits. This remains an isolated contract proof; final Soong/APEX source/module
composition and the full product build are still required.

## Privileged userspace CLAT integration — November 15

Inactive clat-20261115-01 adds dedicated fullUID1000/session-bound raw-FD RPC16
on the existing provider. Exact IPv6/RAW/IPPROTO_RAW validation precedes tag0/
UID1029; ordinary1029 tagging remains denied. Actual ClatCoordinator uses real
userspace clatd and socket-owned final-FD cleanup without private BPF maps/cookie/
offload. Stock paths are preserved. Full CFI netd/OEM,16 AIDL ordinals and15 actual
Java sources pass; Java compilation now binds the original Soong Android core
modules.1243/17 and60366 kernel-source checks pass. Host checks pass2582 transport,
26622 owner,46245 kernel-function cases; prior Java suites replay and56 new CLAT
cases pass. Explicit raw/driver/Binder/process/API fixtures are not device tests.
Existing strict production/debug policies permit required borrowed-FD rights;
no policy change is needed. See experiments/clat-20261115-01.

No selected source/snapshot/kernel/vendor/policy is changed. Final Soong/APEX/
jarjar composition, explicit input selection, full ROM build and installation/
encryption/partition checks remain. No flash-ready package exists.

## Genuine loopback event delivery — November 15

Inactive loopback-rpc-20261115-01 exposes the existing real kernel consuming
stream through append-only RPC15, fullUID1000/current-session checks and bounded
unsigned sequence/loss validation. Actual CFI netd/OEM,12 Java sources,15 AIDL
ordinals/API compatibility, ARM32/64 and1243/17 audits pass. Host checks pass26592
native and87 new Java cases, including uncertain consume without retry.

Inactive loopback-worker-20261115-01 connects the real shared-session stream to
one Android handler worker and existing A17 statsd atom1216 with exact UID field
annotations and result enums. Actual ConnectivityService skips the BPF event
listener only for the private backend. All14 actual Java sources compile with
native prerequisite hashes and1243/17 audits; prior suites replay and36 new worker
checks pass. Actual proto/generated native encoding are bound; host API/syscall
fixtures do not establish physical device behavior. See the two experiments.

Selected source/snapshot/kernel/vendor/policy remain unchanged. CLAT, final
Soong/APEX/jarjar composition, explicit input selection, full ROM build and
installation checks remain. No flash-ready package exists.

## Durable UID cleanup and recovery — November 15

Inactive stats-removal-20261115-02 adds complete-state durable UID intents before
native RPC13, confirms actual kernel COMPLETE before clearing local statistics,
and gates first policy publication on real journal validation. Exact cached
completion preserves counters created for a reused UID; ambiguous/PREPARED
requests are not replayed. NSS skips private BPF maps/listener construction and
retires recorder/cache state per confirmed UID, including partial batch failure.
All12 actual Java sources compile against A17 SDK classpaths and1243/17 audits
pass. Host checks replay prior suites, pass62 durable transaction cases and18
backend/factory/NSS routing cases. Explicit platform/kernel/store fixtures are
not physical Android execution. See experiments/stats-removal-20261115-02.

Published f62e1d5 validates terminal-abort14:26528 native assertions, full CFI
netd/OEM/Java compilation and15 additional Java checks. Exact session+token abort
cannot withdraw a newer owner, even with a reused token. Normal close is nonfatal.
Strict receipt-policy production/debug probes preserve5918/5881 assertions and
constraints and pass17 permissions/labels/20 positive ioctl contradictions plus
negative674f/6764 neighbors. Only netd ioctl6763 is newly granted.

The isolated receipt kernel7ece8d6f retains PREPARED/COMPLETE across daemon
lifetimes and fixes both ioctl routing guards. Full Image/modules/Gator and
source/Android audits pass; host checks pass5454 with9830400 A17 GSO comparisons
and two80000-update concurrency cases. HOLD still counts dropped ingress.
Selected TOP, snapshot, kernel/vendor prebuilts and policy remain unchanged.
No flash-ready ROM exists.

## Actual factory and TrafficStats routing — November 15

Inactive candidate `traffic-stats24-20261115-01` contains complete durable factory
state and real shared-session UID/iface/total TrafficStats consumers. All12 actual
Java sources, Controllers/owner/lease/service CFI netd/OEM, unchanged11 AIDL
ordinals and ARM32/64 UAPI compile/link;1243/17 before/after audits pass. Native
regressions pass26339 assertions. Host tests replay1467 client cases,61 poll flows,
326 consumer and12 actual factory assertions, then26 TrafficStats/privacy checks.
These include genuine A17 NetworkStats/VPN/464xlat code and explicit host platform
boundaries; hardware behavior is untested. See stats-factory-20261115-01 and
traffic-stats-20261115-01. Native fatal-quarantine recovery is recorded in
policy-fatal-20261115-01. Commits36a3505,48ec5e0 and412b4ed preserve these deltas.

Selected TOP, snapshot, policy and prebuilts remain unchanged. Service map/listener
initialization and complete UID/socket cleanup still require porting, followed
by loopback events, CLAT raw sockets, final source/Soong/APEX composition, full
product build and installation/encryption checks. No flash-ready package exists.

## Durable statistics consumer lifecycle — November 15

Inactive journal schema2 now supports metadata before native acceptance and
explicit revision-CAS amendments that retain the real receipt through UID cleanup.
The poller rejects missing/regressed metadata and preserves cleanup on restore.
Actual four-source SDK compilation and1243/17 audits pass. Host journal checks
pass312; poll fixtures replay1467 client checks and pass61 flows. See
stats-lifecycle-20261115-01. Actual factory/service serialization/routing remain.

## Kernel-lifetime interface-name history — November 15

Isolated real ifindex/name history now survives removals and daemon lifetimes.
Full Image/modules, Gator118/KUTF43 ABI,60366/60366/60331 source audits and1243/17
Android audits pass; host checks pass4061. Authenticated native/Java routing,
CFI netd/OEM and ARM32/64 UAPI pass; owner/Java host checks pass26286/1924.
Both strict policy profiles preserve5918/5881 assertions and pass permission,
label and19 ioctl boundary probes. See iface-names-20261115-01. No selected
kernel/policy/source promotion or flash package is claimed.

## Frozen-bank poll transaction — November 15

The inactive poller now orders real SWAP/read, complete-state restoration,
durable acceptance/installation and final ACK, with receipt-based recovery.
Actual four-source SDK compilation and1243/17 audits pass. Host fixtures replay
1467 client cases and pass48 poll-flow cases including uncertain mutations,
journal/consumer faults and no invented empty baseline. See stats-poll-20261115-01.
Actual factory/service consumer routing and lifecycle remain; no ROM is ready.

## Durable statistics acceptance — November 15

An inactive journal now binds complete consumer state to genuine runtime boot
UUID and frozen bank/epoch. Explicit FD/directory sync, exact readback, integrity,
stale/conflicting replay and uncertain-write recovery are enforced. Actual SDK
compilation and1243/17 audits pass; host fixtures pass271 checks. See
stats-journal-20261115-01. Actual factory serialization/routing/lifecycle remain;
this primitive alone does not authorize ACK or establish flash readiness.

## Actual statistics transport — November 15

The inactive private Binder protocol appends genuine bounded statistics reads,
SWAP/ACK and counterset controls, all authenticated and session checked. Actual
AIDL compatibility/11 ordinals, CFI OEM/netd links, two final Java clients and
1243/17 audits pass. Owner/service host checks pass26184; Java lifecycle/decoder
checks pass1467, including full tables and lock independence. See
stats-rpc-20261115-01. Actual Android poll/persistence/boot-epoch deduplication and
consumer routing remain unfinished; no selected source or flash package changes.

## Private held boot preflight — November 15

An inactive product-selected init action now invokes actual private netd1shot
verification and then netd without inventing a BPF-loaded property. Actual CFI
main/provider/full netd, init verifier and1243/17 audits pass. Startup fixtures
pass38 cases; owner/DNS regressions pass26050, including distinct owners over
retained rule images. See private-boot-20261115-01. Full Soong graph/source
integration and device boot remain unvalidated; no flash candidate exists.

## Sole-owner DNS routing — November 15

The inactive DNS path now reads the same committed native policy as packet rules,
through the actual helper instance inside libnetd_resolv. Actual CFI resolver/netd
links, append-only export and1243/17 audits pass. Owner/DNS host checks pass26040;
actual provider/main startup cases pass23, including registration failure before
listeners. No callback registration is treated as networking Ready. See
dns-owner-20261115-01. Stats/events/CLAT, private boot admission, Soong composition
and full integration/installation checks remain.

## Actual framework policy routing — November 15

The inactive BpfNetMaps branch now chooses the real shared owner before BPF map
initialization. PermissionMonitor registers the actual raw/identity receiver.
Early policy is buffered while held; complete frames route ordinary/metered,
IIF/VPN/discard/LNA/permission state with actual runtime flags. Queries verify the
native generation. Five actual Java sources compile against current module/API
classes;1243/17 audits pass. Actual A17 query/Struct oracles pass219573 Java checks;
2111 emitted frames pass the actual native parser and270348 comparisons. See
framework-policy-20261115-01. DNS, stats/events/CLAT, boot/restart and real Soong/APEX
composition remain; this is not a flash candidate or hardware networking proof.

## Raw Java permission receiver — November 14

The inactive receiver now handles complete identities, raw permissions, exact SDK
UID expansion and serialized revocation/removal under the backend's shared lock.
It preserves observed INTERNET-only zero conversion and invalidates failed input
through a required sink. Current actual module/API compilation and1243/17 audits
pass; host fixtures pass2258 cases, including all1024 raw combinations. See
java-permission-collector-20261114-01. Actual observer registration, native backend
sink and BpfNetMaps routing are still required; no networking Ready is claimed.

## DEFAULT installation identity refresh — November 14

The inactive DEFAULT install path now refreshes actual package identity while
preserving its original decision to skip permission-policy/exemption changes.
Actual full71-source compilation preserves155 classes; thirteen helper/branch
fixture checks and all96 lifecycle cases pass, as do current API and1243/17 audits.
See permission-install-identity-20261114-01. Android boot/device execution and the
actual Java receiver/BpfNetMaps routing remain unvalidated and unimplemented.

## Permission identity lifecycle — November 14

The inactive permission-service proposal now sends complete same-state frames on
user/installed-UID identity changes before UID deltas, including zero-permission
packages. Per-consumer epochs, isolated callback arrays and unregister fences
pass96 host cases. Actual71-source compilation preserves155 classes; API and
1243/17 audits pass. See permission-lifecycle-20261114-01. The DEFAULT
install-path identity refresh is staged separately; Java receiver/routing is pending.
Selected Image/latest21-MTP vendor/DTBO and both strict policy profiles are rehashed
unchanged in policy-client-final-inputs-20261114-01. No flash candidate exists.

## Java policy transport lifecycle — November 14

The inactive actual Java client now uses the private Binder route for immutable
complete frames, exact generation CAS and bounded chunks. Failed publication
retires the token through real HOLD; uncertain cleanup remains explicitly
retryable. No automatic commit retry or connection-as-Ready behavior is added.
Actual original Connectivity classpaths, AIDL compatibility and complete native
CFI build/link pass; owner/service host tests pass25,856 assertions and Java
lifecycle/serialization fixtures580. See policy-client-20261114-01. Actual framework
state collection/routing and Soong source composition remain unfinished.

## Complete policy Binder transport — November 14

The inactive native service now accepts bounded ordered chunks for all ten policy
sections, validates complete state before the sole owner's generation commit,
and holds traffic on client death. Every RPC requires system UID1000. The OEM
getter preserves existing ordinals; actual AIDL compatibility, C++/Java generation,
Java stubs, full netd/OEM DSO CFI build/link and1243/17 audits pass. Host fixtures
pass25,709 assertions including partial input, permissions, capacity, session/death
and HOLD faults. See policy-frame-20261114-01. Java source collection/routing,
reconnect/query lifecycle and Soong composition remain; this is not a test ROM.

## Ordered initial framework permission snapshot — November 14

The inactive permission-service proposal now serializes the initial snapshot and
callback with live mutations. Same-state users and installed package UIDs include
zero-permission packages. Actual 71-source Kotlin compilation preserves the exact
155-class inventory; 81 host cases reproduce the old race and validate ordering,
metadata, duplicate registration, failure cleanup and old consumers. Actual
metalava generates the exact interface signatures, accepts full server API
compatibility and rejects a removed-method negative control. Original compiler
flags and all existing APIs remain. See permission-initial-snapshot-20261114-01.
No IPC/network readiness or selected source change is claimed.

## Atomic tagging and held mainline provider — November 14

The isolated native stack now performs tagging permission checks, real active
statistics budgets and transport I/O under the sole owner's transaction mutex.
It matches A17's canonical-UID UpdateDeviceStats logic, core/DNS exemptions and
CLAT prohibition. The real qtaguid transport closes on passive/inaccessible mode
and requires explicit recovery. App input/ordinary command errors preserve the
publication; session loss or protocol errors close the owner and hold traffic.

An explicit private libnetd_updatable entry point validates and publishes immutable
callbacks only after genuine held-owner/tag-session initialization. All three old
C APIs/default BPF behavior remain. The private main path verifies Controllers
and this provider before listeners start. It publishes no BPF objects or networking
Ready signal; complete framework policy is still required to release traffic.

All23,026 owner assertions,2,339 socket/FD transport assertions,29 registration
cases with6,400 concurrent callbacks and21 startup/cleanup cases pass. Actual18
server CFI sources plus new main and minSDK31 library dispatch compile; complete
netd and provider DSO link with unchanged dynamic dependencies and append-only C
exports. Actual ARM32/64 callback/wire checks and full1,243-project/17-patch audits
pass. Current strict production/debug policies each pass22 permissions,3 genfs
labels and7151 enabled/neighbor-boundary probes without changing assertions or
grants. See socket-tagging-owner-20261114-01 and held-provider-20261114-01.

The selected kernel/latest21-MTP-vendor/DTBO and strict policy inputs remain
unchanged, rehashed in held-provider-final-inputs-20261114-01. Java/Binder frames,
statistics/event lifecycle, privileged CLAT, boot admission and final installation/
encryption/package gates are unfinished. These inactive proposals are not a test
ROM or evidence of device execution.

## Active statistics for tagging budgets — November 14

The isolated kernel can now snapshot the real active packet-statistics bank
without swapping, clearing or acknowledging it. The existing READ ioctl/layout
is preserved; kind3 requires the exact current epoch and returns one locked
snapshot of sorted rows, loss and sequence. A distinct private compiled feature
bit protects the new reader. No SELinux assertion/grant or policycap changes.

The sole native owner reads the active rows under its existing mutex/descriptor,
returning actual total and per-chargeUID row counts. Errors withdraw published
state; invalid arguments preserve it. This supplies the data needed for tagging
budgets, not permission to tag or network readiness. Kernel tests pass 5,396 cases,
9,830,400 actual A17 GSO comparisons and two 80,000-update concurrency runs. Native
owner tests pass 3,250 cases. A complete matching Image/modules build and complete
netd CFI link pass, with ARM32/64 wire checks and full kernel/protected/Android
revision audits. See kernel-active-stats-20261114-01 and
active-stats-owner-20261114-01 for the exact staged proposals and evidence.

The actual generated and compiled Java accessor confirms UID migration enabled
in this checkout. The actual A17 tagging-budget guard passes 81 boundary cases:
limits500 perUID and4500 total, strict greater-than rejection. Flags are unchanged.
The selected Image/latest21-MTP-vendor/DTBO and every strict runtime policy input
and binary hash are rechecked unchanged in active-stats-final-inputs-20261114-01.
Authorized socket tagging and genuine mainline provider startup still need wiring,
followed by Java/Binder frames, statistics/event lifecycle and installation gates.
No flash-ready ROM or device execution is claimed.

## Sole owner in Controllers startup — November 14

The isolated Controllers candidate now acquires and verifies the single real
accounting lease before root-chain rebuilding. Existing atomic root guards are
retained. A checked bandwidth-only parent reset replaces the BPF-dependent
factory startup on the explicit private-backend path. The same descriptor then
installs and verifies the real accounting, socket and metered programs. The gate
remains held and all policy unpublished until a complete framework snapshot is
committed. The stock path and class layouts are preserved; a non-null owner
pointer is not a readiness signal.

The actual owner/transport passes 3,186 fixture checks, including both sides of
six acquisition and seventy completion I/O fault points. Actual Controllers init
and bandwidth-reset bodies pass 29 order/failure cases; the actual root-builder
differential passes 960. All sixteen actual Android 17 ARM64 CFI sources compile,
and the complete netd binary links with two replacement platform objects and
fourteen private objects in the original eighteen-member archive. Dynamic
library dependencies remain unchanged. ARM32/64 wire checks and full
1,243-project/17-patch before/after audits pass. See
controller-owner-20261114-01 and controller-owner-native-20261114-01.

This does not yet make the process runnable on the legacy kernel: the earlier
mainline libnetd_updatable initialization still requires its genuine replacement
provider, and Java/Binder initial-frame and delta routing are unfinished. Real
statistics persistence/ACK, tags/events and final installation/encryption checks
remain. Selected sources/kernel/latest21-MTP-vendor/DTBO are unchanged, rechecked
in controller-owner-final-inputs-20261114-01. No new ioctl/SELinux grants, startup
execution, flash candidate or hardware validation is claimed.

## Explicit runtime network modes checkpoint — November 14

The isolated kernel now implements Android 17's independent loopback checks and
metrics switches, and both permission-propagation and legacy blocked-UID local
network modes. A versioned 32-byte runtime image uses the existing authenticated
owner lease. Each new lease requires explicit confirmed configuration before
RELEASE; no mode is silently enabled or disabled. Exact revision/content SET
receipts are idempotent, and native publication requires matching real readback.
The owner commits all five states under one held lease, after the last firewall
operation, with runtime before LNA and UID permissions last. Any uncertain
kernel result withdraws the complete publication.

Actual kernel/pinned Android 17 predicate comparisons pass 49,152 LNA and
786,432 loopback combinations, plus 120 lifecycle/protocol cases. The full isolated
Image/modules build passes, retaining the product configuration, Gator/KUTF
imports and complete candidate/protected kernel and Android revision audits.
Image `ef3426a0c001f0dea8ac4203d7faf02a9c7ccc74f722fcdc74d3b5f9c7d771ee`
is an isolated build; it is not the selected Android prebuilt.

Native transport passes 71 cases; the combined five-state owner passes 2,711,
including generic and accounting failure-point replays. Packet transport's 99
cases pass on the current source. Fifteen actual Android 17 ARM64 CFI sources
compile and partially link without unresolved private namespace symbols. Actual
ARM32/64 compilation checks runtime field offsets, sizes and ioctl encodings;
all nine UAPI headers match the complete kernel. Source audits retain all 1,243
projects and 17 exact patches. These are compiler/host results, not device proof.

Both strict policy profiles pass with all 5,918/5,881 existing assertions and
constraints retained. Only exact runtime controls 0x6760/0x6761 are appended.
Each profile passes 17 compiled permission queries, real device/genfs label
checks, 18 enabled-ioctl contradiction tests and two denied-neighbor tests.
No neverallow bypass, permissive domain or automatic policy selection is used.
Failed attempts are archived unchanged alongside the final evidence.

See kernel-runtime-policy-20261113-01, runtime-transport-20261114-01,
runtime-owner-20261114-01 and runtime-policy-20261114-01. Current selected kernel,
latest LineageOS 21 MTP vendor and DTBO remain unchanged, verified in
runtime-final-inputs-20261114-01. Controllers/Binder/Java routing, complete initial
snapshot/delta ordering, statistics poll/persistence/ACK and event delivery remain
required, followed by installation, encryption and final-ROM checks. No flash
candidate or global networking readiness is claimed.

## Complete permission-frame checkpoint — November 13

An explicit first-publication path now validates the caller's complete user,
known-UID and raw permission snapshot before any transaction I/O. It preserves
observed INTERNET-only entries that convert to canonical zero, supplies explicit
NoInternet for missing known UIDs, and requires the actual framework's complete
root/system rows for each declared user. It rejects ambiguous, incomplete or
oversized input while leaving the gate held and the output unchanged.

The converter matches the actual pinned PermissionMonitor body in all 2,048
raw/loopback-flag combinations. The frame builder passes 39 cases, and the
integrated path adds 1,192 cases to the previous 1,537 owner/statistics checks,
including both sides of every 114 publication I/O fault points. Generic owner
regressions (994), fifteen actual ARM64 CFI sources, private namespace partial
linking, actual ARM32/64 wire checks and 1,243-project/17-patch audits pass.
See permission-bootstrap-20261113-01 and permission-bootstrap-native-20261113-01.
The initial pure host attempt stopped on an overly narrow source-spelling check;
run 02 validates the actual Kotlin long-mask expression and passes.

This validates a caller-supplied frame; Java snapshot collection/order, early
policy buffering and Binder/Controllers routing remain to be implemented. It
creates no BPF map or global readiness flag and selects no source/policy/image.
Selected kernel/latest LineageOS 21 MTP vendor/dtbo hashes were rechecked unchanged
in permission-bootstrap-final-inputs-20261113-01. Runtime loopback check/metrics
switches and LNA propagation/legacy-blocked-UID mode still need explicit source-
faithful control before actual service activation. No installation candidate exists.

## Published-owner statistics API checkpoint — November 13

All seven statistics controls now use the published accounting owner's existing
mutex and descriptor. Before publication they return EAGAIN; generic-only mode
returns EOPNOTSUPP without statistics I/O. Invalid arguments preserve the current
publication. Kernel/protocol failure withdraws all four states and closes/holds
the lease. Loss and epoch fields remain explicit; uncertain SWAP/EDIT never
blindly retries. Original owner implementation bodies remain unchanged.

The facade passes 286 new cases plus all 1,251 accounting-owner regressions;
the generic owner passes 994 checks. Fourteen actual ARM64 CFI sources partially
link, all seven facade symbols resolve, actual ARM32/64 layouts and complete
1,243-project/17-patch audits pass. See packet-owner-api-20261113-01,
packet-owner-api-host-20261113-02 and packet-owner-api-native-20261113-01.
The first host run retained a test-expectation failure: ordinary mutations after
quarantine correctly return EAGAIN; the production implementation did not change.

This remains a primitive API. Statistics polling/persistence, final UID/socket-tag
cleanup, Binder/Java routing and permission bootstrap still require integration.
No production source/prebuilt selection, global Ready or flash candidate exists.

## Actual packet accounting checkpoint — November 13

Both real socket-aware packet functions now feed the bounded UID/app store.
One UID/tag sample controls policy and accounting. Receive DROP (including HOLD)
is counted; output DROP and CLAT output are excluded. System DNS billing remaps
to the socket UID while preserving its tag. Capacity loss never changes verdicts.
Actual store plus actual packet functions match the pinned Android 17
bpf_traffic_account function in 7,200 flows, alongside the earlier 9,830,400 GSO
comparisons and 80,000 concurrent updates. ARM64 disassembly proves both compiled
packet paths reach record/loss, and all original output hooks remain bound.
See kernel-packet-hooks-20261113-01 and kernel-packet-hooks-build-20261113-02.

A separate compiled-producer bit 13 now distinguishes these paths from storage
bit 12. Eight getter checks across four configs and exact source identity checks
pass; packet/accounting bodies remain unchanged. A fresh full kernel and modules,
Gator/KUTF bindings, unchanged product config and all protected/Android source
audits pass. See kernel-packet-capability-20261113-01.

The single-lease accounting owner now requires both storage and compiled packet
producers before any firewall operation. Tests cover both missing bits, all
fourteen missing primitive flags, all 74 startup and 114 update I/O fault points,
and the existing hard cutoff before policy image publication. Primitive admission
(40), transport (99), generic owner (994) and integrated owner (1,251) checks pass.
Fourteen actual ARM64 CFI sources partially link, private namespace resolution
and actual ARM32/64 wire checks pass, and all 1,243-project/17-patch audits pass.
See packet-accounting-owner-20261113-01.

The five ioctl definitions and layouts are unchanged. All actual strict
production/debug policy inputs and compiled policy hashes were rechecked intact;
no new policy grant, neverallow exception or automatic selection was introduced.
The selected kernel/latest LineageOS 21 MTP vendor/dtbo are unchanged. See
packet-accounting-final-inputs-20261113-01. Earlier hook host runs 01/02 preserve
test-fixture compile failures; run 03 passed. Initial full hook build 01 stopped
on an old source-identity fixture; the reviewed helper is now accepted only with
its exact fixed hash, retaining all other identity checks. Full build 02 passed.

Statistics poll/lifecycle and Controllers/Binder/Java routing still need
integration with this one owner. No production source/prebuilt promotion,
network readiness, hardware validation or flash candidate is claimed.

## Packet statistics storage checkpoint — November 13

A real bounded UID/tag/counterset/interface store and app UID counters now build
in a fresh isolated kernel. Two banks use explicit epoch-bound swap/read/ACK;
loss is reported, and pending-bank deletion is rejected. Capacities match the
pinned Android 17 maps. Actual Linux 4.4 GSO metadata matches the Android 17
UID/app arithmetic in 9,830,400 comparisons; 109 cases and 80,000 concurrent updates
pass. Full Image/modules, Gator (118)/KUTF (43), unchanged product config, all 60,363
candidate/all 60,331 protected source hashes and Android 1,243-project/17-patch audits pass.
See kernel-packet-stats-20261113-01 and kernel-packet-stats-build-20261113-01.

Shared-lease Android transport passes 99 wire/fault cases, 994 generic and 1,245
accounting-owner regressions. Fourteen actual ARM64 netd CFI sources partially
link with no unresolved private namespace symbols; actual ARM32/64 layouts pass
for all five new controls. Uncertain swaps/edits close the lease without blind
retry. Reads do not consume; ACK is explicit and idempotent. UID statistics
removal does not remove socket tags. See packet-stats-transport-20261113-01.

Both production and debug policy compile with strict assertions enabled. Their
5,918/5,881 assertion/constraint inventories remain identical. Each passes 17 real
permission/label checks and 18 strict compiler ioctl oracles (16 allowed controls,
two denied neighbors). Only five exact new ioctl grants are staged. No policy
input selection, SELinux weakening or prebuilt promotion occurred. The selected
latest LineageOS 21 MTP vendor hash is unchanged. See packet-stats-policy-*-20261113-01 and
packet-stats-final-inputs-20261113-01. Earlier packet-store host runs 01/02 retained
the passing executable results but failed report writing due to a missing helper;
run 03 and the full kernel runner contain complete successful reports.

Private bit 12 proves storage/control only. Actual packet-hook production,
statistics poll/lifecycle and Controllers/Binder/Java routing are still required.
There is no network readiness or flash-ROM claim.

## Held accounting startup checkpoint — November 13

The actual BandwidthController now has an explicit private source factory with
real interface producers and empty metered parents; its other code remains
unchanged. AccountingRoots accepts only empty/known ordered prefixes, verifies
both families/all three tables before writing and preserves foreign rules.
The four-state owner can bootstrap these producers under its existing lease and
reverify them before publication, with no firewall operation after image SET.
129 component, 1245 integrated owner and 994 generic regression checks pass.
Fourteen actual ARM64 netd CFI sources partially link; both wire architectures,
all UAPI/source audits and private namespace resolution pass. Source factory
checks pass 1040 cases. See accounting-projection-20261113-01.

A truthful separate kernel primitive bit distinguishes compiled DROP correction
from producer registration; twelve getter/config checks, forty transport cases
and a full fresh kernel/modules/source audit pass. See
kernel-iface-capability-20261113-01 and iface-capability-transport-20261113-01.
Actual Controllers/Binder/Java routing, UID/tag/app/bank statistics and remaining
ROM gates are still required. No selected image or test-ROM candidate exists.

## Interface DROP correction checkpoint — November 13

All three actual postrouting wrappers now call the original policy and genuine
interface UNDO inside one outer RCU lifetime. The real store/wrapper passes 251
host cases and 60 actual Android17 counter-flow comparisons. Full kernel Image
and modules, Gator/KUTF CRCs, unchanged config, complete candidate/protected and
Android source audits pass. Complete normalized ARM64 output disassembly retains
all old code except the intended call target, including four compiled calls.
The finalizer verifies the exact expected module-export transition and all frozen
inputs, preserving earlier failed test-assumption logs. See
kernel-iface-egress-20261113-01 and kernel-iface-egress-final-20261113-01.
No producer rules or Android startup are activated; UID/tag/bank accounting and
service integration remain. No selected source/prebuilt change or test candidate.

## Interface counter primitive checkpoint — November 13

An isolated real interface XT producer, bounded global counter store and leased
snapshot pass 49 host cases and 786432 comparisons against the actual Android17
counter macro. Full kernel Image/modules, Gator/KUTF bindings, unchanged config,
60360 candidate/60331 protected source hashes and 1243-project/17-patch Android
audits pass. The same policy owner exposes snapshots with genuine loss and
quarantines on I/O/protocol failure; 25 transport and 994 owner tests pass. All
twelve sources compile with actual netd ARM64 CFI flags; both real ARM32/ARM64
commands validate wire layouts. A tenth builtin XT parser passes 25 cases and
full ARM64 iptables link with all 80 registrations. Strict production/debug
extensions preserve all 5918/5881 assertions/constraints and pass 17 access queries
plus 13 ioctl compiler probes each. See kernel-iface-stats-20261113-01,
iface-stats-transport-20261113-01 and xtables-iface-stats-20261113-01.

Producer-rule activation, UID/tag/bank accounting, actual service and startup
integration remain. Matching egress DROP UNDO is built in the checkpoint above. No new source, policy or kernel is selected into
Android images, no readiness is fabricated and no test-ROM candidate exists.

## Shared four-state policy projection checkpoint — November 13

A single genuine lease/mutex now covers private ordinary/ingress and filter
metered programs, both LNA tables, UID permission images and four-value publication.
All firewall work ends before LNA then UID SET/readback LAST. Shared20000-owner
union admission, real startup feature checks, stale generations and quarantine
are implemented.990 fault/publication tests and actual twelve-source ARM64 netd
CFI/partial link pass, with no unresolved private namespace symbols. The metered
parent bridge retains critical IPv6 exceptions and quota/foreign rules;141 tests/
1280 graph comparisons and nine-source CFI pass. See socket-projection-20261113-01
and metered-roots-20261113-01. Source startup/control routing, accounting and
Binder/Java/metrics delivery remain; no global readiness or flash candidate.

## Native ingress compiler checkpoint — November 13

Canonical IIF/lockdown/destination state now compiles into typed private input
rules within the fixed ordinary exemptions. Explicit wildcard0 is preserved;
discard precedes IIF, both actual kernel bits are required for ingress root
activation, and filter placement is rejected.72 host cases/1800 actual A17 C
comparisons plus180/90/59/84 regressions pass; seven actual ARM64 netd CFI sources
and all source/UAPI audits pass. See ingress-chain-20261113-01. Shared owner
capacity/image-size limits and complete atomic native/Binder/startup/accounting/
metrics integration still require work. No selected image or flash candidate.

## Private ingress predicate checkpoint — November 13

The isolated actual socket hooks now carry exact-skb DNS/direction metadata.
Read-only private IIF/lockdown and ingress-discard predicates pass240/2160 actual
A17 comparisons; context73 and owner92 regressions pass. Full kernel/modules,
60357/60331 source audits and1243/17 Android audits pass. Both new xtables plugins
pass76 callback tests and actual full ARM64 iptables link with nine private
registrations. See kernel-ingress-context-20261113-01 and xtables-ingress-20261113-01.
Native ingress state/compiler, atomic complete transactions, accounting and
Binder/startup/metrics integration remain required; no test-ROM candidate exists.

## Actual ordinary socket hooks checkpoint — November 12

The private ordinary program is now evaluated at actual supplied-socket receive
and egress stages in an isolated full kernel build. One UID sample spans tag,
ordinary, LNA and loopback decisions; CLAT precedes egress owner policy and DNS
cannot bypass ordinary DROP. Source-bound84 hook assertions plus all prior
regressions, actual ARM64 call relocations and full kernel/modules/source audits
pass. See experiments/kernel-socket-owner-20261112-01. Real VPN/IIF, accounting,
complete multi-table native transactions, Binder/startup and metrics consumer
remain required. Selected Android inputs are unchanged; no flash candidate.

## Private socket-table control checkpoint — November 12

The isolated dual-stack private tables now have one exact-skb UID snapshot and a
real registered-primitive capability. Full kernel/modules and all source audits
pass; selected prebuilts are unchanged. Held-gate root bootstrap/activation passes
180 fault/recovery assertions plus90/59/84 regressions and six-source actual ARM64
netd CFI compilation. See experiments/kernel-socket-{tables,snapshot}-20261108-01
(the table success is02), kernel-socket-capability-20261112-01 and
socket-roots-20261112-01. This does not attach packet hooks or complete the
ordinary/VPN/IIF/accounting, multi-table transaction, Binder/startup or metrics
consumer work. No flash candidate exists.

## Loopback enforcement and metrics checkpoint — November 8

Real actual-socket loopback permissions and packet-derived metrics now pass1797
host cases/98304 A17 permission comparisons, full kernel/modules and source audits.
Imagec3194ba82cbaf32e3cab903d9cae0dff534fd823ee0e1fad715f7edaa6473f58,
config unchanged. Bounded event queue/real loss/rate-limited LRU and authenticated
consumer are implemented; unknown receiver is never UID0, DNS does not bypass
loopback, and CLAT preserves the corrected A17 fallback. Strict production/debug
ioctl6759 grants retain5918/5881 assertions,17 queries and12 compiler probes each.
Private native consume client passes132 cases (+696/90 regressions), actual CFI
and ARM32/64 wire checks. See kernel-loopback-events-20261108-01 and
loopback-event-transport-20261108-01. No worker/Binder delivery, late ordinary/VPN/
IIF/accounting completion, global readiness or prebuilt promotion is implied.

## Native LNA transaction checkpoint — November 8

Real two-table LNA lease transport now passes696 host checks plus90 UID regressions
and actual Android17 ARM64 CFI/ARM32+64 wire ABI proof. Canonical state passes27096
checks/144246 kernel Patricia/reference comparisons and CFI. Combined rules/LNA/UID
transaction62 +publication106 cases pass, together with55/82 prior regressions.
Actual four-/ten-source CFI compile/link and1243/17 before/after audits pass.
See experiments/local-network-{transport,state,transaction,publication}-20261108-01.
These components remain isolated from production Binder/startup and prebuilts.

A subsequent source audit found the first egress prototype missed untagged CLAT's
actual socketUID fallback. Explicit kernel-egress-clat-20261108-01 corrects it;
100 egress cases include48 comparisons with the actual A17 accounting prefix.
Full corrected kernel/modules/audits pass (Image6bf52891...579d9, config unchanged).
Historical67ec0b37 output is
superseded for that case. No test-ROM candidate or global networking readiness.

## Socket-aware attachment checkpoint — November 8

The real receive LNA/shared gate hook now passes51 host cases and5,632 actual
Android17 parser comparisons, full kernel/modules and complete source audits.
Image808468364a79c037930089f4d5f2d63085ca7fdc52b9d0646a47c5ff59381529;
configuration remains unchanged. Native xtables70+7 registrations/link pass.
See `experiments/kernel-receive-context-20261107-01`. Ordinary UID/VPN/IIF and
accounting still require correct late socket attachment; this LNA component does
not complete networking. New output hooks (IPv4/IPv6/multicast) pass51 additional
host cases and full isolated kernel/modules/audits plus native xtables now pass
(exit0, Image67ec0b37...915bb). No prebuilt promotion.

## Current isolated networking checkpoint — November 7

The server reboot left completed results intact; SSH, idle processes and free
build.lock were checked at14:35 UTC. Active Android inputs remain unchanged.
Peer tuple lookup full kernel/modules/audits passed (Image04790c4..., host8+672).
The seven-bit UID permission value passed46 cases and two1048576-comparison A17
oracles plus actual ARM64 CFI compilation. Selected cache/generated Java flags
confirm UID-map migration and loopback metrics are READ_ONLY ENABLED. Dynamic
NoInternet, LNA, cross-profile loopback and real metrics remain required.
See experiments/kernel-socket-peer-20261106-01, uid-permission-state-20261106-01
and network-permission-flags-20261106-02. These isolated parts do not implement
the complete provider or constitute packet/hardware enforcement validation.

The new isolated sparse permission-image and real IPv4/IPv6 NoInternet kernel
completed exit0 (kernel-uid-permissions-build-20261107-01). Image660234ef...5559c,
unchanged configuration, matching Gator/KUTF modules, all60343/60331 source hashes
and1243/17 Android audits pass. Host81+124608 comparisons and44 lease regressions
pass; actual ARM64 objects contain both create-check call sites. No runtime proof.
The actual selected vendor image inventory1074 entries/60 init files and preserved
diagnostic archive8194 members contain no packaged .ko/module lists; vendor init
has no active module-load commands. Repeat this inventory on the final package.
See experiments/kernel-uid-permissions-20261107-01 and kernel-module-inventory-20261107-02.

Exact UID-image grants passed strict production/debug compilation, preserved
5918/5881 assertion/constraint records,17 access queries each, real labels and
seven enabled/two denied neighbor ioctl compiler probes. Primitive transport90
and original65 tests, real ARM64 CFI and actual ARM32/64 wire ABI checks passed.
Combined both-family rule/image transaction55 +old90 tests and3-source CFI passed.
Permission SET is last; no firewall I/O follows it before release. Any uncertainty
quarantines; only a verified previous full commit may resume after rule rollback.

Combined UID value publication82 cases +old164 regressions and actual9-source
ARM64 CFI/audits also passed. Ordinary updates retain permissions, UID removal
removes both, and neither value publishes until full kernel commit verifies.
See experiments/uid-permission-publication-20261107-01. These are isolated UID
primitives; Binder/Java/DNS registration and complete network startup remain.

Next LNA contract is recorded in experiments/local-network-contract-20261107-02:
selected migrated policy exempts only literal UID0/1000, not all core appIds.
Actual prefix tables/packet path, loopback/real metrics, VPN/IIF/DNS/CLAT/complete
attachments and final strict image/FBE/Keymaster/installer gates remain.

## Local-network kernel checkpoint — November 7

Real immutable1000-entry main/host Patricia tables, exact migrated permission
semantics and held-owner ioctls passed73 tests/787916 comparisons after adding
explicit64-bit interface wildcard and192-bit host override coverage. The exact
A17 parser/private match passed17 cases/2887305 parsed values/5774610 dispatches.
Two full isolated kernels/modules/config/source audits passed; latest Image is
9d7f49c7771883aa0d98f4dbe8147fc096b62bd0cc2c96a9859012b3682e0213.
Actual whole ARM64 iptables has70 original plus7 private registrations, all final
registry paths verified. Exact new ioctl policy grants passed strict production/
debug assertions, contexts/access and boundary probes. Actual ARM32/64 wire ABI
is40/32/4 bytes with identical command codes. All Android1243/17 audits unchanged.

Receive attachment is a material open gate: an actual-C composition fixture
reproduces that an unassociated early INPUT skb normalizes to root while the
supplied receiving UID is denied. Modern cgroup filtering supplies that socket
context explicitly. Plain INPUT activation is not approved; socket-aware receive
(and egress) placement, DNS/tag/NAT/guard/accounting order must be completed.
See experiments/receive-socket-context-20261107-01. No new kernel/network/policy
inputs were selected into Android images and no flash candidate exists.

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

[Ordinary UID-chain program compilation](experiments/uid-chain-program-20261106-01/)
passes35 boundary/structure cases and1,048,576 comparisons against the actual
Android17 BPF ordinary UID expression. It generates bounded typed nine-chain
images with exact membership/range compression, preserving output on failure.
Actual three-source netd CFI object compilation/linking and complete source audits
pass. Packet dispatch/core exemptions, metered and remaining backend features
are separate requirements; no kernel rule is installed by this compiler.

## Raw socket identity and metered programs — November 6

The isolated kernel now has separate raw socket UID and appId matches, preserving
owner revision1 and the separate receive-side lookup-appId path. Metered deny
has no core exemption; metered allow uses raw appId/core plus HAPPY membership.
Absent/non-full sockets use actual overflowuid, with literal65534 normalization
only for the appId/core view. Host fixtures compare the actual A17 expressions.

The complete kernel/modules build exits0, original config unchanged, Gator118/
KUTF43 CRC checks pass. Image is d99587cc3b1ff4b879f6fbfcb7cf36f0efacd9c7a184e96299a2dc63e8011348.
Complete60336 candidate/60331 protected and Android1243/17 audits pass before/after.
All four private extensions build into the whole real ARM64 iptables binary,
retaining70 old registrations and verifying all four new registration paths.
See [kernel source proposal](experiments/kernel-raw-uid-20261106-01/README.md) and
[iptables source proposal](experiments/xtables-raw-uid-20261106-01/README.md).

The [metered program](experiments/metered-chain-program-20261106-01/README.md)
compiles user/admin deny union, HAPPY/core allow and Data Saver to typed chains,
using family-default builtin REJECT and a bounded self-contained goto target.
Its51 host cases and1248 comparisons use actual A17 xtbpf predicates. Extended
checked I/O passes84 prior cases; ordinary compilation passes35 cases plus
1048576 A17 expression comparisons. Four actual C++ sources compile with Android17
ARM64 netd CFI flags and combine in an isolated relocatable object. Complete
source audits are included. Host socket/map/I/O behavior remains fixture-based;
no kernel rule/packet execution or device behavior is established.

These are inactive source proposals, not a complete network backend. Verified
parent packet dispatch, real Java/DNS/provider/startup ownership, mandatory local
network/loopback protection, VPN/interface state and final integration remain.
The owner requires implemented networking before the first test package. No
Android prebuilt promotion, readiness bypass, offline-first package, partition
change, flashing or signing is performed. The ROM is still not flash-ready.

## Committed UID-state transaction component — November 6

The [UID transaction proposal](experiments/uid-policy-transaction-20261106-01/README.md)
combines all12 typed chains with aggregate limits and serializes candidate updates,
actual dual-family commits and query publication. Start leaves state unpublished
and the kernel lease held. Explicit full initial state is required; every kernel
error withdraws state and closes the lease. Validation-only errors preserve the
previous value. No Java/DNS callback, service or global readiness is registered.

152 cases exercise all seven real C++ components with syscall/table fixtures,
including partial writes, errors after possible commit, rollback/restart and
concurrent reads/mutations. Final native02 compiles/combines all seven actual
Android17 ARM64 CFI sources with complete1243/17 source audits. Ordinary membership
now explicitly uses raw socket UID, matching bpf_traffic_account's actual argument
to bpf_owner_match; the prior Owner-selector proposal is superseded. The separate
lookup-appId primitive must not replace raw packet identity. Raw ordinary testing
passes38 cases and1048576 actual A17 predicate comparisons. Packet dispatch,
mandatory security, startup and real framework provider integration remain open.

## Ordinary owner packet-exemption primitive — November 6

The [private kernel match](experiments/kernel-owner-skip-20261106-01/README.md)
implements A17's exact ESP/TCP RST/ingress FIN ordinary-owner exemptions, including
its IPv6 option parsing and zero-on-read-failure behavior. No blanket loopback or
independent metered/LNA/VPN exemption is introduced. Host tests pass11 cases plus
5774610 comparisons with the actual A17 parser and skip function. The complete
isolated Image/modules build exits0, original config and Gator118/KUTF43 CRCs
preserved, complete60338/60331 and Android1243/17 before/after audits pass. Image:
b3b10669196c8864c6d6be0759b545db8e109f4f7e10ce0fb9604decc9665986.

The [fifth xtables extension](experiments/xtables-owner-skip-20261106-01/README.md)
links with the previous four into whole real ARM64 iptables. All70 old plus five
private registrations, including actual final machine-code registration paths,
are checked; complete Android source audits pass. No rules or packets are run.
The combined network-final-20261106-01 sequence finishes exit0. These inactive
primitives still require the authoritative packet dispatcher, independent
mandatory protections, framework/provider/startup wiring and device validation.

## Ordinary UID dispatch and current-route predicate — November 6

The [ordinary dispatch portion](experiments/owner-dispatch-20261106-01/README.md)
adds raw appId core and exact packet exemptions followed by nine bounded child
calls. Only BACKGROUND is skipped on interface1. Typed I/O rejects foreign target
aliases and requires included children. The full UID transaction now contains14
chains. Ordinary comparisons pass13 cases plus12582912 actual A17 owner-expression
comparisons; all eight transaction components pass164 lifecycle/error/concurrency
cases. Existing checked84 and metered51/1248 regressions pass. All eight actual
C++ sources compile/combine with Android17 ARM64 netd CFI flags and complete source
audits. No parent hooks or framework callbacks are activated.

The [non-loopback primitive](experiments/kernel-non-loopback-20261106-01/README.md)
is superseded for OUTPUT selection by the [current-route correction](experiments/kernel-non-loopback-route-20261106-01/README.md).
The correction uses skb's current destination device after mangle rerouting,
not a stale original hook output pointer.24 cases plus5774610 actual parser/skip
comparisons pass. Full Image/modules build exits0, original config and Gator118/
KUTF43 CRCs retained, full60338/60331 and Android1243/17 audits pass before/after.
Final isolated Image b131fcd4195b3781cea2fe6c84fe45c55acb688517dc2418832971b9f757773e.

All six private extensions link into whole ARM64 iptables with70 original plus
six private actual registrations. All native inputs remain hash-identical and
all four UAPI headers match the corrected full kernel; binary/archive hashes are
recorded in the reuse report. No rules or packets execute. Complete mandatory
LNA/loopback permission, VPN/IIF, DNS/CLAT, attachment/startup/provider/Java wiring,
installation and final-ROM checks remain. This is not a flash-ready ROM.

## Immutable socket creator prerequisite — November 6

The [isolated creator marker](experiments/kernel-socket-creator-20261106-01/README.md)
records real userspace inet creator UID independently of mutable socket/inode
ownership. Kernel sockets are unmarked; cloned/accepted sockets do not inherit a
marker. Existing initialization/copy/graft bodies and sk_uid behavior are retained.
Two helper tests plus960 credential/lifecycle comparisons and exact hook/source
contracts pass with fatal UBSan and explicit fixtures. No receiver lookup or
permission check is supplied and no active packet rule consumes this metadata.

Complete kernel/modules build exits0; Image dec48db3d5dbd684a9274823b3f1b8cc412c048606137a23dba595557fc77cbd.
Original config is retained. Rebuilt Gator118/KUTF43 imports match current exports;
full60338/60331 and Android1243/17 before/after audits pass. UAPI and prior native
six-extension inputs remain byte-identical, with reuse hashes recorded. Internal
struct sock layout changes require matching modules and a complete vendor-module
inventory before promotion. No original module/prebuilt is replaced. Mandatory
loopback/LNA enforcement and complete framework/startup/provider integration
remain unfinished; no flash-ready ROM is produced.

## Referenced creator reader prerequisite — November 6

The [kernel-only reader](experiments/kernel-socket-creator-read-20261106-01/README.md)
returns an immutable UID only for a marked full inet socket, preserving output
on unknown/null/request/timewait inputs. It never invents root or substitutes
mutable ownership.41 actual-helper/state cases and960 identity regressions pass
with fixtures/fatal UBSan. Full kernel/modules build exits0, original config,
matching rebuilt Gator118/KUTF43 and all60338/60331+1243/17 source audits pass.
Image dfd8e7fed78628a6254d61bf619b6afa8c76f8edf296214979a5340c386d4188.
Receiver lookup still must resolve request/listener lifetime correctly; this
reader supplies no socket search, permission decision, callback or readiness.

## November 21: fixed boot image patch level (build 38)

Samsung's TEE keymaster binds the FBE key blobs to the OS patch level the
bootloader reads from the booted image header (offset 44). The installed TWRP
recovery header carries `0x220001ab` (Android 17 / 2026-11). AOSP builds the boot
header from `PLATFORM_SECURITY_PATCH` (`INTERNAL_MKBOOTIMG_VERSION_ARGS` in
`build/make/core/Makefile`). Setting `BOOT_SECURITY_PATCH` alone only affects the
AVB property, which is unused here because AVB is disabled. Snapshot38 therefore:

- sets `BOOT_SECURITY_PATCH := 2026-11-01` in `BoardConfig.mk`;
- makes the custom Samsung boot rule in `mkbootimg.mk` pass
  `--os_patch_level $(BOOT_SECURITY_PATCH)`, and fails the build if it is unset;
- derives the installer preflight word in `releasetools.py` from the fixed boot
  level, requires the boot header to equal it and the system level not to be
  older, and keeps the kernel, release, helper, vendor and recovery guards.

`ro.build.version.security_patch` keeps following the platform. The prebuilt
vendor image is unchanged. Package checks (`check-runtime38-target-files24.py`,
`check-runtime38-bootspl-target24.py`) confirm header word `0x220001ab`, system
level = platform level, and a byte-identical boot.img to build 37. They also
confirm that the packaged hook keeps the same word for a later system month. The
build was installed and verified on the tablet. TWRP still decrypts `/data`
while system and boot levels are equal.

Trade-offs: keymaster rollback protection no longer advances with the boot
patch level, and attestation reports the fixed boot level.

Known limitation: the TWRP ramdisk's crypto preparation script requires the
system patch month to equal the recovery header month. After the next ASB
month, sideload installation keeps working without a header change, but TWRP
will not unlock `/data` unless that script is reviewed and changed. Whether the
TEE binds keys to the header level, the normal-world `configure()` system level,
or both is not yet determined, because all levels are currently 2026-11.

Future ASB months: only the platform/system level changes. Keep
`BOOT_SECURITY_PATCH`, `_BOOT_SECURITY_PATCH` and the preflight word, and leave
the TWRP recovery unchanged. Never raise the boot level without a reviewed
recovery header change, because a raise is one-way for the key blobs.

## November 21: recovery crypto script and preflight identity (build 39)

The owner chose to resolve the limitation above in TWRP. The TWRP ramdisk crypto
preparation script now requires the system patch month to be equal to or newer
than the recovery header month. Before, the two months had to be equal. Release
and format checks and all property copies are unchanged. Only that script and
its line in TWRP's own repacker hash manifest changed. The TWRP kernel, the
recovery DTBO and header word `0x220001ab` are byte-identical. The image was
written after a full backup and fully read back, and the new TWRP decrypts
`/data`.

The read-only OTA preflight helper recognizes only exact TWRP images, so
snapshot39 adds the new image identity and keeps the previous ones.
`test-runtime39-recovery-identity24.py` compiles the helper source in its host
test mode and runs it against the real images. Both the new and the previous
image are accepted. A raised header word, a single changed ramdisk byte and an
unknown image are refused. Build 39 was installed and verified. With this
change, new ASB months need neither a recovery header change nor another TWRP
change.

## November 21: GApps, product in system, ION for privileged apps and the network gate split (builds 40–43)

**GApps.** MindTheGapps 17 (official arm64 release 20261022, whole-package
signature verified) cannot work on this device: Google Play services ship only
as an EROFS APEX (`com.google.android.gmssystem`) and the Linux 4.4 kernel has
no EROFS, so apexd fails with `No such device`. NikGapps core 17 (official
20261119 release, SHA256 matching the release manifest) ships GmsCore as an
ordinary priv-app; its v3 signing lineage was verified back to Google's
`f0fd6c5b…` certificate. NikGapps core is installed and confirmed working:
Google sign-in, Play Store installs and self-updates of Play services/Play Store.
Play Integrity was not evaluated.

**Build 40: product folded into system.** The physical product partition
(299,480 KiB ext4) is smaller than even the MindTheGapps low-resource set.
Snapshot40 sets `TARGET_COPY_OUT_PRODUCT := system/product`, builds no product
image (`PRODUCT_BUILD_PRODUCT_IMAGE := false`) and drops the first-stage
`/product` mount. The partition table is unchanged; the old product partition is
left untouched and unused. `check-runtime40-product-layout-target24.py` checks
`/product -> /system/product` inside the real `system.img` (debugfs) and compares
the installer's own size rule with the ext4 free blocks. The first clean build
(`m installclean`) dropped stale files that earlier builds had carried in
`system`, among them `/system/bin/linkerconfig` (the runtime APEX provides
linkerconfig); the checker binds the exact file-set difference.

NikGapps finds a "dedicated" product block through TWRP's `/etc/recovery.fstab`
and would install into the unused partition. For the test, the `/product` line
was commented out in TWRP's runtime fstab (RAM only, recovery partition
untouched) and the old block was set read-only for the session. A release needs
either a TWRP without that line or matching instructions.

**Build 41: ION read for privileged apps.** Android 17 runs privileged apps
targeting SDK < 37 as `priv_app_36`, and Play services UI as `gmscore_app`. Both
were denied ION read, so Samsung gralloc could not allocate buffers and HWUI
aborted (`drawRenderNode called on a context with no surface`). The owner asked
for `priv_app`, `priv_app_36`, `priv_app_all` and `gmscore_app`; the new rule is
`allow { priv_app_all gmscore_app } ion_device:chr_file r_file_perms;` (no write).
Strict link keeps all 5,881 assertions/constraints, 321 compiled-policy queries
pass, and the vendor composition changes only the precompiled policy cache.

**Builds 42/43: network gate split.** Every policy publication
(`SocketPolicyProjection::applyLocked`) holds the private netpolicy lease while
both families' tables and the kernel images are replaced (about 0.4 s). While
held, the kernel dropped every ordinary app packet and `socket()` returned
`EAGAIN` for app UIDs, so bursts of rule changes (for example Play services
process-state churn) blacked out all apps and pushed TCP into SYN backoff. A
code-free debuggable test app gave an app-UID shell through `run-as`: 60
publications on another UID caused 19/136 `EAGAIN` and up to 2,447 ms connects.

The kernel now keeps a packet gate separate from the update lease
(`experiments/kernel-gate-split24-20261121-02/gate-split.patch`). `HOLD` with
argument `GTA3XLWIFI_NETPOLICY_HOLD_UPDATE_ARG` takes the update lease without
closing the gate; plain `HOLD`, opening, and closing/exit of the owner (every
netd failure path) still close it. ABI version 2. netd uses it only for normal
commits; framework suspension keeps the gate-closing `HOLD`. Build 42 used a new
ioctl number, which netd's SELinux xperm list denied; netd quarantined
(fail-closed) and system_server could not start. Build 43 reuses the allowed
`HOLD` number; no SELinux change. The same churn test on build 43: 82
publications, no `EAGAIN`, no timeouts, slowest connect 220 ms.
Batching of backend publications was not implemented; it would require moving
the native publish out of the policy lock.

## November 21: TWRP without `/product` and with the correct accent colour

The owner asked for a TWRP that matches the build 40 layout and shows the
standard blue accent. The new recovery image (SHA256 `33875693…`) was built
from the installed image (`96b3de24…`) by an offline ramdisk repack. Exactly four
ramdisk files changed:

- `system/etc/recovery.fstab`: the `/product` line is removed. Since build 40
  the ROM has no product partition (`/product -> /system/product`), and NikGapps
  no longer finds the old, unused product partition. The runtime fstab
  workaround is no longer needed.
- `system/etc/twrp.fstab`: `/product` and `/product_image` are removed, so the
  TWRP UI no longer offers to mount, wipe, flash or back up that partition.
- `system/lib64/libminuitwrp.so`: rebuilt with
  `TARGET_RECOVERY_PIXEL_FORMAT := "ABGR_8888"`. The decon framebuffer reports
  BGRA (red offset 16), but the panel shows red and blue swapped, so the theme
  accent `#0090CA` appeared amber (`#CA9000`). In the generated build files the
  only flag change is `-DRECOVERY_ABGR` for `libminuitwrp`. A rebuild in a
  separate output directory without the change reproduced the installed library
  byte for byte.
- `ramdisk-files.sha256sum`: the three matching lines.

The TWRP kernel, the recovery DTBO, board, cmdline, Samsung trailer and header
word `0x220001ab` are byte-identical. Only the ramdisk size and the image id in
the header were recomputed. The image was written after a full backup and fully
read back. The new TWRP decrypts `/data`, runs enforcing, and the owner
confirmed the blue accent. The TWRP device-tree change is in
`experiments/twrp-fstab-abgr-20261121/device-gta3xlwifi-twrp.patch`, together
with the repack, write and verification scripts (they expect the private
recovery images next to them and are not usable without them).

The OTA preflight helper recognizes only exact TWRP images. The next ROM build
must add `{40271888, "de91185c3dbbed822612c5478780aa0bd4cb1c77c0b20c42e29cd0301b3b65bb"}`
to `recovery_header_sync.cpp` and keep the previous identities (the same method
gives `01e34bd1…` for `96b3de24…`). Until then, OTA installs stop with
"Unrecognized recovery" before any write.
