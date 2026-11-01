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

Active snapshot **port-20261101-04** locks 1,243 projects and **15 exact patches**.
It adds a source backport of policy 30.0 compatibility data and generator modules,
with the frozen API30 source copied verbatim from the pinned prior platform.
The framework advertises 30.0 only for gta3xlwifi. Device inputs are separately
pinned by commit. Dedicated compatibility compilation is currently pending;
strict actual-vendor policy is not approved and this is not a full ROM build.

The cgroup port retains cpuacct v1 process groups, mounts real supported v1
controllers, skips v2 subtrees only for this product, loads product profiles last,
and returns `EOPNOTSUPP` for the new clone-into-v2 API. Its Android 17 zygote
callers and runtime behavior require further investigation. Host cleanup/path
checks are separate from Android execution. Optional GPU BPF accounting still
reports unavailable, rather than invented counters. Existing safety/installer
and strict SELinux checks remain enforced.

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
