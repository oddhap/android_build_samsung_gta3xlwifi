# Actual-vendor checks and spawn FD hygiene — October 20, 2026

This continues the successful `native-policy-04` compilation. It is **not a
complete ROM, a security approval, or a physical Android 16 test**. No device,
working 21/TWRP tree, signing key, or existing user data was changed.

## Source state

Current replay snapshot: `snapshots/bringup-20261020-04/`, with **1,168 exact
project revisions and ten captured source patches**. The first nine patches
are unchanged from `bringup-20261020-01`; the tenth is Bionic's spawn fallback
and its native regression tests. The patched-state audit passed: exact HEADs,
commit/tree objects, exact reviewed changes, no external Git alternates.

`bringup-20261020-02` is historical: its 4 KiB scan buffer failed libc's 2 KiB
stack-frame check on ARM32/ARM64. Snapshot 03 uses a 1 KiB buffer instead. The
warning/error checks were not disabled. Do not choose snapshot 02 as the current
port. Snapshot 04 additionally verifies real procfs and the scan FD's presence,
so an ordinary chroot directory or an empty scan cannot silently defeat FD
hygiene. Sources were not resynchronized or advanced to a different platform.

## Actual vendor and kernel inputs

The vendor was extracted **without mounting** from the checked hybrid image
in the isolated 23.2 device tree, using `simg2img` followed by read-only
`debugfs -R 'rdump / DESTINATION'`. It is not Soong's generated vendor metadata.
Extraction and validation artifacts remain on the VM at:

`/srv/android/artifacts/lineage-23.2-arm64/vendor-validation-20261020/`

| Input | SHA-256 |
| --- | --- |
| Sparse hybrid `prebuilt/vendor.img` | `276777b5bde1dac2f31dbe9299c79e02c07486df6ff7b2ecad03cc722edee939` |
| Converted `vendor.raw.img` | `4c320e8bfd9db294e4027acae204a8276c8f06d0e522654f668e38550eded7b9` |
| Actual `vendor_sepolicy.cil` | `8df663eb65a807e6ee99f8b2384cb52d34c994a25087410486b1f88e278e2e53` |
| Baseline `kernel-dt2w/kernel.config` | `fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea` |

The kernel remains the preserved **4.4.302 prebuilt**, not an Android 16 kernel
rebuild. Its configuration explicitly disables `CONFIG_BPF_SYSCALL` and
`CONFIG_BPF_JIT`, while enabling `CONFIG_NETFILTER_XT_MATCH_QTAGUID` and
`CONFIG_NETFILTER_XT_MATCH_BPF`. The latter does **not** supply the missing modern
eBPF syscall/cgroup backend. Real legacy networking work remains necessary.

## SELinux: runtime link succeeds; strict verification FAILS

`tools/check-vendor-policy.py` links the built platform, v30 mappings,
system_ext/product policy, and the **actual extracted** vendor CIL. Vendor
mapping version is `30.0`. Binary policy version 30 matches this kernel's
source-supported maximum. The old vendor has no genfs version file; the pinned
`libgenfslabelsversion` defaults to 202404, for which no extra fragment exists.

- Mandatory strict invocation: compiler exit **255**, **367 neverallow
  diagnostics**. The validation tool itself correctly returns **1**.
- Failed assertions originate in platform CIL (194), vendor's versioned public
  CIL (155), vendor CIL (14), and system_ext CIL (4). These are diagnostic counts,
  not a count of distinct vulnerabilities.
- Examples include legacy Samsung app ptrace constraints versus `llkd`, old
  versioned public assertions versus newer platform domains, and conflicts with
  vendor allowances. They must not be hidden or treated as strict success.
- Optional **diagnostic only**: repeating the existing Android 16 init flags
  (`-m -M true -G -N -c 30`) links successfully. This demonstrates that this normal
  split-policy input set can be compiled by init. `-N` omits compile-time
  neverallow assertions; it is not SELinux permissive mode. No source/boot
  enforcement setting was changed. This result **does not override the failed
  strict check or establish security equivalence**.
- Inspecting that diagnostic binary with `sepolicy-analyze ... permissive`
  lists `su` and `backuptool`, inherited from userdebug/Lineage policy. No new
  permissive domain was added by this work. The device's runtime policy and
  enforcement have not been tested on Android 16.

Raw CIL/compiler logs and diagnostic binaries stay in VM `policy-01/`; the
non-secret input hashes, commands and exit statuses are in
`reports/vendor-policy-20261020.json` here. No vendor binary/CIL payload or
private backup is published by this report.

## VINTF: current static metadata is COMPATIBLE, with explicit limits

`vendor-metadata-02` successfully built the current host `checkvintf`,
`assemble_vintf`, system/system_ext manifests, standard framework matrices,
the device-carried FCM 3 matrix, Lineage matrix and legacy SDK fragment:
**1,985 actions, exit 0, 18:31:50 UTC**, 4 minutes 28 seconds.

`tools/check-vendor-vintf.py` then reports **COMPATIBLE / exit 0**, using the
actual extracted vendor manifests/fragments/matrix, shipping API 28, and the
real 4.4.302 kernel configuration. There is no separate ODM partition; its map
is empty. Tool and JSON retain the kernel configuration and hashes.

Limitations are important:

- This checks the **currently built metadata**, including the inherited
  device-specific legacy FCM 3/kernel profile. It is not a pass of unmodified
  Android 16 runtime kernel requirements. The modern network loader remains
  incompatible with this kernel.
- The actual build-output `/apex` directory is mapped. A complete activated
  `apex-info-list.xml` does not yet exist; no empty list was manufactured and
  no `apex.all.ready` override was used. Libvintf tolerates a missing list, so
  **full post-APEX compatibility is still unproven**. Repeat against complete
  target-files with all activated APEX manifests before any candidate.
- The tool warns that device manifest/kernel release do not declare an explicit
  kernel FCM version. The warning is retained, not suppressed.
- No HAL has been physically exercised, and no boot/linker/FBE operation is
  proven by these XML checks.

The reproducible invocation and input hashes are in
`reports/vendor-vintf-20261020.json`; VM raw evidence is in `vintf-03/`.
The earlier metadata attempt requested the disabled `product_manifest.xml`
module and stopped with an unknown-target error. Removing that nonexistent
request, not changing product HAL requirements, fixed the build. An initial
checker invocation lacked `/apex` mapping; that tooling error is also preserved
in `vintf-01/` rather than called a vendor incompatibility.

## Bionic: real close-on-exec fallback, not a dummy syscall success

Changed `bionic/libc/bionic/spawn.cpp` for `POSIX_SPAWN_CLOEXEC_DEFAULT`:

1. Keep the existing `close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)` fast path.
2. Only on `ENOSYS` (no syscall) or `EINVAL` (no CLOEXEC flag), enumerate the
   child's real `/proc/self/fd` using raw `__getdents64` into a fixed stack buffer.
   Require `fstatfs` to identify procfs and require the scan FD to appear in the
   enumeration; an ordinary directory or unexpectedly empty scan fails closed.
3. Set `FD_CLOEXEC` on every open non-stdio descriptor. Do not scan only to
   `RLIMIT_NOFILE`: existing descriptors can survive above lowered soft **and
   hard** limits. The helper's directory FD is itself CLOEXEC and is closed.
4. Do not use allocator/stdio/directory-stream APIs after fork/vfork. Preserve
   original error codes and fail closed on access, enumeration or flag errors.
   Other `close_range` errors, including `EPERM`, are propagated, not bypassed.
5. Leave original spawn file actions in place: intended `dup2` descriptors,
   including same-FD dup2, can still survive exec. Parent flags are unchanged.

Fallback requires readable procfs and a spare FD slot. If unavailable, including
`EMFILE`, the child exits through the existing spawn failure path instead of
leaking descriptors. This is a spawn-specific compatibility implementation;
it does not pretend the kernel now implements the public `close_range` syscall.

`tools/test-spawn-cloexec.py` compiles the **actual extracted production helper
and dup2 action** on the Linux VM. **42 cases passed**: real fast path, forced
ENOSYS/EINVAL, fork/vfork, distinct/same-FD dup2, actual exec, 400 descriptors,
high FDs above both lowered limits, parent flag preservation, multi-read procfs
scans, EPERM, access/FD-flag/enumeration/statfs failures, malformed records,
unexpected empty scans, a real non-procfs directory, and EMFILE.
Only syscall call sites are redirected for fault injection. These are real host
process/FD tests, **not tablet tests**.

Two native tests were also added in `bionic/tests/spawn_test.cpp` for normal and
USEVFORK spawn with CLOEXEC_DEFAULT, leaked-FD rejection, intended inheritance
and parent flag preservation. They must still run on Android hardware.

Six temporary-fixture safety tests for the validation CLIs pass on Mac and VM,
including that successful init-style linking cannot turn strict failure into
success. Fixtures are not used for the actual-vendor results above.

`bionic-linker-02` **completed successfully at 18:46:21 UTC**, exit 0, **9,065
of 9,065 actions**, 8 minutes 3 seconds. It compiled libc/linker/linkerconfig and
both ARM32/ARM64 Bionic test binaries against snapshot 03. Native test binaries
exist under both `data/nativetest/` and `data/nativetest64/`; they were not run on
the tablet. This also passed the existing libc ABI comparison targets.

The final follow-up **`bionic-linker-03` completed successfully at 18:51:34 UTC**,
exit **0**, all **157 incremental actions**, 4 minutes 14 seconds. This builds
snapshot 04's additional procfs safeguards with the same requested targets.
The latest source state therefore passes the targeted cross-build as well as
42 host FD-hygiene tests. **No Android test was run on the tablet**, and this is
not a full ROM. No build from this attempt remains running.

## Reproduce checks on the VM

From the integration `lineage-23.2` directory, with a **new** output directory
for each validation run:

```sh
TOP=/srv/android/src/lineage-23.2-arm64
VENDOR=/srv/android/artifacts/lineage-23.2-arm64/vendor-validation-20261020/vendor
python3 tools/test-spawn-cloexec.py "$TOP/bionic/libc/bionic/spawn.cpp"
python3 tools/test-vendor-validation.py
python3 tools/check-vendor-policy.py --top "$TOP" --vendor "$VENDOR" \
  --output /NEW/OUTPUT/policy --runtime-diagnostic
# Expected exit 1 until the strict conflicts are resolved; diagnostic success is not a pass.
python3 tools/check-vendor-vintf.py --top "$TOP" --vendor "$VENDOR" \
  --kernel-config /srv/android/artifacts/kernel-dt2w/kernel.config \
  --output /NEW/OUTPUT/vintf
```

Remaining gates: real networking/firewall/accounting/DNS/CLAT backend, strict
policy/security review and complete post-APEX VINTF, both-ABI runtime/kernel
execution, real Mali/HAL/TEE/FBE operation, guarded recovery/non-A/B OTA,
partition sizes/signing and finally owner-approved installation with rollback.
