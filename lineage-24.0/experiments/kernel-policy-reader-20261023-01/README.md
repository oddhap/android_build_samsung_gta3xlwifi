# Kernel version-30 AVTAB forward-record fix — isolated, NOT flash ready

Three production kernel files / one checksum-locked patch. **Not applied to
Android TOP, not installed or copied into a prebuilt.** This is a reader fix,
not a claim of modern netlink extended-permission enforcement or complete policy
compatibility. Qtaguid work remains separately locked in
`../qtaguid-persistent-20261022-02/`.

## Actual problem reproduced

The source-locked Android libsepol reads the actual init-style diagnostic binary
from the finished userdebug policy as **1,177 ioctl-kind-1 / 92 nlmsg-kind-3 rules**.
A fresh production `user` policy has **1,159 / 91** respectively. Both binaries
have format version 30, but **netlink_xperm capability bit 9 is OFF**. Source and
binary version numbers alone were therefore insufficient compatibility evidence.

The preserved Samsung `avtab_read_item()` assumes any non-1/non-2 extended kind
is an old Android-M ioctl encoding with no second driver byte. Actual modern kind
3 has that byte. The extracted actual old reader consumes **41 of 42 bytes**,
turns a real nlmsg entry into ioctl-driver 3 and enables its global M compatibility
mode. A following record is then misaligned. Controls verify normal native ioctl
and genuine old M driver 0x89 input. The mismatch remains a recorded **exit 1**, not
a passing compatibility check. This is actual binary-derived record data, not
an invented replacement API. Type/class bounds and input I/O are host fixtures;
this does **not** execute a kernel or prove loading the whole binary.

## Scoped correction and deliberate fail-closed gate

- Recognize native extended kind **3**, read its actual second byte and do not
  switch to M format. Existing kind-1/2 native encodings and representative old M
  control remain intact. The ancient M driver-3 encoding is intrinsically
  ambiguous with modern kind 3: this device shipped Android 9, not M. We explicitly
  prefer the modern format; **no universal Android-6 policy-ABI claim** is made.
- This preserves **inactive** forward-format data, as the pinned Android 16 6.12
  kernel reader can do. It does not enable netlink_xperm or pretend its AVC/base-
  permission/hook enforcement has been backported.
- After reading policy capabilities and before reading the AVTAB, the real loader
  **rejects active netlink_xperm bit 9 with EOPNOTSUPP**. The existing kernel does
  not have the required enforcement. No capability is advertised and no active
  required feature is silently ignored. A later full feature backport is a
  separate reviewed project, if needed.
- All policy rules, neverallows, domain enforcement and current capability bits
  are untouched. **No -N override changes a strict failure into approval.**

## Evidence

- Actual original-vs-patched reader tests use the production C function and
  structures, ASan/UBSan. The expanded suite has **25 cases per policy**: 3 format
  controls, 8 real nlmsg records, each followed by a native ioctl record, and 6
  truncated modern-record checks. Original reader remains INCOMPATIBLE; patched
  production and userdebug record suites PASS. Not whole-policy execution.
- **8,192 combinations** of policy-capability bits pass against the extracted
  actual production guard, plus a source callsite ordering/error-propagation
  assertion. Bitmap storage is a fixture, not real kernel enforcement.
- Eight CLI safety cases PASS on Mac/Linux. Vendor-checker safety suite expanded
  to 11 cases (isolated output selection, path/alias protection, no fallback).
- Complete independent kernel build **exit 0, 2026-10-23 16:29:25 UTC**, same
  preserved config and actual baseline `efbdbfa3...` + complete four-file input/
  touch delta + separately locked qtaguid patch + these reader edits.
  **Image 25,443,704 bytes**, SHA-256
  `1967fd98c56c7812e6b8cb0450fc000052fc9709ce6a6221370afb50d7d8c665`.
  Native/compat qtaguid ioctl pointers and exact ELF→Image reconstruction still
  PASS; reader/load-function disassembly is archived. Not hardware execution.

## Production policy build does NOT solve policy/security

A fresh isolated **`user` policy-only build** completed exit 0 at 16:12:38 UTC
(2,546 actions, reported 11m58s), without changing `out/`, active sources or any
ROM. Its combined actual-vendor diagnostic binary has **zero permissive domains**,
versus inherited su/backuptool in userdebug. But strict linking **still FAILS with
281 neverallow diagnostics**, versus 367 userdebug. The 86 removed diagnostics
are a configuration comparison, not 86 source security fixes. Debug-only behavior
was not the full problem. No product type/neverallow or vendor image is changed.

Concrete vendor-private/platform duplicate type names were also observed, notably
`uwb_service` (vendor line 3337 / platform service type). The old vendor's
platform_app registration and new system_server service labeling conflict. These
need scoped namespace/effective-policy review, not automatic broad allow rules or
blind renaming of every shared type. None is claimed fixed here.

## Reproduction / remaining blockers

See `reports/policy-kernel-reader-20261023.json`. Runner copies and full baseline
touch delta are archived beside this file. Their hardcoded fresh paths are already
used; don't rerun over existing outputs. Remote build source/output:
`/srv/android/ports/lineage-23.2-arm64/kernel-socket-owned-20261022-01/`
`src-policy-reader-20261023-01` / `out-policy-reader-20261023-01`.
Artifacts: `/srv/android/artifacts/lineage-23.2-arm64/`
`kernel-policy-reader-build-20261023-01/`, `kernel-policy-reader-link-20261023-01/`,
`kernel-policy-reader-host-20261023-03/` (userdebug), `...-04/` (user),
`kernel-policy-reader-old-20261023-02/` (expected failure).

Complete network backend/owner/enforcement, other legacy SELinux capability and
whole-loader behavior, strict vendor policy, HAL/APEX, FBE/recovery/OTA/signing
and approved hardware/backup/rollback tests remain unresolved. **No flash-ready
ROM or security approval is claimed.** Original Image, DTBO/vendor, full-platform-03,
LineageOS 21, TWRP, owner keys and userdata remain untouched.
