# Legacy kernel NNP/nosuid policy-capability backport — initial experiment

**Historical revision, superseded by `../kernel-nnp-transition-20261023-02/`.**
This first kernel linked successfully at 17:49:19 UTC but retained the old mount
flag-only detection. Revision 02 adds mount-namespace membership and an explicit
USER_NS=n build guard. Its larger oracle suite is the current result. Preserve
this earlier patch/build as evidence; do not integrate it or rerun its paths.

**NOT integrated into the ROM; NOT a flash-approved kernel.** No preserved
source/output, Android prebuilt, vendor, TWRP, owner keys or device is changed.
No platform policy/neverallow/permissive settings are altered.

## Actual gap and scoped implementation

Both real Android-16 production-user and archived userdebug diagnostic policy
binaries enable **capability bit 5 (`nnp_nosuid_transition`)**. The old 4.4 kernel
recognizes only bits 0–3 in its capability enum and has no `process2` class. Its
`check_nnp_nosuid()` allows changed SIDs only through bounded transitions.

The five-file patch adds:

- capability **5 explicitly**, preserving old 0–3 numbers; bit 4 remains an
  unnamed gap, **not advertised as implemented cgroup_seclabel**;
- the `process2` class **appended**, preserving every existing class/permission ID;
- loading/resetting the capability on policy reload;
- the `nnp_nosuid_transition` selinuxfs capability name and null-safe handling of
  the intentionally unnamed slot;
- the modern explicit `process2` AVC permission check before the existing bounded
  fallback. NNP and nosuid together require **both** permission bits. Capability
  OFF preserves legacy decisions. Failed AVC checks still try the bounded
  fallback; final errno remains NNP `-EPERM`, nosuid `-EACCES`.

All ordinary exec checks (`process:transition`, `file:entrypoint`, execute-no-trans,
shared state, audit, automatic fallback versus explicit-exec-SID errors) remain
byte-identical outside the extracted helper. No arbitrary UID or domain bypass,
new SELinux allow, removed neverallow or permissive setting is introduced.

**Scope limit:** this retains the old kernel's `MNT_NOSUID` detection. It does NOT
backport modern `mnt_may_suid()` user/mount-namespace behavior. The actual config
has `CONFIG_USER_NS` disabled, but that alone is not proof of full mount-namespace
equivalence. Other modern policy capabilities (including extended socket classes
and functionfs labeling), whole-policy loading, AVC/exec/runtime/reload concurrency
still need review. Bit-5 support does not certify all enabled capability semantics.

## Real policy versus fixtures

A separate source-locked Android-libsepol inspector reads the actual version-30
user/userdebug diagnostic binaries (not an invented policy). Both have bit 5 set.
Userdebug grants unconditional nosuid-transition TE permission for
`kernel → overlay_remounter` and `overlay_remounter → init`; **user does not**.
Neither queried binary grants `platform_app → init`. The inspector does not
execute AVC constraints, role/MLS checks, full exec authorization or runtime.
These variant differences are retained, not replaced by new grants.

The archived `test-host-mountflag-only.py` extracts the actual patched, preserved and pinned
Android-16 functions plus the actual capability-loading helper and class tables:

- **8,192 decision cases** match the actual pinned Android-16 function after
  explicitly normalizing its mount detection to the 4.4 flag expression.
- **120 legacy/modern decision differences** are reproduced, not labeled tests
  of live devices. Explicit single-permission grants fail when both flags apply.
- **8,192 bitmap combinations** check actual load/reset helper control flow.
- All **56 old class tables and every permission position** remain unchanged.
- **ASan/UBSan + Wall/Wextra/Werror PASS Mac and Linux**. AVC, bounded decisions,
  credentials/mounts, bitmap and nlmsg initialization are fixtures, not real LSM.

The first strict-host attempt hit the original mapping header's `{ NULL }`
terminal sentinel (`-Wmissing-field-initializers`). It is retained in evidence.
The host fixture now explicitly zero-initializes ONLY that sentinel; no production
entry or compiler warning is disabled. The production kernel table format stays
unchanged apart from the appended class.

## Reproducibility / integration boundary

`staging-lock.json` locks **five files / one kernel patch** to manifest revision
`669b9584e678ce5865ed38e04c24639082d78de1`. All five original inputs byte-match the
actual preserved build baseline `efbdbfa3e216b0c300d381c340b0a22b24e15c13` as well.
This does not claim complete identity of those different source trees.
Actual Git forward/reverse-check replay and read-only locked-TOP apply-check pass.

`build-kernel.sh` uses a fresh no-hardlinks/no-alternates clone/output. It captures
the complete four-file input/touch prerequisite, checks every locked reference
hash, applies ONLY the kernel parts of socket-owned qtaguid final revision,
policy-reader and this transition experiment, verifies staged hashes, runs actual
record/capability/transition tests, then builds with preserved config/toolchain/
firmware inputs. No working staged file is copied in place of a locked patch.
Do not rerun its hardcoded fresh paths over existing outputs.

The complete original ROM still has 367 strict userdebug diagnostics; original
user policy 281, separate metadata experiment 279. No networking/backend/runtime/
FBE/recovery/OTA/signing/hardware approval is implied. Source snapshot 06 remains
authoritative; see `reports/kernel-nnp-transition-20261023.json` for build/link
status and exact evidence once recorded.
