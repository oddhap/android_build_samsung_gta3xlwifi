# FunctionFS per-inode labels + bounded NNP backport — isolated kernel

**Complete kernel/link PASS, NOT kernel/USB execution, security approval or a
flash-ready ROM. No TOP/prebuilt/device modifications.**

## Patch relationship and actual gap

This **five-file/one-patch combined capability experiment includes NNP02** and
adds FunctionFS. It is based on the original manifest files and **REPLACES** the
NNP-only patch when building; **do not stack both patches**. Qtaguid-persistent02
and policy-reader are still separately checksum-locked kernel patches.

Both actual user/userdebug Android-16 diagnostic binaries enable **bit12,
functionfs_seclabel**, and contain **genfs functionfs / → functionfs**. The old
kernel does not recognize that capability or mark FunctionFS as per-inode
labelable/genfs-path-aware. Its actual config has **USB_F_FS=y and
USB_CONFIGFS_F_FS=y** (standalone USB_FUNCTIONFS=n is NOT absence of configfs FFS).
The existing driver creates endpoint files without an inode setxattr operation;
the existing VFS security-xattr fallback can update the in-core SELinux SID once
normal authorization has succeeded. No new driver/xattr implementation is invented.

The scoped addition:

- explicit **capability12** number/name and load/reset on policy change;
- only capability-enabled FunctionFS gets special GENFS per-file label support
  and SE_SBGENFS path lookup. Capability-off retains no FunctionFS GENFS labeling;
- use the modern FS-behavior switch: XATTR/TRANS/TASK/NATIVE labelable,
  selected GENFS special filesystems labelable, **MNTPOINT/context=, NONE and
  unknown behaviors never per-inode relabelable**. This also tightens the old
  sysfs/etc context-mount exception instead of extending it to FunctionFS;
- unnamed/unimplemented capability slots are skipped in selinuxfs, not advertised
  as support or created repeatedly as duplicate `unknown` dentries;
- all NNP02 permissions, bounded fallback, namespace detection and USER_NS=n
  compile guard remain intact. Old 56 class/permission tables + process2 ID57
  remain unchanged. No new SELinux allow/neverallow/permissive/domain changes.

## Empty-context audit boundary fix

Testing the actual old relabel hook with a **non-null buffer and length zero**
reproduced ASan/UBSan underflow at `str[size - 1]` in invalid-context auditing.
The real context parser already rejects zero length with -EINVAL. The patch adds
only `&& size` to that audit-buffer guard, preserving rejection and permissions.
This is an extracted-function reproduction, **NOT proof of an exploitable syscall
path or tablet crash**. The original sanitizer failure is retained in
`reference/validation/functionfs-20261023/host-attempt02.log`.

## Evidence — distinguish the layers

- **340 mount/oracle cases** compare actual patched and pinned modern label
  helpers with cgroup capability disabled (not backported here). Modern Android's
  FunctionFS helper is unconditional for ABI reasons; this port additionally gates
  it on actual userspace bit12. MNTPOINT/NONE/invalid behavior reject labeling.
- **896 actual VFS/SELinux authorization paths**, plus empty/malformed/force-
  context cases: owner/POSIX/RELABELFROM/RELABELTO/validate-transition/ASSOCIATE
  failures propagate before SID update. `vfs_setxattr`, `__vfs_setxattr_noperm`,
  SELinux relabel hook and in-core setsecurity are extracted production functions.
  MAC_ADMIN force parsing does not bypass normal in-core context validation.
  Objects, locks, AVC, parser, audit and notifications are fixtures, not a kernel.
- Mac/Linux **ASan/UBSan + Wall/Wextra/Werror PASS**. Only existing unused flags
  parameters are explicitly marked in fixtures. Host unused-parameter/GCC
  indentation failures and an initially wrong fixture expectation about forced
  invalid contexts are retained; no warnings or security checks are disabled.
- The rest of hooks.c is byte-identical to reviewed NNP02 except the exact
  label-helper/GENFS changes and one audit-size guard. The updated NNP regression
  still passes **16,384 decisions / 8,192 actual capability-load combinations**,
  including both bits5/12 reset and unsupported USER_NS=y negative compile.
- **Real binary policy** inspector, source-locked Android libsepol: bit12 ON and
  root genfs type functionfs in both variants. The queried init→functionfs:file
  relabelfrom and init→usbaccessory_device:file relabelto are **NOT granted**;
  usbaccessory_device→functionfs:filesystem associate is granted; queried
  untrusted_app relabelfrom is not. **No permissions are added to force success.**
  This is unconditional TE data, not constraints/MLS/role/full AVC authorization.
- **Full fresh kernel build exit0 18:11:07–18:13:51 UTC** with unchanged config
  `fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea`, preserved
  firmware/toolchain, complete four-file touch/input baseline and three locked
  kernel patches. New clone/output, no hardlinks or alternates.
- **Actual ELF/link:** FunctionFS mount, VFS-LSM and in-core labeling functions
  linked. Capability12 read by mount/label selection and stored by policy loading;
  NNP capability5, both exec sites, namespace/AVC/bounded fallback remain linked.
  Native/compat qtaguid ioctl/fops and final-close hooks retained. Exact GNU
  objcopy ELF→Image equality: **25,411,320 bytes**,
  **7250adb995df7cc2d599f38f5829cf92bec9679a2dbe914c264741f604c1c6f9**.
  Structural link proof, NOT whole-policy loading/AVC/USB/runtime proof.
- Eight CLI safety tests pass both modes on Mac/Linux (16 rejection invocations
  per host). Protected/aliased source/output/experiment and existing outputs are
  not modified. Original stats/DNS 13-file/two-patch capture hashes unchanged.

## Paths, reproduction, limitations

`staging-lock.json` locks original reference and final hashes to manifest kernel
669b9584e678ce5865ed38e04c24639082d78de1. Selected originals also byte-match actual
build baseline efbdbfa3e216b0c300d381c340b0a22b24e15c13; not complete-tree identity.
Git replay and read-only locked-TOP apply-check pass. `build-kernel.sh` archives
all inputs and applies locked patches only; **do not rerun used fresh paths**.

Remote `/srv/android/artifacts/lineage-23.2-arm64/`:
`kernel-functionfs-build-20261023-01/`, `kernel-functionfs-link-20261023-01/`,
`policy-functionfs-20261023-01/`. Source/output under
`/srv/android/ports/lineage-23.2-arm64/kernel-functionfs-20261023-01/{src,out}`.
Reference test files are selected copies in `reference/functionfs23/`, mirrored
under ports/functionfs23/, with hashes in build evidence. Aggregate:
**reports/kernel-functionfs-20261023.json**.

**Remaining:** real endpoint creation/relabel/getxattr persistence, USB/adb/AOA,
policy reload/remount/concurrency, whole policy loader and AVC/exec behavior,
other enabled capabilities (especially extended socket classes), strict policy
(281 user / 367 complete userdebug / 279 proposed metadata still FAIL), full
networking/backend/authorization/budgets/Java, HAL/APEX/ART/Binder/graphics/TEE/FBE/
recovery/OTA/signing and approved backup/rollback/hardware tests. This kernel is
not integrated; original prebuilt/vendor/DTBO/TWRP/keys/userdata remain untouched.
