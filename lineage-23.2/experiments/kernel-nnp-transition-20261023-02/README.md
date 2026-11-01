# NNP/nosuid capability and foreign-mount check — final NNP-only revision

**Newer combined capability kernel:** `../kernel-functionfs-20261023-01/` includes
this reviewed NNP02 delta plus FunctionFS against the ORIGINAL reference files.
Use one capability patch or the other, **never stack both**. This directory keeps
the earlier NNP-only build/report unchanged. `test-host.py`, `check-link-at-time.py`,
`test-cli-at-time.py`, `capture-at-time.py` preserve its exact report tool hashes.

**Kernel link PASS, NOT kernel execution/security approval or a flash-ready ROM.**
Not integrated into TOP/prebuilt. Original source/output/vendor/21/TWRP/keys/data
are untouched. Revision 01 is retained as historical mount-flag-only evidence.

## Why this is needed / exactly what changes

Both actual Android-16 user and userdebug diagnostic policy binaries enable bit
**5, nnp_nosuid_transition**. Preserved 4.4 supports only capability enum 0–3,
has no process2 class, and its exec helper knows only bounded-SID transitions.
The five-file patch adds an explicit policy-controlled AVC check for process2
nnp_transition/nosuid_transition before the existing bounded fallback.

- Capability number is explicitly **5**; old 0–3 remain unchanged. Slot 4 is
  unnamed, **not an invented cgroup_seclabel implementation**. selinuxfs handles
  the hole safely and names the implemented bit 5.
- Load/reset the capability on actual policy reload, including 1→0 changes.
- **Append** process2; all **56 old classes and every permission position** stay
  unchanged. Real generated kernel class number is **57**, resolved to policy
  classes by existing name mapping, not by assuming matching binary IDs.
- If both NNP and nosuid apply, require **both** permission bits. Missing/failed
  AVC authorization still follows the original bounded-SID fallback. Same SID
  needs no new transition authorization. NNP failure remains -EPERM, nosuid -EACCES.
- Every byte of hooks.c outside the changed helper is unchanged: ordinary
  process:transition, file:entrypoint/execute-no-trans, sharing/audit, explicit
  exec-SID error versus automatic fallback remain in place.

The final revision also checks **mount namespace membership** through the actual
4.4 `our_mnt()` helper. A foreign mount accessed through an inherited FD, fchdir
or /proc path must not bypass nosuid protection merely because MNT_NOSUID is off.
`our_mnt()` calls `check_mnt(real_mount(mnt))`, exactly the namespace test used in
modern mnt_may_suid(). With **CONFIG_USER_NS=n**, the modern current_in_userns()
helper is always true. The actual pinned upstream mount helper is used unmodified
in host comparison. **USER_NS=y explicitly fails compilation** until superblock-
owner/user-namespace support is backported; it is not silently advertised safe.
The preserved actual config already has USER_NS disabled; no config is changed.

No allow/neverallow/permissive/domain rules are altered. This implements explicit
policy intent, not blanket permission to change domains. With capability off,
legacy behavior is preserved on own-namespace mounts; foreign-mount checks only
restrict old behavior. Full AVC/exec/namespace/reload-concurrency behavior still
needs real kernel testing; this is not that test.

## Separate evidence layers

1. **Actual policy data:** source-locked Android-libsepol inspector reads actual
   version-30 diagnostic binaries. Both bit5 ON. Userdebug has unconditional TE
   nosuid grants kernel→overlay_remounter and overlay_remounter→init; user does
   not. Neither queried variant grants platform_app→init. No grants were added.
   This is not constraint/MLS/role/full-exec authorization or live AVC proof.
2. **Extracted production functions:** ASan/UBSan + Wall/Wextra/Werror on Mac/Linux:
   **16,384 decisions** match pinned Android-16 NNP + actual mount helper, using
   actual 4.4 our_mnt/check_mnt and USER_NS=n helper semantics. **936 legacy/oracle
   differences** reproduced. **8,192 bitmap combinations** exercise actual
   security_load_policycaps. Mount/credential objects, AVC, bounded decisions,
   bitmap and nlmsg initialization remain fixtures, not kernel execution.
   Unsupported USER_NS=y negative compile passes. The first host warning failure
   is retained; only the zero table sentinel/unused helper parameter are made
   explicit in the fixture. No production warning or limit is disabled.
3. **Full build:** kernel-nnp-transition-build-20261023-02 **exit0**,
   **17:52:08–17:54:53 UTC**. Fresh no-hardlinks/no-alternates clone/output;
   config **fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea**
   unchanged. Complete four-file touch/input prerequisite plus checksum-locked
   qtaguid-persistent02, policy-reader and this patch; kernel portions only.
4. **Actual ELF/Image:** native+compat private qtaguid ioctl/fops and original
   releases remain linked. New NNP helper calls our_mnt, AVC, bounded fallback;
   both explicit/automatic exec paths call the helper. Actual capability address
   is loaded by the helper and stored by policy loading. Class constant 57 is
   verified from generated header and machine code. GNU objcopy reconstruction
   equals archived Image exactly: **25,411,320 bytes**,
   **88b9a98b42caa89f9848c7d44a89da58b23538b4ecb57c7d29ab9cd40ff9c4a5**.
   This is structural link proof, NOT execution/full loader/enforcement.
5. **Tool safety:** eight CLI rejection tests pass Mac/Linux: protected source,
   output, experiment and explicit roots, resolved aliases, existing dir/file.
   No fabricated successful ELF fixture. Default 13-file/two-patch networking
   capture regression still has exactly the original patch hashes.

## Reproduction and limits

`staging-lock.json`: five files / one checksum-locked kernel patch, manifest
669b9584e678ce5865ed38e04c24639082d78de1. Five original files also byte-match
actual preserved build baseline efbdbfa3e216b0c300d381c340b0a22b24e15c13; **not a
claim of complete-tree identity**. Actual Git replay/read-only TOP apply-check pass.
`build-kernel.sh` uses only locked patches, not mutable staged source; all baseline
and result hashes are checked. **Do not rerun hardcoded already-used fresh paths.**

Pinned mount references/URLs/SHA: local reference/selinux23/nnp-upstream-mount/
source-lock.json; remote ports/nnp-upstream-mount/. No platform resync.
Remote artifacts under /srv/android/artifacts/lineage-23.2-arm64/:
`kernel-nnp-transition-build-20261023-02/`, `kernel-nnp-link-20261023-01/`,
`policy-process2-20261023-01/`. Earlier build01 and failed host attempt preserved.
Aggregate evidence: **reports/kernel-nnp-transition-20261023.json**.

**Still not flash-ready:** strict original user policy 281, complete userdebug 367;
separate proposed vendor metadata 279. None is a security pass. Whole policy
loading and other enabled modern policycaps (extended socket classes/functionfs),
live namespaces/AVC/exec/reload, full networking/permissions/budgets/backend/Java,
HAL/APEX/Bionic/ART/Binder/graphics/TEE/FBE/recovery/OTA/signing and owner-approved
backup/rollback/hardware validation remain. Active ROM kernel remains ORIGINAL.
