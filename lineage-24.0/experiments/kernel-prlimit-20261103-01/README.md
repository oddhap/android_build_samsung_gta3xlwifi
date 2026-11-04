# Isolated prlimit/getrlimit mediation

This is a complete source path from prlimit64 read/write pointers through DAC,
the initialized/registered LSM hook chain and the actual SELinux credential-based
permission check. READ/WRITE flags follow the pinned modern kernel callsite.
Self-task exemption, all six UID/GID comparisons, CAP_SYS_RESOURCE and the
original do_prlimit hard-limit implementation remain intact. Both native and
compat syscall tables still call the same sys_prlimit64 body. getrlimit is
appended to the existing process class without moving prior permission bits.

The new LSM hook has its union field, head field, real LIST_HEAD_INIT initializer,
public API, disabled-security inline, dispatch wrapper and SELinux registration.
Host tests compile the actual vendor call_int_hook macro, initializer fragment,
LSM registration macro and security_add_hooks helper as well as real DAC,
SELinux and syscall bodies. Credentials, RCU/list mechanics, AVC, user copies,
task references and resource updates are sequential fixtures, not live kernel.
16,384 DAC/LSM/SELinux and 256 syscall/error/refcount scenarios pass with ASan/UBSan.
The unmodified do_prlimit function and unchanged native/compat tables are checked
exactly. The modern DAC function is copied verbatim from the revision-locked
Android17 kernel. No ARM ABI execution or real resource mutation is claimed.

Initial staging stopped on an ambiguous unanchored prototype match; its partial
tree is preserved locally and unused. A fresh candidate uses an anchored match.
Initial host setup needed the parent's classmap input, and macro extraction was
corrected to retain both nested initializer braces. These were staging/fixture
errors, not kernel changes to bypass a failed enforcement test.

No enforcement setting, policy assertion, Android prebuilt or tablet is changed.
Netlink capability9 rejection remains. Perf, enabled inotify checks, full policy,
networking and Android17 FBE/installer/rollback still block installation.


## Complete build and Linux fixtures

`kernel-prlimit-build-20261103-01` completed exit0 at 18:54:51 UTC on November 3.
The pending Linux fixtures were run on continuation and completed exit0; source,
runner and result hashes match Mac. Image SHA256:
`d4fe970004cdef2c959259351c9e6adc66b0e56a570c92cb8760d1885bfb6409`.
The 60,331-file tracked-source/protected-input audits pass. Preserved config,
firmware inputs and all 8,408 original export symbols/CRCs match; no added,
removed or changed export is hidden. All three untracked source files are hashed.
Full inventories remain on the server and are bound by evidence-lock.json.
No Image promotion, live resource update, ARM ABI execution or flash approval.
