# Isolated perf event mediation and owner labels

The preserved profile enables PERF_EVENTS. This adds real LSM/SELinux checks for
open, CPU, kernel/privileged-branch and tracepoint access; read/mmap checks and
write mediation for ioctls. Existing paranoia/capability, memory-lock and custom
trace permission rules remain. The old trace behavior is preserved when the new
LSM permits access. The compat ioctl still forwards through the common wrapper.

A creator SID is stored in a newly allocated per-event legacy single-owner blob.
Allocation occurs before publication/accounting. Failed allocation or a later
LSM denial frees that blob; the core's new error label releases already-acquired
callchain buffers before the existing PMU/namespace unwind. Successful teardown
uses unconditional common cleanup, matching the modern common blob free semantics.
Read/write reject an unexpectedly missing label instead of inventing ownership.
The perf_event class is appended without changing existing class/permission IDs.

The added pointer changes perf_event layout. Export CRCs and actual packaged
module usage must be reviewed. A filename/directory inventory finds no module
markers in the immutable target-files or actual vendor. Three terminfo .konsole
names from the initial broad .ko substring match are explicitly recorded as
non-module names. This inventory does not prove absent external modules or live
ABI compatibility; optional module results and limitations are recorded below.

Mac ASan/UBSan actual-body fixtures pass 9,984 LSM/owner-label, 128 allocation/
free-unwind, 6,144 read/ioctl/mmap-fragment, 6,144 old-versus-new trace and 24 CPU-
gate scenarios. Allocation starts at the post-PMU callchain tail, mmap stops
before mapping, and CPU executes its authorization fragment. Full old/new trace
permission functions, IO wrappers, common/SELinux LSM code and successful free
bodies are real. Memory, policy, PMU, context/RCU and ring-buffer backends are
fixtures. Kernel/initial syscall placement is asserted, not a full open execution.

Staging now validates all edits in memory before creating any tree. Two missing
vendor include/array anchors stopped preparation without partial trees. The
old function extractor then matched prose mentioning perf_mmap before a different
function; extraction now blanks comments/strings before searching and balances
code braces. Four focused parser cases and the real mmap declaration pass.
The initial fixture build warned about labels used only by its omitted prefix;
only the fragment harness warning settings changed. Production labels remain.
No failed enforcement result was reclassified as a pass.

No Android prebuilt, enforcement/neverallow, BPF readiness or device is changed.
Netlink capability9 rejection, strict vendor policy, full legacy networking and
Android17 installer/FBE/rollback remain installation gates. No flash approval.

The complete standalone kernel and Linux fixture jobs finish exit 0. Mac/Linux
results, input hashes and runner/extractor hashes match (input path prefixes
differ). The 60,331-file before/after and protected-source audits pass; config
and firmware stay exact. Image SHA256 is
`5bc1e2446704cddc623fc31c66a30460c5d4f4f59bce40974a035649980c6796`.

All 8,408 export names remain, but **1,104 CRCs change** through the perf_event
layout dependency graph. Full differences are in build-review.json. This is a
real ABI change; existing modules cannot be assumed compatible.

The normal module build exits 0 and creates kutf.ko. Static ELF64 LE AArch64
ET_REL/vermagic and all 43 import CRC checks pass against the new exports.
Samsung's top-level Makefile only visits Gator for CONFIG_GATOR=y, although the
preserved config sets m. An explicit M= attempt exits 2 at an old arm64 prepare0
build-system error. The correct in-tree drivers/gator/gator.ko target compiles
its objects but exits 2 at MODPOST: walk_stackframe is undefined. That symbol
also is not exported by the preserved original kernel. Gator has no successful
module or ABI result. Neither failure is bypassed; no extra symbol is exported.
Post-failure source/config/Image checks pass. module-evidence-lock.json retains
all three job exit/log hashes and complete source audit hashes; the static KUTF
report is a separate limited success, not an all-module approval. No module was
installed, loaded or signed. Full runtime/module ABI compatibility remains open.
