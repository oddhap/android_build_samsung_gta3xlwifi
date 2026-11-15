# Kernel-lifetime UID cleanup receipt and actual ioctl routing

Inactive four-file delta over kernel-iface-names-20261115-01. No selected source,
prebuilt, policy or device change. Native nonce/journal/NSS integration is pending.

The prior interface-name implementation was missing its opcode in both the outer
ioctl dispatch and the inner operation allowlist. Its handler/module could compile
while the real device request still returned ENOTTY. One exact operation switch
now serves both routing checks, preserving root/namespace/file/TGID authorization.
The host test executes both real dispatcher functions and verifies the name
request reaches the interface boundary. That boundary returns ENODATA in the
fixture; actual interface-name module behavior was independently tested earlier.

The real packet store now retains one boot-lifetime UID cleanup receipt with
NONE/PREPARED/COMPLETE phases. BEGIN validates a strictly increasing nonzero nonce,
UID/generation/active epoch, and absence of pending frozen banks. Repeating an
identical completed BEGIN/COMMIT returns cached completion without deleting newly
created records for a reused UID. A repeated PREPARED request returns EINPROGRESS;
it never authorizes replaying socket deletion. COMMIT atomically removes actual
packet/app/counterset data and records COMPLETE under the existing stats lock.

PREPARED blocks bank swaps, legacy UID deletion and private gate release. It is
retained through daemon/lease death. READ reports actual state, including after
copy-out faults that followed a committed phase transition. Native code must
perform genuine socket-tag deletion between BEGIN and COMMIT. This kernel API
does not itself prove that external step or implement the durable caller.
Dropped ingress is still genuinely counted during HOLD; no unchanged-counter or
networking-ready assumption is introduced.

UAPI: one64-byte transfer, nonce/generation/epoch offsets16/24/32, reserved offset40,
ioctl0xc0406763, storage capability bit17. Phase/input/reserved fields are checked.
An ambiguous PREPARED transaction must remain closed pending explicit recovery;
blind UID replay after restart is not permitted.

Validation:
- kernel-uid-receipt-host04 passes5454 checks, including prior5392 checks,
  9830400 genuine pinned A17 GSO oracle comparisons and both80000-update host
  concurrency cases. New receipt/outer-dispatch checks pass61. Kernel primitive
  boundaries remain explicit fixtures; no hardware or live kernel execution.
- uid-receipt-abi01 passes actual Android ARM32/64 compilation and relocatable
  links proving transfer size, offsets and ioctl value.
- kernel-uid-receipt-build01 exit0: full Image/modules/Gator, static118 Gator and43
  KUTF import CRC checks,60366 candidate/60366 baseline/60331 protected tracked
  files audited before/after, plus1243-project/17-patch Android audits.
- Image SHA256:7ece8d6fd70870811abfe5fd9f947311506f97233491b4016cde441de3578aec.
  Config remains fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea.

Source/out are isolated, with fresh output and no copied signing material. No
Image/module binaries are published here. Public evidence includes config,
checksums, source audit metadata and static ABI reports.

The replay reference's historical test-kernel-active-stats24.py runner hash had
changed before this work. It is not imported/executed by this test; the exact
compiled test.c and all its other source/header inputs remain hash-checked. The
new report explicitly records that unused historical-runner discrepancy. Earlier
fixture syntax/header/admission failures remain in server artifacts; host03 also
exposed the real dispatcher omission corrected in this delta.

Remaining: native nonce-aware transport/owner/service, durable factory intent and
startup admission, explicit current/vendor strict policy for ioctl0x6763, NSS
map/listener selection and diagnostics, loopback, CLAT, final source/Soong/APEX
composition and full installation/encryption/partition checks. No ROM is ready.
