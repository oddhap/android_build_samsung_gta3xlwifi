# Isolated qtaguid socket transport — NOT a complete backend

Two new production source files, one checksum-locked Netd patch. Not applied to
TOP, wired into Netd, or included in the diagnostic ROM. No BPF loader, readiness
property, security check, or Android-14 recovery/OTA guard is bypassed.

**Later work:** `qtaguid-persistent-20261022-02` adds a mandatory private
socket-owned kernel handshake and a separately source-built kernel to address
structural session-exit tag loss. This original process-owned source lock remains
historical evidence, not the current WIP or a deployment-approved transport.
See `reports/qtaguid-persistent-20261022.json` for proof and limits.

## Implemented real I/O primitive

`Gta3xlwifiQtaguidTransport.{h,cpp}` owns one process qtaguid device session and
writes actual bounded `t FD ACCOUNT_TAG UID` / `u FD` commands to procfs:

- Requires genuine sysfs, exact `N\n` for both kernel passive flags (at start
  **and before each operation**), misc device identity matching sysfs and a
  genuine procfs control file. Missing/inaccessible/malformed/overlong/NUL data
  and passive mode fail; no property or regular-file fallback.
- Holds the device FD with CLOEXEC for the session. EBUSY is an error, not
  presumed ownership of another session. Control/sysfs paths use O_NOFOLLOW.
- Pins a duplicated socket descriptor with F_DUPFD_CLOEXEC before family/protocol
  checks and command writing. It cannot accidentally tag a replacement of the
  caller's original descriptor. Allows IPv4/IPv6 TCP/UDP, validates UID range and
  serializes its operations.
- Shifts the full unsigned 32-bit tag into high 32 bits, writes one complete proc
  command, propagates actual errors and retries only EINTR. A short write is an
  error that discards the I/O session; a suffix is never sent as a new command.

**Trusted low-level transport only:** ordinary caller authorization, UPDATE_DEVICE_STATS
permissions, forbidden CLAT charge UIDs, statistics budgets, UID-removal/counter-
set/quota/CLAT integration are not implemented by this class. It must not be
exposed directly as a public policy endpoint. `start()` success means only that
these I/O handles/checks succeeded, not complete networking/backend readiness.
No callback owner or live policy publication is included.

## Existing kernel hook confirmed — previous suspicion narrowed

Read-only inspection found `inet_release -> qtaguid_untag(sock, true)` and
`inet6_release -> inet_release` already present in both preserved kernel source
and locked port kernel source. All four relevant source files are byte-identical.
With `true`, cleanup looks up the stored tagging PID, removes the tag and drops
the retained sock reference; it does not depend on the closing app being Netd.

More importantly, the hook and true second argument are present in the **linked
preserved vmlinux**. Reconstructing Image with the original objcopy flags in a new
scratch directory produces exactly baseline SHA-256
`33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553`.
The source-only suspicion that a missing final-close hook might force a new
kernel patch is therefore **resolved by offline binary evidence**. No kernel
was modified or compiled. This is not physical lifetime/concurrency testing.

**Restart persistence remains separate and unresolved:** closing this process's
qtaguid device session removes all tags owned by that session. A Netd crash can
therefore discard tags even while app sockets remain open, unlike persistent BPF
cookie maps. The final-socket hook does NOT solve this. A future owner must solve
and test restart/tag ownership semantics, not automatically restart this I/O
session and declare the backend healthy. Live passive-parameter changes by a
privileged administrator are not synchronized by a userspace mutex; this code
never changes those kernel settings.

## Evidence and remaining validation

- **1,607 assertions PASS**, Linux host with ASan/UBSan, real IPv4/IPv6 TCP/UDP,
  actual dup/getsockopt and descriptor reuse, errors, passive modes, malformed
  metadata, short write, EINTR and 16 concurrent serialized tag requests.
  **Driver/proc/sysfs I/O is a wrapped fixture, not real qtaguid execution.**
  Ubuntu fortified `__read_chk` is wrapped with its bounds contract preserved;
  fortification/warnings/sanitizers are not disabled.
- Actual Netd ARM64 CFI object compilation **PASS**. First preflight caught
  Bionic's unsigned statfs f_type versus host signed type; fixed with an explicit
  uint64 conversion, not weakened warnings. Not linked Netd or full header ABI.
- New-file patch forward/reverse Git replay and read-only apply-check against
  the exact locked actual Netd revision PASS. No application performed.
- `tools/check-qtaguid-lifetime.py` records source/config/vmlinux/Image hashes,
  reconstruction and disassembly proof outside preserved source/output.
- Actual Android SELinux access to the exact new sysfs paths is unproven; no broad
  allow rules have been added. Strict vendor policy still fails independently.

See `reports/qtaguid-socket-20261022.json`. Full firewall owner/packet engine,
permissions/budgets, restart semantics, loader/Java integration, strict SELinux,
FBE/recovery/OTA and approved hardware validation still block a test ROM.
