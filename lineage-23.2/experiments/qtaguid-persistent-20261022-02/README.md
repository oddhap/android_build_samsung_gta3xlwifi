# Opt-in socket-owned qtaguid tags — isolated kernel + Netd experiment

**NOT applied to Android TOP, NOT installed, NOT a flash-ready ROM.** Six selected
files in two checksum-locked patches. This supersedes the earlier process-owned
transport for future integration; archived experiments remain historical evidence.

## Concrete change

The existing Samsung driver holds a sock reference for each tag but also places
ordinary tags on a tagging process's qtaguid session list. Session destruction
therefore untagged still-live app sockets on a Netd restart. This experiment adds
an explicit private **`QTAGUID_SOCKET_OWNED_SESSION = _IO('q', 0x51)` (0x7151)**:

- Only initial/global UID root **and CAP_NET_ADMIN** can enable it. Wrong command,
  nonzero argument, passive modes, missing/foreign session and existing legacy
  list members fail. Both native and compat ioctls call the same no-pointer ABI.
- Socket-owned creation/promotion rejects non-IPv4/IPv6 families **before any
  new resource allocation**, since Unix/packet sockets lack the inet cleanup
  hook. Existing legacy Unix tags retain their original session cleanup.
- Legacy mode is unchanged by default. Socket-owned new tags use reserved PID 0,
  are never appended to a process session list, and survive tagging-process exit
  and PID reuse. Privileged retag can safely detach/promote a legacy tag. Retagging
  a socket-owned tag never downgrades its lifetime.
- Existing explicit untag/UID deletion and **inet socket-file release** remain
  cleanup paths. Socket-owned zero tag refs/unused UID resource records are
  retired under the existing locks, including after cross-UID/tag retag. Traffic
  accounting counters are not cleared by this resource cleanup.
- Do not confuse the existing inet file-release hook with proof of every modern
  BPF sock-destruction/queued-packet timing property. Real buffered-close, file
  passing, concurrency, UID-removal and packet accounting tests are still needed.
- Netd's staged raw transport now **requires** this acknowledgement before opening
  its control path. ENOTTY/EPERM/other errors or unexpected positive results fail;
  there is no fallback to the restart-unsafe old mode. This only establishes a
  tag I/O capability, not firewall/permission/complete-backend readiness.

## Validation completed

- **45,953 assertions PASS** with ASan/UBSan using **23 extracted actual production
  kernel functions**, including tag, untag, process open/release, ioctl and ref/UID
  helpers. Exercises default legacy cleanup, all new gates, session exit/PID reuse,
  shared refs, cross-UID and same-tag retag, valid/rejected promotion, unsupported
  family rejection preserving old ownership, no downgrade and 2,048 tag
  churn cycles. Locks, tree balancing, credentials, allocators/socket lookup are
  fixtures: **not actual kernel execution or races**.
- Updated raw transport: **1,825 assertions PASS**, ASan/UBSan, real host TCP/UDP
  IPv4/IPv6 and FD reuse; driver/proc/sysfs/ioctl are fixtures. Unsupported old
  kernel, permission errors and malformed ACK fail. Production source passes actual
  Netd ARM64 CFI compilation (one object, not linked/installed Netd).
- **Complete independent source-built kernel Image PASS**, exit 0, finished
  2026-10-22 21:13:05 UTC (final bounded-family revision), same config as preserved baseline. No external Git
  alternates/hardlink clone. No modification of preserved source/output/Image or
  active Android sources/prebuilt. Diagnostic Image is deliberately NOT copied
  into BoardConfig/prebuilt/target-files.
- Binary validator proves both native/compat file-operation pointers reference
  the linked private ioctl, command/capability instructions and existing IPv4/IPv6
  release calls are retained. GNU objcopy reconstruction matches the new Image
  byte for byte. This is ELF/link proof, not executing the driver.

## Source provenance and preserved initial failure

The patch base in the Android manifest is kernel `669b9584...`; the three touched
kernel file inputs correspond to the actual preserved kernel source. The isolated
kernel build uses the **actual prior build baseline `efbdbfa3...`**, the complete
four-file touch/input delta from that preserved working tree, and these qtaguid
changes. These are distinct revisions: no claim that the complete two kernel
source trees are identical. The exact build patch/config/firmware/source hashes
are recorded in the artifact directory and report. This directory also archives
`build-kernel.sh` and `baseline-touch-complete.patch`; the runner refuses existing
output/source edits and is not an instruction to rerun over an existing build.

Attempt 01 safely stopped **before make**: the archived touch-only patch did not
include the additional `input_set_enabled` input.c/input.h prerequisites already
present in the preserved built kernel. Their symbol exists in that vmlinux. Retry
02 captures the complete read-only four-file baseline delta, refuses any other
modified filenames, applies it to a fresh independent clone and byte-compares all
four resulting files against preserved input. It does not delete/reset/edit the
preserved working tree or guess away the difference. Failed clone/source/logs stay.

## Still not ready for deployment

The live Netd owner, caller/UPDATE_DEVICE_STATS/CLAT authorization, statistics
budgets, all 12-chain packet enforcement, VPN/LNA/interface, quota/CLAT,
Java/API/loader integration and restart reconstruction of **other** policy state
remain missing. Socket-owned resource refs can retire independently of historical
accounting rows: an authoritative real stats budget is mandatory before exposing
untrusted tag requests. No readiness/BPF markers are forged. SELinux access to the
new exact ioctl/sysfs paths is unproven; strict existing vendor policy still fails.
Full runtime/HAL/FBE/recovery/OTA/signing and owner-approved hardware tests remain.

See `reports/qtaguid-persistent-20261022.json`. Kernel artifacts:
`/srv/android/artifacts/lineage-23.2-arm64/kernel-socket-owned-20261022-03/`.
Final Image: 25,410,936 bytes, SHA-256
`a902b92f618885b690c27cf867cab2c7c5f3cf910852c697b805032cce0bc597`.
The earlier successful build/experiment 01 is retained; revision 02 adds the
kernel-side family guard. Both remain isolated, uninstalled diagnostics.
Existing original Image (33c1a0d1...), DTBO/vendor, LineageOS 21, TWRP, keys and
userdata are untouched. The earlier complete full-platform-03 ZIP is unchanged.
