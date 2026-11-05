# Isolated Samsung diagnostic boot packaging

This packages the capability-profile kernel using the pinned Android17 host
mkbootimg/unpack_bootimg tools and the unchanged immutable non-A/B archive.
First, unpacking and rebuilding the original boot plus its Samsung trailer must
reproduce every original byte. That control passes. Then only the kernel input
is replaced; no active prebuilt, target-files, vendor, recovery or device changes.
The only generated image is explicitly named NOT_FLASHABLE_boot.img on the
server, outside Android TOP. No image is published as an installation candidate.

The diagnostic boot is 25,454,608 bytes, with 8,099,824 bytes remaining in the
33,554,432-byte physical boot partition. It retains version1/2048-byte pages,
SRPSA25A005KU board name, kernel-only SAR/no ramdisk, enforcing cmdline and the
Android17/2026-10 boot-header OS/SPL word. The source device ramdisk checker
passes. A separate raw comparison verifies every original header/padding byte
except the kernel-size field and SHA1 ID field. ARM64 Image magic and the exact
kernel payload digest are also checked. No signature or AVB signing occurs.

Diagnostic boot SHA256:
`9d7675e06ea750dc4b5785f708f079a88de3c18fa140d47b77cf6f9d395bd5c9`.
Kernel SHA256:
`5d3b21c1a9abb1e7c5175670606f9486c8a5da8f8ad536c132c5bd9c6c350fb2`.
Inputs, tool binaries/sources/revisions, original archive and source-audit digest
are bound in report.json and evidence-lock.json. No signing material is read.

This is packaging/geometry evidence only. It does not prove bootloader, TEE,
key upgrade/rollback, FBE/TWRP, networking/BPF, runtime/module ABI, full SELinux
loading or strict policy compatibility. Vendor metadata strict checks still
fail, and no installer/OTA guard is bypassed. The boot image is not flash ready
and is not a standalone test ROM.
