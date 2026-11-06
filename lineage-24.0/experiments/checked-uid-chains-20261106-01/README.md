# Checked UID-chain I/O — isolated component

This component calls the actual Android17 `IptablesRestoreInterface`. It reads
existing owned `g24_*` chains from the kernel, accepts a deliberately narrow
UID-range/RETURN/DROP grammar, writes the complete selected image, and requires
exact ordered readback before reporting success. A failed acknowledgement may
follow a committed transaction, so failure always attempts to restore the actual
before-image and verifies that restoration. Unverifiable restoration returns
`EUCLEAN`; the future owner must quarantine/fail closed. No policy cache or
readiness is published here.

Both address families are tested separately. All requested names, rules, numeric
bounds and the 1MiB image limit are validated before writes. Malformed, missing,
foreign, truncated or unsupported output is an error. Multiple owned chains are
updated together, and existing identical kernel images need only a read. No
unrelated or built-in chain is flushed.

84 real-component parser/transaction cases pass with fatal UBSan and empty stderr
on macOS and Linux, using scripted kernel I/O through a fixture interface. These
cover acknowledgement failure, readback mismatch, complete multi-chain rollback,
unverifiable rollback, input limits and preserving caller output on read errors.
The Android17 formatter source was inspected: `-S` emits `-N` for a user chain,
and the owner save formatter explicitly prints numeric UID values.

The component also compiles with the actual netd ARM64 CFI Soong command and
actual interface headers. Android ld.lld materializes a real AArch64 relocatable
object with the expected method definitions. This is not a complete netd link,
ABI/runtime validation or a real iptables execution. The first metadata extraction
raced Kati rewriting a mapped Ninja graph and received SIGBUS; the tool now acquires
the build mutex before querying the graph. Retry02 passes without production
source/object changes.

Still required: a sole authoritative owner and netd transaction lock, verified
attachments/startup and persistence, dual-stack quarantine/rollback, full packet
control exceptions, all 12 UID-chain semantics, per-user core exemptions, metering,
VPN/interface/LNA, lifecycle/permissions, quotas/CLAT, Java/JNI/DNS readers and
truthful startup. This code is outside TOP and all Android prebuilts. It does not
constitute network readiness or a flashable ROM.
