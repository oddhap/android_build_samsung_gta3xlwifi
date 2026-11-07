# Real immutable local-network prefix store

Adds a real two-table compressed Patricia image, actual selected A17 migrated
permission/LPM decision and held authenticated lease ioctls. No packet hooks,
BPF map emulation, parent attachment or full-network readiness is installed.
Each table supports1000 entries,192 payload bits and canonical32-byte entries.
Transfer is40 bytes with aligned64-bit revision/pointers. SET0x40286757 requires
the actual gate held and advances revision by1 (identical replay idempotent).
GET0xc0286758 probes metadata then reads both tables at the exact revision.
Only root/initial-CAP_NET_ADMIN/exclusive file/TGID may use either operation.

All copies, validation and at-most2N-node construction occur before publication;
RCU readers traverse an immutable compressed tree without packet-time allocation.
Grace completes before freeing old entries/nodes. Faults preserve the old image.
Literal UID0/1000 or real AccessLocalNetwork bit0 is exempt; other core appIds
are not exempt. Main no-match/true allows, false requires a true host exception.
Real native byte-order keys, protocol/remote-port and mapped IPv6 semantics match
A17. Packet/DNS/loopback applicability is the caller's separate obligation.
Features bit3 reports the actual compiled store primitive only.

Host64 cases and787909 comparisons passed with fatal UBSan: actual C store,
driver authorization and decision, actual selected A17 expressions and an
independent bit-loop linear LPM oracle,64 random images up to1000 entries,
all193 prefix boundaries, all128 masks across literal/multiuser core UIDs,
allocation/copy faults, malformed inputs, coherent reads and generation bounds.
First fixture failed a glibc IPv6 member spelling; fixed only initialization.
RCU/allocation/copies/credentials are fixtures, not runtime kernel enforcement.

Complete isolated build kernel-local-network-build-20261107-01 exited0 at
15:59:48UTC November7. Image4b39c989f52d9ea46253f09c51166caa870a5c894093ce3204bce51082d41ac8.
Original configfac42...b3acea unchanged. Gator118/KUTF43 imports, all60346
candidate/60331 protected source hashes and Android1243/17 before/after audits
passed. All earlier parser/UID/creator/peer regressions also passed. No Android
prebuilt promotion or tablet changes. Next: real packet match, private xtables
registration, strict exact new ioctl grants and native full-image transport.
