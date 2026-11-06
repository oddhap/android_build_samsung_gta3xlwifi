# Separate non-loopback interface predicate

Adds gta3xlwifi_non_loopback alongside the existing owner-skip match, sharing
its zero-reserved four-byte payload and INPUT/OUTPUT/initial-userns constraints.
It reads input/output device index, treating a missing device as index0 (not
exempt). Interface names/flags are not used. This is intended only to condition
BACKGROUND's child call, never to exempt all ordinary or independent protection.

Host fixture01 passes19 cases plus5774610 actual A17 parser/skip comparisons,
including distinct input/output devices, index1 versus others, absent devices,
null skb and forbidden forward direction. I/O/device/header reads are fixtures.
Full kernel/modules/source/config/CRC audits are performed by the isolated runner.

Integration limitation: this first primitive reads par->out for OUTPUT. The old
kernel mangle hook can reroute after nf_hook_state.out was selected, so that
pointer can be stale. A follow-up must use current skb destination/route and audit
packet ordering before any activation. This proposal is inactive, not a complete
packet-path equivalence or network-readiness result. Existing owner skip is unchanged.

Full kernel/modules job exits0. Image d7dc8bdbe91c970d05d1f040ea4469a3be4130e1c2dba6b5431f473a33a6674b.
Original config fac42... is retained, Gator118/KUTF43 CRCs pass, full60338 candidate/
60331 protected tracked files and Android1243/17 audits match before/after. This
build evidence does not resolve the routing limitation described above; the
follow-up kernel-non-loopback-route-20261106-01 supersedes its OUTPUT selection.
