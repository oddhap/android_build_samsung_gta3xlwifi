# Truthful interface correction capability

This isolated delta adds private UID_FEATURES bit 11 (0x800) for the compiled
IPv4+IPv6 postrouting DROP correction. It is reported only with successful real
interface-match registration, alongside bit 10 (0x400). Configurations without
both builtin INET and IPv6 do not report correction availability. This is not a
BPF map, kernel version change, installed-rule flag or complete accounting/Ready.
The new userspace admission check requires BOTH bits before producer setup.

These private transport bits are distinct from SELinux policy capability bits.
The latter supported/unknown-capability behavior, enforcement and assertions are
unchanged. No new ioctl, SELinux grant or wire layout is introduced.

The actual feature getter bodies pass 12 checks across four config fixtures;
the actual unchanged builtin product config is bound. A separate exact source
identity report verifies all four changes and byte identity of the six existing
counter/correction functions. Their previous 251-case wrapper test is re-run on
the immutable prerequisite; current counter/owner/receive/egress/loopback/ingress
and source-oracle regressions run in the fresh candidate build. The prior output
code identity checker verifies all four actual ARM64 output call relocations.

Full fresh kernel-iface-capability-build-20261113-01 passes Image, configured
modules, Gator 118/KUTF 43 import CRCs, unchanged configuration, 60360 candidate/
60331 protected source hashes and 1243-project/17-patch Android before/after audits.
Image SHA256:
`24f37c9111a524b1870dbfbd00258cf27446a15f7dbc7068b97d613d7e223ca9`.
Config remains
`fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea`.
No selected prebuilt, policy input, signing material or device is changed.
