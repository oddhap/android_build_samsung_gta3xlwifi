# Separate raw socket UID and appId matches

Extends the isolated lookup-appId kernel proposal with private revision0
`gta3xlwifi_raw_uid` and `gta3xlwifi_raw_appid` eight-byte inclusive ranges.
They read the full socket UID in its network namespace, with actual overflowuid
for absent/non-full sockets. They do not perform qtaguid receive-side slow lookup.
Raw UID preserves65534; raw appId maps literal65534 to root, then takes modulo
100000. This preserves the distinct Android17 xtbpf metered deny/allow semantics.
The lookup-appId missing-socket default also uses actual overflowuid. Original
owner revision1, accounting and initialization remain unchanged. Private ranges
require the initial user namespace and IPv4/IPv6 input/forward/output hooks.

Host raw fixture02 passes19 cases plus896 comparisons with actual A17 metered
expressions. Lookup overflow fixture02 passes24 plus343599 A17 core UID comparisons.
Fixture overflow01 failed before compilation due to a missing unchanged header;
that failure is retained. Socket/map/namespace helpers are fixtures, not packets.

Full `kernel-raw-uid-build-20261106-01` finishes exit0. Image SHA256:
`d99587cc3b1ff4b879f6fbfcb7cf36f0efacd9c7a184e96299a2dc63e8011348`.
Original config fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea
is preserved. Gator118/KUTF43 CRC checks pass. Complete60336 candidate and60331
protected tracked-source audits plus Android1243/17 audits pass before/after.
All44 lease cases,24 lookup cases and19 raw cases pass against this full tree.
No Android prebuilt, firmware, vendor image or device is changed. This is not a
complete network implementation or a flashable ROM.
