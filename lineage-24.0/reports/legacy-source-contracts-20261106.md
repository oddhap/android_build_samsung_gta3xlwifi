# Legacy service and network source contracts

The companion JSON hashes twelve actual current source/config files and records
the relevant snippets. This is source review, not native HAL, packet, keymaster
or permission execution validation.

The Health factory retains an explicit AIDL-to-HIDL fallback. Keystore2 retains
its Keymaster4 compatibility enumeration; the connector still needs real vendor
services and hardware-level validation. These source paths do not establish
successful TEE operation, key upgrades or rollback.

The actual kernel config enables ANDROID_PARANOID_NETWORK. Both IPv4/IPv6 socket
constructors gate access through current_has_network, and Android17 platform.xml
still maps INTERNET to the inet group. This existing enforcement must be reviewed
alongside UID permissions; an in-memory permission value alone is not evidence of
a new enforcement backend. A future backend probe should test actual disconnected
socket creation with and without inet membership and privileges removed.

The current boot action waits for bpf.progs_loaded before starting netd. Netd
itself is disabled until explicitly started and is deferred until APEX readiness.
A legacy netfilter owner therefore requires an explicit product-scoped bootstrap
order, real rule installation/readback and its own truthful readiness condition.
Other products must keep their upstream startup behavior. Setting the BPF-loaded
property without loading BPF programs is not an acceptable port.

The native BPF handler/wait helper and the broad Java BpfNetMaps API remain
consumers to port. UID chains, permissions/chunks, interfaces/VPN, LNA prefixes
and host exceptions, stats/quotas/tag authorization, persistence and restart
behavior all need actual supported implementations. No callback registration,
BPF skip or network readiness was enabled by this review.
