# Private LNA parser/match primitives — attachment not approved

Adds an exact40-byte A17 relative-L3 parser and a private gta3xlwifi_lna match.
Parser handles mapped IPv4 addresses, IPv6's single hop/dst extension andu8 offset
wrap, TCP/DCCP/UDP/UDPLITE/SCTP ports and ICMP type/code bytes, matching zero-filled
read failures. The match uses normalized raw socket UID, ingress source/current
input index, egress destination/current skb_dst device. No DNS identity or exemption
is invented. Match feature bit4 is reported only after actual registration succeeds.

Host17 cases +2887305 full-packet comparisons and5774610 UID/device/remote-endpoint
fixture dispatch checks pass against actual A17 parsing. Registration failure keeps
its feature absent. The original raw UID implementation is unchanged. First fixture
failed only u8 include order and loop braces; production source unchanged for retry.

Complete kernel-local-packet-build-20261107-01 exited0. Image SHA256:
9d7f49c7771883aa0d98f4dbe8147fc096b62bd0cc2c96a9859012b3682e0213.
Configfac42...b3acea unchanged; all60348 candidate/60331 protected kernel source
hashes, Android1243/17 audits and matching Gator118/KUTF43 imports pass. Actual
whole iptables registration and strict new ioctl policy checks passed separately.
No Android prebuilts or tablet state changed.

CRITICAL: this proves parser/predicate/build contracts, not complete ingress
attachment. The modern cgroup skb wrapper explicitly binds the supplied full
receiving socket. An early netfilter INPUT skb is not guaranteed that context.
receive-socket-context-host-20261107-03 reproduces the difference with actual
store/parser/raw UID/match C: unassociated skb normalizes65534 to root and allows,
while the real modeled receiving UID10001 is denied by the same network prefix.
Do not activate plain INPUT rules as a complete A17 ingress replacement. Correct
socket-aware receive placement, DNS tag ordering, guard lifetime/atomicity, receive
accounting and other ordinary/VPN/IIF behavior must be implemented and validated.
The immutable creator UID is for loopback receiver identity; it must not replace
mutable raw socket UID for ordinary/LNA packet identity. No readiness claim.
