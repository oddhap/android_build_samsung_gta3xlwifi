# Actual-socket egress LNA attachment

**CLAT correction:** the untagged raw socketUID1029 case in this historical
prototype was too restrictive. `kernel-egress-clat-20261108-01` explicitly ports
A17's statsUid fallback and supersedes that expectation. Do not promote this
historical Image as the final egress implementation.

Isolated extension of the receive-context proposal. The supplied full AF_INET/
AF_INET6 socket, not skb owner or INPUT-only peer lookup, determines mutable UID.
Real qtaguid accounting metadata supplies CLAT (statsUID1029, egress only) and
system DNS (statsUID1051/tag0xffffff82) exceptions. Process UID alone never grants
these exceptions. The held gate precedes them and the complete decision stays
inside the actual RCU drain domain. No predicate changes skb ownership or data.

Policy executes at IPv4/IPv6 finish-output after POST_ROUTING, before the preserved
GSO/fragmentation/XFRM body. Original bodies are byte-identical after renaming;
rejection frees exactly once and does not call downstream output. Original errors
propagate without a second free. IPv4 multicast/broadcast clone callbacks get the
same check, preserving the selected4.4 loopback transmit behavior. Modern6.6 has
an additional route-clone operation which is not silently backported here.
IPv6 sets protocol and actual output dev before POST_ROUTING as modern ip6_output
does; it previously lacked those assignments. The policy observes actual dev,
never skb_iif or a guessed early socket. Reference URLs and SHA256 are pinned in
reference-provenance.json. Unsupported modern congestion markings are not invented;
this primitive returns allow0 or a negative denial, with no congestion result.

Host run kernel-egress-context-host-20261108-02 passes51 output assertions plus
51 receive cases/5,632 actual Android17 parser comparisons. Tests compile real
policy/store/parser/wrapper C with syscall/socket/RCU/output fixtures and fatal
UBSan. Cover tagged CLAT vs process UID, ingress not exempted by CLAT, DNS pair,
mutable UID and absent/foreign skb owner, actual IPv6 packet, exact destination
prefix/device/port, all three wrappers' consumption, preserved original bodies
and contended HOLD drain. Initial host01 passed49 assertions but the report's
minimum50 check failed; host02 adds two real IPv6 checks. Historical failure is
retained. Full kernel/modules and native xtables pipeline exit0 at16:08:04UTC Nov8.
Image SHA25667ec0b37f058df501732522a89d7ec0f9de7a03c355681674ce339c4ae5915bb,
configfac42 unchanged;60349/60331 tracked kernel hashes and1243/17 Android audits
match before/after. Gator118/KUTF43 imports match. Actual xtables archive/ARM64
link and70 original+7 private registrations pass. Source/log/hash evidence only
is collected, with binaries kept on the build server.

Capability bit64 means compiled output hooks only. Together with bit32 receive,
this is still only LNA/shared gate, not complete ordinary UID/VPN/IIF policy,
loopback enforcement/metrics, accounting, native publication or networking startup.
No prebuilt promotion, hardware execution or flash approval.
