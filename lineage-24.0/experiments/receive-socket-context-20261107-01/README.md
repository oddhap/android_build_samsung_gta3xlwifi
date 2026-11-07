# Receive socket context is a mandatory attachment gate

Primary upstream Linux6.6 cgroup skb filtering temporarily binds the supplied
full inet socket while running the program, then restores the prior skb socket.
See the URL/hash in reference.json and [upstream source](https://github.com/torvalds/linux/blob/v6.6/kernel/bpf/cgroup.c).
Its receive call is in sk_filter_trim_cap before LSM and socket filters. The old
4.4 tree has no such cgroup receive stage; ordinary IPv4 LOCAL_IN occurs before
protocol delivery. Early demux may associate some packets, not a proven universal
replacement for the actual receiving socket context.

Host03 combines actual LNA store/decision, parser, raw UID and match C. An input
with no associated socket permits under the normalized root identity, while the
same packet with a supplied receiving UID10001 is denied by a global denied
prefix. Nine assertions with fatal UBSan reproduce the gap. Binding is a fixture
derived from the modern wrapper, not real kernel packet execution. First two
fixture attempts failed function-extraction/unused-variable checks only.

Next implementation must provide the correct receiving socket/lifetime and stage,
retain mutable raw UID for ordinary/LNA identity (creator identity is different),
preserve original skb state, handle DNS metadata, NAT/demux/order and shared guard
semantics, and test TCP/UDP/raw/SCTP/DCCP/IPv6 paths. Do not substitute guessed UID0,
blanket DNS/core exemptions or assume an installed INPUT match solves this gate.
No existing or experimental image is approved for flashing.

The modern wrapper also supplies socket context for egress. OUTPUT equivalence
must be audited too, including kernel-generated packets and hook-state socket
versus skb socket. The current counterexample specifically proves the INPUT gap;
it is not proof that every egress case already has the correct socket context.
