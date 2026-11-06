# Immutable inet creator identity prerequisite

Adds private creator UID/valid metadata to struct sock. Explicit IPv4/IPv6 create
hooks capture the real UID in init_user_ns, matching the low32 bits of the BPF
current-UID helper, rather than mutable inode/sk_uid or fsuid. Kernel-created
sockets have no valid marker. Clone reset clears both fields after sock_copy:
A17's sk_storage map uses default zero flags, without BPF_F_CLONE. Original
sock_init_data, sock_copy and sock_graft bodies remain byte-identical; the normal
sk_uid, accounting and socket ownership semantics are not replaced.

The candidate provides no receiver socket lookup, permission table/check,
BPF storage emulation, callback or readiness signal. Its metadata is not consumed
by active rules. It is a prerequisite for a future independent loopback policy.
Socket data created before any future policy initialization and exact lookup/
attachment ordering still require explicit treatment and device validation.

Host fixture02 executes the actual new init/reset C bodies plus the existing
kernel BPF current-UID helper body under fatal UBSan, with credential/namespace/
object-copy fixtures.960 comparisons cover user/kernel creation, real UID versus
inode UID, owner/FD-recipient changes and non-inheriting clones. Exact IPv4/IPv6
and clone hook placements and unchanged original functions are source-checked.
Fixture01 failed a test verifier's macro spelling assumption; both actual header
variants still have literal-zero flags/no CLONE. Test only fixed, source unchanged.
The exact four-file incremental patch and reverse replay are verified.

Primary references: [Linux UID helper](https://raw.githubusercontent.com/torvalds/linux/v6.6/kernel/bpf/helpers.c),
[IPv4 create hook](https://raw.githubusercontent.com/torvalds/linux/v6.6/net/ipv4/af_inet.c),
[IPv6 create hook](https://raw.githubusercontent.com/torvalds/linux/v6.6/net/ipv6/af_inet6.c).
The modern create hooks skip kernel sockets. These references do not establish
that this old kernel executes modern BPF or that its new marker has runtime parity.

Internal struct sock layout changes, requiring matching rebuilt modules. Full
kernel/config/source/module-CRC validation is required; all vendor prebuilt module
inputs must be inventoried before promotion. No Android prebuilt is replaced.

Full kernel/modules build exits0. Image SHA256:
`dec48db3d5dbd684a9274823b3f1b8cc412c048606137a23dba595557fc77cbd`.
Original config fac42... is preserved. Rebuilt Gator118/KUTF43 imports match this
kernel's exports. Complete60338 candidate/60331 protected and Android1243/17
source audits match before/after; the actual creator init symbol is present.
All earlier lease/raw/lookup/packet fixtures plus960 identity comparisons pass
against the full tree. Four UAPI headers and all previous six-extension native
inputs remain hash-identical; binary/archive reuse hashes are recorded. This
establishes build/contracts, not compatibility with original prebuilt modules,
real socket lifecycle execution or loopback permission enforcement.
