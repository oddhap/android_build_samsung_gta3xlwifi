# Referenced receiver identity from a typed tuple

Adds a kernel-only typed TCP/UDP tuple lookup helper for both inet families.
It uses inet_lookup/inet6_lookup and udp4_lib_lookup/udp6_lib_lookup, not the
INPUT-only qtaguid skb helper on OUTPUT. Caller supplies a parsed tuple/current
interface and protects net lifetime. Unsupported/absent/unknown results preserve
output. IPv4 packets may resolve a dual-stack IPv6 socket; family equality is not
artificially required. UID0,65534 andUINTMAX stay literal, with no root substitution.

A request is converted to its listener while the ORIGINAL lookup reference is
held. The immutable creator is read before sock_gen_put(original), exactly once.
The borrowed listener is never put as if independently referenced. The old request
allocator holds its listener and its destructor releases that reference; source
contracts are checked. Timewait and unmarked sockets supply no creator result.
This API supplies no packet eligibility, permission decision, callback or readiness.

8 cases plus672 tuple/identity/reference comparisons pass with fatal UBSan.
Actual helper, creator getter, full-socket and request-conversion C bodies execute
with lookup/object/reference fixtures. All four lookup paths, exact address/port
bytes, indexes0/1/7, unknown/unmarked/timewait/request variants and post-put object
poisoning are checked. Fixture01 failed counter names conflicting with stdio;
test counters only renamed, product source unchanged. No actual socket lookup
or packets run. Modern helper reference: [Linux BPF socket lookup](https://raw.githubusercontent.com/torvalds/linux/v6.6/net/core/filter.c).

Full kernel/modules build exits0. Image SHA256:
`04790c406116b94b63ba54694dbefc7f431643a484c83af0d18881fe6d295d33`.
Original config fac42... is retained, rebuilt Gator118/KUTF43 imports match exports;
complete60340 candidate/60331 protected plus Android1243/17 before/after source
audits pass. All earlier fixtures also pass. The actual peer symbol is present.
Nothing is selected in Android prebuilts. Mandatory permissions and real packet/
startup/framework-provider integration remain incomplete; this is not a test ROM.
