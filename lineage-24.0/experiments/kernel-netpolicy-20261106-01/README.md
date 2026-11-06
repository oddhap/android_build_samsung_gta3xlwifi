# Isolated leased packet barrier

Prerequisite: `kernel-gator-20261105-01`. This proposal does not change Android
prebuilt inputs, install packet rules or advertise networking readiness.

Independent IPv4 and IPv6 iptables updates cannot provide one commit boundary.
This kernel component supplies one shared, initially held match state. A sole
userspace owner must install and verify `-m gta3xlwifi_guard -j DROP` rules at
all required hooks in both families before relying on it. The distinct match
name and device prevent an older kernel from silently accepting an unknown
option on the ordinary owner match. Existing owner and qtaguid behavior is intact.

The private misc device has an exclusive file/PID lease. Opening and every ioctl
require root in the initial user namespace with CAP_NET_ADMIN. HOLD closes the
barrier and drains network readers. RELEASE drains readers while still held,
then opens the shared state. Owner descriptor close closes the barrier, including
when forked children retain references. A child close does not revoke its live
parent's lease. The last file release also closes it if performed by another
task; an old file cannot revoke a new owner's lease.

The four no-argument ioctls are ABI `0x6750`, HOLD `0x6751`, RELEASE `0x6752`,
and STATE `0x6753`. ABI returns version 1; STATE reports the real held bit.
Other commands, nonzero arguments and foreign owners fail. The four reserved
match bytes must be zero. No readiness property, fake BPF result, permission
fallback, automatic rules or SELinux input selection is introduced.

The host fixture extracts actual C bodies and tests 44 lease, ownership, close,
registration and grace-order cases, including real mutex contention. PID,
credentials, packets and grace periods remain fixtures. Native preflight uses
the actual Samsung GCC4.9 command and headers to compile an ARM64 object. Neither
check establishes real kernel packet processing, FD lifetime or network behavior.

The full isolated build runner clones the protected original kernel without
hardlinks, verifies/replays exact patches, preserves the exact configuration,
and audits all tracked source hashes before and after. It builds Image and
modules and checks actual Gator/KUTF import CRCs. Build attempt01 failed before
kernel compilation because the host test included the raw kernel UAPI tree.
The test tool now exports only the exact private header and uses installed host
ABI dependencies. Kernel source was unchanged; attempt02 uses fresh paths.

Userspace xtables registration, verified guard attachments, the owner transport,
strict private-device SELinux policy and a complete Android17 networking backend
remain required. The existing qtaguid `0x7151` policy proposal does not cover this
new device. No flash-ready or runtime validation claim is made.

Full build attempt02 completed exit 0 on November6 at 11:29:07 UTC. It passed
44 host cases against the complete staged tree, built Image and both modules,
and verified 118 Gator plus 43 KUTF imports against actual exported CRCs. All
60,334 candidate and 60,331 protected tracked-file hashes match before/after.
Exact config remains `fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea`.
Candidate Image is `2bfd071921a7967ceb677f6314638572630e69293cb17df103bafa5eda339bad`;
it remains outside Android prebuilt inputs. Source, logs and metadata are archived
separately; no binary image, module or signing material is published here.
