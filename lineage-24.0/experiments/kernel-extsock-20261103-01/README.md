# Isolated extended socket class candidate for the preserved kernel profile

This adds actual extended-socket classification for the 4.4 kernel's existing
address families and ICMP datagram sockets, controlled by policy capability2.
The old selector is preserved when cap2 is off. Supported-UAPI modern selection
is ported while retaining the existing DCCP class and legacy protocol defaults;
MPTCP and newer address families do not exist in this kernel. Twenty-six class
entries are appended without changing any existing class or permission number.
Common socket permission bits match exactly across the appended classes.

The existing create/post-create/socket permission hooks use those real class
values; bind explicitly selects ICMP and SCTP node_bind bits. Enabled Phonet and
INET/IPv6 are included in the review. SCTP is disabled in the preserved config,
and enabling it deliberately fails compilation until its association and extra
bind/connect LSM hooks are implemented. The class declaration is not a claim of
SCTP support. Bluetooth, VSOCK, and crypto userspace algorithms are also disabled.

Capability2 is loaded from the actual policy bitmap, not fabricated. The old
redhat1 slot/name is corrected to canonical extended_socket_class. Existing
NNP/FunctionFS capability names and unnamed unsupported gaps are preserved.
Netlink capability9 rejection is retained.

Mac ASan/UBSan actual-body fixtures pass 360,448 selector comparisons, 16,384
capability-loading combinations and 216 create/label/bind/error scenarios. The
cap-off oracle is the actual old selector. The cap-on oracle is the actual
modern selector restricted to this old UAPI and old protocol defaults; the
preserved legacy DCCP branch is an explicit exception. Real create, post-create,
sock_has_perm and bind bodies run with fixture credentials, transitions, AVC,
network labels and address objects. A control confirms SCTP-enabled compilation
fails with the intended error. This is not live networking or socket enforcement.

Target constants/layout are from data-only cross compilation using the parent
kernel's original hooks compile recipe. All outputs stay outside its source and
output trees. Three captures are retained on the server: initial UAPI, added bind
sizes/constants, and added kernel SID. The final 120-value report is used here.
An initial harness compile lacked the fixture max macro; only that fixture was
corrected. No active Android source/prebuilt or tablet partition is changed.
Strict policy, remaining kernel hooks, networking and installer/FBE gates remain.


## Complete build and Linux fixture checkpoint

`kernel-extsock-build-20261103-01` completed exit0 at 18:40:29 UTC, followed by
`kernel-extsock-host-20261103-01` exit0. Mac/Linux fixture results, source and
runner hashes match. Image SHA256:
`23e3ad6d7b322788378ed9fe1bbc8f1c7288e69c6f858f2724f5ffb0ffaaa790`.
Full 60,331-file tracked-source/protected-input audits pass. Preserved config and
all original Module.symvers bytes/CRCs match. Firmware inputs match originals;
the qtaguid header is unchanged after build, and all three untracked source files
are explicitly hashed. Complete source inventories remain on the server, bound
by evidence-lock.json. No Image is promoted and no live socket/boot approval is
implied. Active inotify watch checks, prlimit/getrlimit and perf-event mediation
remain further kernel work; INOTIFY_USER and PERF_EVENTS are enabled.
