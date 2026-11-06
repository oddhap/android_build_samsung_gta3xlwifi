# Private appId xtables registration

New revision0 match uses the byte-identical private kernel UAPI and a mandatory
bounded uint32 range `--appid minimum[:maximum]`. The actual xtables range parser
is used; inversion is not enabled. Printing/saving emits an explicit range.
The separate name cannot be silently interpreted as an unknown owner-revision1
flag on an old kernel. It does not alter the existing guard extension.

The combined native verifier compiles BOTH extensions with actual Android17
commands, reproduces the original registry exactly before adding them, creates
the complete archive and links the whole ARM64 iptables binary. Actual final
machine code registers both match structures. Existing initialization symbols
and dynamic dependencies remain, and both headers match the actual built kernel.
Complete 1,243-project/17-patch source audits pass before/after. No CLI parser
execution, saved-rule roundtrip, rule installation or packet behavior is claimed.
No TOP or Android prebuilt input is changed. Complete backend integration remains.
