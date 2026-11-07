# Exact UID-image ioctl policy grants

The production and debug isolated proposals append only netd allowx rules for
low16 ioctl codes6754/6755/6756. Existing four-command access, root/read-only node
and sysfs labels remain. All5918 production and5881 debug assertion/constraint
records are byte-token identical in the inventory. Android17 platform and Samsung
vendor assertions, legacy vendor symbols and all other input bytes are preserved.
This extends the explicitly ported platform-policy component; no Android11
platform input is silently substituted and no image input is selected here.

uid-permission-policy-20261107-01 completed exit0, including full1243-project/
17-patch before/after audits. Both actual A17 strict compilers return0 with no
normal/extended assertion diagnostics. Both binary policies pass17 actual access
queries, genfs context resolution and checkfc validation. No permissive domains.

For each flavor, seven extra contradictory neverallowx probes fail with exactly
the expected single assertion diagnostic, proving the actual6750..6756 grants.
Extra assertions denying neighboring674f/6757 compile successfully. These probe
assertions are additional negative-test inputs, never image policy inputs.
Compiled policy binaries and full generated CIL stay on the server. This folder
contains only source/log/hash/command metadata. No runtime/packet/flash proof.
