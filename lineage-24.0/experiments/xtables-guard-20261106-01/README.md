# Builtin leased-barrier match registration

Two new files for the pinned Android17 iptables revision. The UAPI header is
byte-identical to the isolated kernel proposal. Existing Android.bp source globs
pick up the extension and generate its unique builtin initialization function.
No source/build configuration is applied to TOP and no packet rule is installed.

The native verifier reproduces the original registry byte for byte using the
actual generator, adds the new extension, uses actual Android compiler commands,
recreates the complete libext archive and links the whole ARM64 iptables binary
with the original strict flags. All existing registration symbols and dynamic
dependencies remain. Final AArch64 disassembly proves init_extensions passes
the new match structure to xtables_register_match. Full 1,243-project/17-patch
source audits pass before and after. Forward/reverse temporary replay and a
read-only apply check against the actual VM source also pass.

Attempt01 linked successfully but its final verifier expected an initialization
function symbol that ThinLTO correctly inlined. It is preserved as a failed
verification; both source audits passed. Attempt02 verifies the actual machine
code registration and callbacks instead and passes completely. This checks real
native linking/registration, not Android execution, saved-rule round trips,
kernel attachments, packet behavior or complete networking readiness.
