# Explicit Android17 private accounting factory

The actual BandwidthController gains a pure static
`makeGta3xlwifiAccountingCommands()` entry point. Its source program retains
IPsec interface/policy returns, CLAT_MARK duplicate suppression, billing marks,
global alerts and shared quota attachment. Four original BPF/metered-parent rows
are deliberately omitted, leaving EMPTY penalty/happy parents for MeteredRoots.
The ingress/raw and egress/mangle BPF producers are replaced by the real private
interface match. Data-saver changes must use the shared policy owner rather than
the retained old bw_data_saver chain.

The original generic factory, initialization, quota methods and all other
controller code are byte-identical. This new entry point constructs commands;
it does not flush, inspect, migrate or install live/foreign rules. It is not
selected into Android startup automatically.

The actual old/new factory functions pass 1040 checks over 20 mark variants.
Their whole ordered output differs only by the four intentional omissions and
two producer substitutions. Actual Fwmark/Permission, frozen INetd18 CLAT_MARK,
IPsec and BPF path source inputs are hash-bound. The complete modified controller
compiles with its actual Android17 ARM64 netd LTO/CFI command and partially links;
1243-project/17-patch audits pass before and after. See bandwidth-factory-host and
bandwidth-factory-native-20261113-01. No production object or image is replaced.
