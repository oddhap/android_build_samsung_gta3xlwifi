# Held-gate metered parent bridge

Connects existing BandwidthController costly-interface paths through
bw_penalty_box -> g24_meter_deny -> bw_happy_box -> goto g24_meter_allow.
The three owned typed chains still implement deny union, system/happy allow and
data-saver fallback. It preserves quota/shared/interface/forward caller chains,
root policies and all foreign rules; it does not replay their text.

The six exact A17 critical ICMPv6 exceptions are retained after deny and before
happy. Moving them here is verdict-equivalent whether data saver is enabled or
not. Actual factory names, wildcard code ranges and canonical ip6tables -S
protocol/match/type spelling are hash-bound in the test. Existing bw_data_saver
is untouched; selected startup/control code must route data-saver operations to
the new owner, rather than updating that unused chain.

Preparation inventories both families before creating only missing owned empty
chains. Bandwidth parents must already exist and be empty or exact known prefixes.
Foreign/old BPF rules, wrong parent order, unrecognized owned namespaces/references
or incomplete nonempty programs fail closed before writes; nothing is silently
removed/replaced. Activation requires both full typed images, installs only
missing exact parent suffixes and checks complete roots/programs/foreign text.
No release/readiness, accounting, bandwidth init or native control routing occurs.

Host02 passes141 assertions and1280 verdict graph comparisons across data saver,
happy/deny membership, system/overflow/multiuser UIDs, quota and IPv6 critical
traffic. Failure before/after EACH prepare/activate I/O, partial recovery, both
family validation before writes, foreign preservation/drift and malformed/old
parent rejection are covered. Syscalls/table execution are fixtures, not actual
kernel packet tests. Host01 fixture indentation warning is preserved.

Native01 exit0 at09:29:29UTC November13: actual nine-source Android17 ARM64 netd
LTO/CFI compile and partial link, six kernel UAPI and1243/17 source audits pass.
No production object, selected image/policy, interface/quota or device changes.
