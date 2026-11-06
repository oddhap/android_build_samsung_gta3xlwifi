# Current-route OUTPUT interface selection

Uses skb_dst(skb)->dev for the OUTPUT non-loopback predicate. The old hook-state
output pointer can be stale: both IPv4 ipt_mangle_out and IPv6 ip6t_mangle_out
invoke route-me-harder after changes, without rewriting the original nf_hook_state.
INPUT still uses the incoming device. Missing current route/device is index0,
which is not exempt. This is a one-file incremental change; no match/UAPI,
original owner/skip, accounting or private lease behavior changes.

24 cases plus5774610 actual A17 parser/skip comparisons pass with fatal UBSan.
New fixture cases cover old loopback/current non-loopback, the reverse reroute,
missing old output with a valid current route and absent current route/device.
They validate C selection logic with fixtures, not actual routing or BPF execution.
The full isolated kernel runner preserves/audits all source/config/module inputs.
Existing six-extension UAPI must remain byte-identical before binary reuse.

No hooks or readiness are activated. Final attachment/cgroup-versus-netfilter
ordering, independent LNA/loopback/VPN/IIF/DNS/CLAT enforcement, startup/provider
and actual device execution remain required before a network test package.

Full kernel/modules build exits0; Image SHA256:
`b131fcd4195b3781cea2fe6c84fe45c55acb688517dc2418832971b9f757773e`.
Original config fac42... and Gator118/KUTF43 CRCs are preserved. Complete60338
candidate/60331 protected tracked-source and Android1243/17 audits match before/
after. All prior lease/raw/lookup and new24/5774610 fixture cases pass in the full
tree. Reuse report verifies all prior native six-extension inputs remain unchanged,
all four UAPI headers match the new full kernel and native binary/archive hashes
are recorded. No ABI or userland recompilation was needed for the internal route fix.
