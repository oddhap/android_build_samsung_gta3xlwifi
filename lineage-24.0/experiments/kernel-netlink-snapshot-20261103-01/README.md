# Isolated whole-skb netlink policy snapshot

The skb hook captures initialized state, generation, netlink-xperm mode, Android
RTM_GETLINK mode, alwaysnetwork and allow_unknown under policy_rwlock. Lookups use
that snapshot and immutable tables. The shared mutable GETLINK table update is
removed. Legacy kernel-SID exemption remains unconditional in the legacy branch;
the extended branch retains its captured alwaysnetwork behavior.

Base and extended AVC calls reject a cached/computed access vector whose sequence
number differs from the captured skb generation, before permissive handling or
permission auditing. The parent change also binds freshly computed extended
permissions to the access-vector generation. All successful hook exits validate
the generation again, including empty packets, malformed headers and short tails.
A reload returns EAGAIN. No policy lock spans AVC or audit recursion. Existing
generic AVC APIs retain wrappers with no expected-generation filter.

Sanitized actual-body host fixtures pass on Mac: 2,621,440 lookup/stability checks
against the old lookup across all 16-bit types; 38,400 packet/error/injected-reload
scenarios; 32 state snapshots; and per Samsung configuration 2,680 generation/API
scenarios, 4,784,128 helper and 807,936 AVC regression scenarios. Packet, policy-lock
and AVC backends are sequential fixtures. Source bodies are real; these are not
live policy reload, packet enforcement, boot or hardware tests.

The fixture UAPI constants and layout are captured in a data-only target-compiled
object using the already-built kernel's original compile recipe. No target code
is executed. The report locks source, recipe, compiler, generated input and output.
The first 119-constant capture remains on the server; the second also includes an
unhandled class and actual kernel SID (121 constants). No guessed modern host
header substitutes for this kernel UAPI. The initial hook fixture compile failed
on its assertion-macro statement form and omitted unhandled-class fixture value;
the corrected fixture uses a statement block and that target-compiled constant.

Capability9 load rejection is retained. No active Android source, Image prebuilt,
policy assertion, SELinux enforcement setting or tablet partition is changed.
Other active capabilities and enforcement gaps, strict actual-vendor policy,
complete legacy networking and Android17 FBE/installer/rollback remain gates.


## Complete standalone build and Linux fixtures

`kernel-netlink-snapshot-build-20261103-01` completed exit 0 at 18:24:21 UTC.
`kernel-netlink-snapshot-host-20261103-01` completed exit 0 after acquiring the
same build mutex. Mac/Linux fixture results, runner and source hashes match.
The AVC stdout's historical "generation mismatch" label includes 120 matching-
generation API checks within the 2,680 generation/API scenarios per config.

Image SHA256 `a80d8caf62d84b8b57c8455a725a3e2d77140e8831ffdc1455ee24bab0358e01`.
The full 60,331-file tracked-source before/after audits pass, protected source is
unchanged, the added qtaguid header matches its pre-build copy, preserved firmware
inputs match, config is byte-identical and all original Module.symvers bytes/CRCs
match. All three untracked source files are explicitly identified and hashed,
including the two build-generated Defex rule files. Full inventories are retained
on the server and bound by evidence-lock.json. See build-review.json and build.log.

This is a complete compilation and host-fixture checkpoint, not live concurrent
reload or packet-enforcement validation. The active Android kernel is unchanged.
Netlink capability9 rejection remains; other active kernel features, strict
vendor policy, networking, FBE and installer/rollback gates still block flashing.
