# Isolated xperm / access-vector generation binding

The old AVC drops its RCU read section before computing an extended decision.
A policy reload in that gap can combine the previous access vector with extended
permissions from a newer policy. This candidate stamps the extended computation
with `latest_granting` under policy_rwlock, and returns EAGAIN before caching,
permissive grants or auditing if that generation differs from avd.seqno.
Initial capabilities/initialized/generation publication is also enclosed in the
policy write lock; AVC reset and completion remain outside that lock.

The sanitized actual-body host fixture passes 640 injected generation-mismatch
cases plus 4,784,128 helper and 807,936 AVC regression scenarios for each of two
conditional Samsung configurations. It checks cache-miss and base-cache-hit
paths, both extended namespaces, error ordering, RCU balance and absence of cache
insertion, permissive grants or permission auditing on mismatches. Source-order
assertions check the generation stamp/publication placement; they are not a real
concurrent policy-loader test. Existing cache-hit behavior remains unchanged.

This is only one part of coherent netlink enforcement. An entire skb still needs
one snapshot of capability/mode/generation, stable lookup semantics and final
validation. Netlink capability9 rejection remains in place. No Android source,
prebuilt or device is changed; no boot, whole-policy or flash approval is implied.


## Complete standalone build

`kernel-xperm-generation-build-20261103-01` completed exit 0 at 18:12:12 UTC.
Image SHA256 `d9d1c8efbb10de2a54b5be3ea0a18e1e5b1bc85dfb68539bc60200f143d5956e`.
The full 60,331-file tracked-source audits pass before/after, protected source is
unchanged, the added qtaguid header matches its pre-build copy, firmware inputs
still match the originals, config is byte-identical and Module.symvers matches
all original exports/CRCs. Full source inventories are retained on the server
and locked by evidence-lock.json. See build-review.json and build.log.

The Linux sanitized fixture also passes with exactly the Mac result counts and
source hashes. No Android Image promotion, policycap9 enablement, live execution,
whole-skb consistency or flash approval follows from this checkpoint.
