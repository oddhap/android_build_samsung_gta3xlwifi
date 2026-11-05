# Explicit restricted ownership for 32 vendor properties

This isolated proposal follows legacy-policy-access-20261105-03. The reviewed set
has only actual vendor-prefixed context names, no direct existing owner membership,
and no direct known core/broad writer symbol in the bound inventory. Context names
and observed writer statements are recorded per type. Unreferenced labels and
properties with observed core writers are deliberately left for separate review.

The proposal adds vendor_property_type and vendor_restricted_property_type
membership through one new private grouping attribute. It adds the current
vendor_restricted_prop writer assertion using a private non-init core grouping.
The legacy public init_30_0 alias maps exactly to init in the pinned actual mapping.
All original vendor statements remain byte-for-byte. No vendor_public scope or
new allow is introduced. Actual indirect writers are still subject to every
current assertion and the additional explicit writer restriction.

Strict compilation still fails with **67 diagnostic blocks**. Resolving ownership
for these 32 types does not remove the shared diagnostic while other unowned
types remain. No diagnostic assertion identity is new. All **5,917 existing
assertion/constraint records** remain, and one new neverallow brings the inventory
to **5,918**. No AV grant statement or permissive declaration is added. Membership
changes can affect existing rule expressions; no effective permission equivalence
or monotonicity proof is claimed. Runtime reads/writes and values remain untested.

Only vendor CIL changes among ordered compiler inputs; all others and the compiler
hash match. Complete 1,243-project/15-patch before/after source audits pass and
match. Secilc255 is failure; runner0 is experiment completion. Exact tools, selected
properties and added CIL are archived. No source, context file, vendor image,
precompiled policy/cache hash, signing material or tablet is modified.
