# Narrow direct sandbox and app-data access

This offline candidate removes isolated_app's direct shell-data open permission,
retains its FD operations, limits platform_app tombstone-file access to read and
getattr, and removes one system_app APK-directory mutation grant. All other text,
labels, attributes, MLS constraints and assertions are unchanged. Two replaced
allow permission sets are strict subsets with identical source/target/class.

Strict diagnostics **65 -> 62**, no new diagnostic assertion identity. All 5,918
assertion/constraint records remain. Full before/after source audits match:
1,243 projects / 15 exact patches. Every other compiler input/hash is unchanged.
Secilc255 is still failure; runner0 is experiment completion. No -N compile,
active source/image/cache change, signing or device operation is performed.

The new positive property-closure inventory handles nested positive dependencies,
typealiasactual and the actual M4 product_property_type-to-system_property_type
alias. It rejects unsupported negative/unknown/cyclic dependencies. The initial
guards exposed the alias cases and were extended before producing the successful
inventory. This inventory finds 524 concrete property types and 66 unowned types;
it is ownership analysis, not AV/MLS runtime approval.
