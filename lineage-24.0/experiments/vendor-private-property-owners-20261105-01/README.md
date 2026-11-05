# Restricted ownership for the remaining vendor-private properties

The complete positive ownership graph identifies 66 unowned concrete types. Every
one is declared exclusively by this vendor CIL and has no existing owner/scope.
The reviewed list is fixed in the stager. This proposal assigns restricted vendor
ownership based on that private declaration origin, expanding the existing private
restricted-property group from 32 to 98 members. Four have actual vendor-prefixed
contexts; 62 have no reference in the audited vendor property-context file. That
absence is recorded, not described as runtime proof. No public scope or additional
writer exception is introduced. All other vendor text stays byte-exact.

The existing non-init core writer assertion's target set grows, strengthening
that boundary. All 5,918 assertion/constraint statements remain; no allow is added.
Membership changes can affect other rule expressions, so no general effective
permission equivalence/monotonicity claim is made. The real compiler now exposes
old core-writer grants that conflict with the restricted ownership. Strict
diagnostics **60 -> 61**: the missing-owner diagnostic resolves, while newly
applicable writer assertions remain errors. They are not given public exceptions.

The positive closure finds **524 properties, zero unowned**, and 102 concrete
vendor-restricted properties including four original types. A separate real
Android17 strict-compiler fixture validates these ownership memberships before
and after, without -N. It does not validate runtime values, writers, AV/MLS or boot.
Full 1,243-project/15-patch source audits match. All images, active source,
assertions, cache hashes, signing material and the tablet remain unchanged.
