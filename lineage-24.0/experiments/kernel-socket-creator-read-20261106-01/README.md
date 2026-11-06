# Kernel-only full-socket creator reader

Adds a GPL reader for immutable inet creator metadata. Caller protects the socket
lifetime. Null/unknown/unmarked/non-inet/timewait/request sockets return no result,
preserving caller output. Successful reads preserve the literal captured UID,
including0,65534 andUINTMAX, without inode/current UID substitution. No request
conversion or socket lookup is hidden in this getter. A lookup caller must resolve
a request to its listener while holding the original lookup reference, read the
listener, then release the original reference. The borrowed listener must not be
released as if it were an independently obtained lookup reference.

41 cases and960 identity/lifecycle regressions pass with fatal UBSan. The actual
kernel full-socket predicate and TCP-state header are used, with object/credential
fixtures. Cases cover both inet families and all TCP states1..12, literal UID
boundaries, absent markers, wrong family, null arguments and output preservation.
Exact initial/create/clone/source contracts from the prerequisite remain checked.
No actual sockets, permission checks, hooks, BPF maps or readiness execute.

Full kernel/modules build exits0. Image SHA256:
`dfd8e7fed78628a6254d61bf619b6afa8c76f8edf296214979a5340c386d4188`.
Original config fac42... is retained; rebuilt Gator118/KUTF43 imports match kernel
exports. Complete60338 candidate/60331 protected and Android1243/17 source audits
pass before/after. Both creator init/read symbols survive in the actual kernel.
The exact two-file incremental patch retains the prerequisite's internal layout;
no new UAPI, struct-layout, ownership, accounting or packet policy change occurs.
Original/prebuilt module compatibility is still not established or promoted.
