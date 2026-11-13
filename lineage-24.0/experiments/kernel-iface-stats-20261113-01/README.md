# Real interface counter primitive

An isolated delta on `kernel-ingress-context-20261113-01` implements the Android17
interface XT accounting arithmetic, a bounded global store and an authenticated,
non-consuming snapshot. It does not install producer rules, wire egress DROP UNDO,
implement UID/tag accounting or make the ROM ready for testing.

The 1000-entry global store uses preallocated hash chains and a BH-safe spinlock.
Packet updates allocate nothing. Counter arithmetic matches the actual pinned
Android17 interface programs' explicit KVER_4_9 argument, including segmentation
estimation and unsigned UNDO. This is an implementation choice in those programs,
not a changed kernel version. Real overflow attempts increment a saturating loss
counter; the update sequence is opaque modulo 2^64. Existing qtaguid counters and
vendor proc interfaces remain unchanged.

A private XT match accepts ingress/raw/PRE_ROUTING and egress/mangle/POST_ROUTING
only, with initial-user-namespace checks. The egress CLAT exception uses the raw
full socket UID 1000 plus actual tag UID 1029; it does not confuse this condition
with the broader egress-policy CLAT exemption. The feature bit reports successful
match registration only. Registration alone does not mean accounting is active.

GET 0xc020675a passes through the existing privileged file/TGID-owned lease
check. A reader supplies capacity 1000 in one call for a consistent snapshot;
metadata-only probes are allowed but are not a revision reservation. User copies,
sorting and allocation occur outside the spinlock. Allocation/copy faults consume
nothing. Records are sorted and reserved bytes are zero. No reset/injection API
is introduced. The public UAPI fixes entry 40, transfer 32 and match 8 bytes.

The actual module and XT functions pass 49 host checks and 786432 comparisons
against the pinned Android17 DEFINE_UPDATE_STATS macro. Tests include capacity,
unsigned wrap/UNDO, loss, copy/metadata faults, real pthread update/snapshot
concurrency, registration failure, CLAT/tag cases and allowed rule contexts.
Kernel, skb, tag lookup and user-copy effects in these tests are fixtures.

Full fresh build02 passes Image, all configured modules, Gator 118/KUTF 43 version
bindings, unchanged configuration, 60360 candidate and 60331 protected source
hashes, and 1243 Android projects/17 exact patches before and after. Image SHA256:
`7f21bde9f142490a58bd9f422ddf2542a681b4f6fa735346c396fe5320427f34`.
Configuration remains `fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea`.
See `kernel-iface-stats-build-20261113-02`. Build01 compiled Image, then stopped
because its symbol-filter regular expression accidentally concatenated two
alternatives. The real symbols existed; the filter was fixed and the entire
fresh build repeated. Its failed evidence is retained separately.

The build runner uses the Samsung drivers' required Android11 build defines,
without changing the userspace Android17 target. Selected Android kernel/vendor/
DTBO, original source/output, firmware, rollback inputs and keys are untouched.
No binary or signing material is published. Runtime and performance remain
unvalidated. Producer rules and corresponding egress-policy UNDO must be reviewed
and activated together before interface accounting can be claimed operational.
