# Android 17 netlink extended-permission candidate

**Incomplete, policy-load guarded, not in Android TOP or any Image/prebuilt.**
This patch is relative to a synthetic partial tree containing the exact existing
qtaguid-persistent02 + policy-reader + combined FunctionFS/NNP experiment graph.
It is not a patch against the original kernel commit or a normal apply-port
snapshot. The staging lock records original revision, prerequisites and every
changed file's before/after digest. Reverse replay passes in the partial tree.

The actual built Android 17 policy enables `netlink_xperm` (capability bit 9).
The prior reader correctly rejects that capability. Removing its rejection alone
would advertise enforcement that the old kernel does not implement. The guard
remains present while this isolated enforcement candidate is developed.

The candidate separates ioctl/netlink base permissions in driver coverage and
AVC decision keys/copies, implements kind-3 computation, appends `nlmsg` to four
netlink classes, and routes their message types through the extended-permission
check and an audit field. Existing permission positions and legacy lookup tables
are retained. Old ioctl audit-only driver-length behavior is preserved with cap9
off. The reference is pinned Android common `android17-6.18`, commit
`d9a614feddce2e8e68767df1d3421305d26a965b`; see the reference lock.

`tools/test-netlink-xperm24.py` extracts the actual candidate helper bodies and
compares them to immutable modern and pre-candidate legacy implementations plus
an independent single-rule bitmap expectation. Each of two configurations passes
4,784,128 helper scenarios and 807,936 AVC fixture scenarios with ASan/UBSan and
warnings treated as errors. One build uses Samsung's `CONFIG_ALWAYS_ENFORCE`.
Checks include all 65,536 command encodings, cached/missed decisions, separate
base namespaces with the same driver, copies, allow/auditallow/dontaudit,
conditional enabled flags, missing namespace/driver denial, permissive-domain
behavior, enforcement and audit-error propagation.

The list, cache population, RCU locks, policy lookup and audit backend are host
fixtures. No actual concurrent cache, allocator, full kernel, policy loading,
packet transport, enforcing Android runtime or hardware is validated. There is
no new Image. `host-helper-report.json` identifies exact tested file bytes.

Before considering guard removal: bind permission-mode and AVC decisions to a
consistent policy generation during reload; test the actual multipart/malformed
netlink path, all lookup classes, audit and allocation failures; complete mapping
and enforcement of other active capabilities, including extended socket classes;
and build/link and review a full independently cloned kernel with its complete
four-file input/touch prerequisites. Do not stack NNP-only onto combined FFS/NNP.
Policy reload must not mix the legacy permission mask and netlink xperm mode.
Neither two unbound capability reads nor merely parsing kind 3 proves this.

Reproduce using explicit paths to the candidate, pinned reference and preserved
pre-candidate partial tree:

```sh
python3 tools/test-netlink-xperm24.py --kernel CANDIDATE \
  --reference ANDROID17_REFERENCE --legacy PRE_CANDIDATE --report REPORT.json
```

Strict actual-vendor policy still fails independently. Complete networking,
HAL/APEX/zygote/FBE/recovery/OTA and rollback validation remain outstanding.
No original image, LineageOS 21, TWRP, signing material or tablet data is changed.
