# Isolated FILE__MAP enforcement candidate

This candidate adds the actual file-mapping permission check before the existing
protection checks, using the old kernel PATH audit ABI. It inserts `map` into the
common file/socket permission prefix in the upstream position. Class numbers and
relative order of existing permission names are preserved; permission bit numbers
change. A complete kernel/header rebuild and module ABI review are required.

The host harness compiles actual mmap and credential/inode/file helper bodies,
with fixture AVC/audit objects under AddressSanitizer/UndefinedBehaviorSanitizer.
2,211,840 legacy and 2,211,840 candidate scenarios passed; 1,105,920 modern control
oracle scenarios passed. This checks permission requests, audit data and error
precedence, not whole-kernel, live enforcement, concurrency or module ABI.

The parent candidate still rejects active netlink policy capability 9. The
untracked parent `security/selinux/netlink.c` is excluded. No Image is promoted,
no active Android source/prebuilt is changed and no tablet access is performed.
The immutable staging lock describes this exact pre-build checkpoint. Subsequent
whole-kernel evidence must be recorded separately without rewriting that claim.


## Complete standalone compilation

`kernel-mmap-build-20261103-01` completed exit 0 on November 3 at 18:03:31 UTC.
The independent clone preserves the full four-file input/touch delta and applies
all five locked kernel experiments. Both 60,331-file tracked-source audits match;
the protected source remains unchanged. The one added qtaguid source header is
separately checked against its pre-build copy and staging hash. Full inventories
remain in the server artifact directory, locked by `evidence-lock.json`.

Image SHA256: `c7238c595b155083973aa073e1ed010a8f34ead6f278d7d54d051367f9a61cb8`.
The generated MAP constants all use bit 10; preserved config is byte-identical.
All 8,408 exported symbols/CRCs match the original Module.symvers. This does not
prove complete module ABI compatibility or module loading. Neither the original
AVC compile command nor the candidate AVC/hooks/services commands define Samsung
CONFIG_ALWAYS_ENFORCE. No enforcement setting was changed. Linux sanitized host
fixtures also pass the same counts as Mac. See `build-input-export-review.json`,
`host-mmap-linux.json` and `build.log`. No Image promotion or flash approval.
