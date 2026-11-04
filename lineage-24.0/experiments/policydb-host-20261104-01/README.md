# Complete policydb reader probe — active policy still reaches panic

This host test compiles the actual, unchanged Samsung policydb.c, avtab.c,
ebitmap.c, hashtab.c, symtab.c and conditional.c with their real structures and
headers. Three actual MLS validation helper bodies are extracted without edits.
Kernel allocation/flex-array/bit primitives, logging and panic are Linux host
fixtures. Unused NetLabel export/import code is excluded. This does not execute
security_load_policy publication, real SID/service/AVC enforcement, a kernel,
concurrency or a device. Source hashes and complete compile flags are recorded.

The original Android17 diagnostic binary (from the preceding strict-failed
experiment) reaches the actual cap9 rejection, then Samsung's policydb_read bad
label calls panic. The fixture terminates with code 77 to represent that
noreturn operation. This is **not** merely an EOPNOTSUPP returned to userspace.
Actual candidate compile commands do not define CONFIG_ALWAYS_ENFORCE. No macro
is added to hide the panic and no production guard/source is edited.

A separate, clearly marked non-installable data fixture differs by exactly one
byte: only capability bit9 is cleared. With unchanged production code, the full
1,485,206-byte structure parses with zero trailing bytes, 3,989 types, 108
classes, 82,238 rules, and the same 1,342 ioctl/95 nlmsg record counts as the
independent Android17 libsepol inspection. This isolates format parsing beyond
the active-feature rejection; it does **not** approve the original active policy.
Five truncated copies reach expected panic paths. ASan/UBSan remain enabled;
UBSan halts on an error. Normal teardown passes the host memory checks.

Early fixture preparation failed on host errno shadowing, kernel typedef/packed
macros, missing MLS dependencies and linker support. A preliminary host execution
also reported a signed-shift issue before the fixture included production's
-fno-strict-overflow semantics. The final fixture retains that actual flag and
-fno-strict-aliasing, uses LLD, and keeps all sanitizer instrumentation. Only
fixture setup changed; no kernel/policy failure was bypassed. Preliminary logs
remain hash-bound on the server. A fresh full 60,331-file audit matches the
recorded firmware candidate exactly after the test.

**ROM remains not flashable.** The active netlink capability gate, strict 322
neverallow diagnostic blocks, complete networking, module ABI and Android17
FBE/installer/rollback remain unresolved. Neither the cap9-off data fixture nor
the neverallow-disabled diagnostic input may become an installation policy.

Reproduce on the server with build.lock held and a new outside-source output:

```sh
python3 tools/test-whole-policydb.py \
  --kernel /srv/android/ports/lineage-24.0-arm64/kernel-firmware-20261104-01/src \
  --kernel-out /srv/android/ports/lineage-24.0-arm64/kernel-firmware-20261104-01/out \
  --policy /srv/android/artifacts/lineage-24.0-arm64/policy-binary-20261104-01/policy/init-runtime-diagnostic.policy \
  --inspection /srv/android/artifacts/lineage-24.0-arm64/policy-binary-20261104-01/binary-inspection.json \
  --output /srv/android/artifacts/lineage-24.0-arm64/NEW_UNIQUE_OUTPUT
```
