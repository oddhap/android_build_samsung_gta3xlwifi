# Android 16 UID firewall-policy value — isolated experiment

**Not applied to the Android tree or included in `full-platform-03`. Not a
kernel firewall, callback owner, readiness signal or test ROM.**

Two new Netd source files, one hash-locked patch against the exact `system/netd`
revision in `staging-lock.json`. Forward/reverse replay passes in a temporary Git
tree. Read-only `git apply --check` also passes against the actual locked VM
project; no application was performed.

## Implemented

`server/Gta3xlwifiUidPolicy.{h,cpp}` is a candidate policy value for a future
Netd owner. It implements all 12 chain IDs, independent enabled/membership state,
allowlist/denylist/default semantics, replacement preserving unrelated chains,
UID removal, Data Saver and exact blocked-reason/metered filtering queries.

- System exemptions use **appId = uid % 100000**, including secondary users.
- Metered allow does not override user/admin deny.
- Metered membership currently ignores configuration enable bits, matching A16.
- Invalid chain/rule/negative UID/null output is rejected. Replacements validate
  the entire UID list before mutation; invalid entries do not partially update
  the candidate. This validation is intentionally stricter than some upstream
  invalid-input paths; source comparisons cover valid Android UID inputs.
- INTERNET permissions, interface/VPN, local-network packet policy, quotas and
  socket-tag permission checks are **separate**, not silently folded into the
  framework/DNS chain query (as parts of the old helper had done).

Mutator success means **only that this candidate value changed**. There is no
kernel transaction or readiness method here. A caller must not publish a value
or register the V2 DNS callback until actual kernel state is committed and all
backend prerequisites are satisfied. No `Android.bp`/Netd service wiring is
included in this experiment.

## Evidence

`tools/test-uid-policy.py STAGED_SERVER ORIGINAL_CONNECTIVITY --sanitize`:

- **192 API/state safety checks**, plus source-bound chain/match/reason/rule
  constant assertions; PASS on Mac and Linux with ASan/UBSan.
- **526,888 comparisons** against the unmodified extracted A16 native DNS query,
  including every enabled/membership combination of the nine non-metered chains,
  metered combinations, secondary-user boundaries and signed UID maximum.
- Linux additionally passes **8,336 reason/decision comparisons** against the
  extracted A16 Java `BpfNetMapsUtils` methods, using the real JDK 21 executable.
  BPF map storage and the fixed A16 SDK environment are fixtures. This is not an
  Android Java module/JUnit build or runtime test.
- The production C++ source compiles with the actual `libnetd_server` ARM64 CFI
  flags. Netd is a primary-ABI daemon here. This remains **one object compile**,
  not a linked Netd module or live firewall test.

See `reports/network-policy-20261021.json` for hashes and VM evidence.

Separately, the **existing** `networking-20261021-01` DNS helper sources now
compile and link as complete ARM64 CFI/APEX31 and ARM32 CFI shared libraries
outside TOP. Strict undefined-symbol/version/fatal-warning flags are preserved;
old versioned exports, SONAME and dependencies are unchanged, with only the
private `ADnsHelper_setLegacyCallbackV2` export added. This checks dynamic symbol
surface, **not complete header ABI or Android execution**. No callback owner or
kernel readiness has thereby been implemented.

## Next actual backend work

Implement Netd ownership, kernel rule installation/readback and failure/rollback
handling before policy publication. Preserve both-family consistency and Netd
restart semantics. Implement interface/VPN/LNA, permission/tag/lifetime, quota,
CLAT, Java/API readers and real loader/readiness integration. Never replay the
old nine-chain helper mechanically: its blanket loopback exemptions and primary-
user-only core handling are not A16 packet semantics. The current kernel's
qtaguid tagging retains a socket reference; process-device cleanup is not proof
of automatic per-socket cleanup for a long-lived Netd tagging other apps' FDs.
That lifecycle needs a real solution/test, not an assumed success.

**October 22 update:** `reports/qtaguid-socket-20261022.json` now proves the
existing final-close hook in the actual preserved vmlinux/exact Image. No patch
is needed for that hook. Real device execution is still unproven, and Netd
restart/session cleanup losing tags of live app sockets remains a separate
concrete problem; see the new qtaguid transport experiment.
