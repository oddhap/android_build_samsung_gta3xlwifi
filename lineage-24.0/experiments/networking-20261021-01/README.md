# Experimental Android 16 legacy-networking layers — NOT a complete backend

These two patches are **not applied to the active Android source tree** and are
**not included in completed `full-platform-03`**. They do not produce a working network
stack or a flashable/test-ready ROM. `staging-lock.json` records the two exact
base revisions, patch checksums and hashes of 13 selected changed/new files.

## Implemented in isolation

- Actual Samsung `xt_qtaguid` detailed/device statistics parsing. Kernel-emitted
  headers are checked against `kernel/samsung/gta3xlwifi/net/netfilter/xt_qtaguid.c`.
  Invalid/inaccessible/empty-without-header input is an error, not zero traffic.
  Output is transactional; indexes, tags, UID/set ranges, full column counts,
  signed-jlong bounds, duplicates and aggregation overflow are checked.
- Native `libnetworkstats` entry points select real procfs accounting only for
  `ro.gta3xlwifi.legacy_networking=true`. Normal BPF paths remain unchanged.
- `NetworkStatsFactory` converts cumulative qtaguid snapshots to increments
  before the existing Android 16 tag-throttling, CLAT and VPN adjustment pipeline.
  It preserves cumulative uptime (subtract otherwise yields an interval), clears
  the baseline on UID removal, and does not construct/swap nonexistent BPF maps.
- A real DNS policy callback gate, with acquire/release publication, refusal to
  replace an established callback, explicit negative errors and malformed-result
  rejection. The private `ADnsHelper_setLegacyCallbackV2` extension deliberately
  differs from the old bool-returning callback ABI. No callback means unavailable,
  not success, including for core UIDs.
- The product-specific DNS resolver branch blocks on a missing callback or any
  nonzero/error result. OEM/experiment bypasses do not bypass this legacy policy.
  The ordinary non-legacy upstream behavior is unchanged.

## Evidence and limits

- **36 qtaguid parser/counter host cases PASS on Mac and Linux.** Actual kernel
  schema strings are extracted from the checked source, not invented fixtures.
- **35 DNS gate/resolver host cases PASS on Mac and Linux**, including a real
  registration/read race. Only Android property/experiment/network-metadata calls
  are fixtures; the gate header and extracted resolver function are production code.
- **12 stats and 8 DNS native object compilations PASS** with actual Soong-emitted
  flags, ARM64/ARM32, including CFI and the ARM64 APEX31 variant. Outputs and
  dependencies are redirected outside the active Android tree. This is **not
  full module linking, native ABI validation, or runtime execution**.
- Later, the **entire staged DNS helper** compiled/linked successfully as
  ARM64 CFI/APEX31 and ARM32 CFI shared libraries. Strict link checks are retained;
  existing versioned exports, SONAME and dependencies match baseline, with only
  the private V2 callback export added. This is dynamic symbol-surface validation,
  **not full header ABI or runtime**; the statistics module remains compile-only.
  Evidence: `reports/network-policy-20261021.json`.
- Four new Android Java regressions cover repeated snapshots, increments/uptime,
  UID removal and read failures. **They have not been compiled or executed.**
  Separately, the production `NetworkStatsFactory.java` now compiles with its
  real Soong SDK/compiler flags (exit 0), resolving siblings from the actual
  existing module JAR rather than Android API fixtures. This one-source check
  is not a complete module build or Android execution. Evidence:
  `reports/network-java-preflight-20261021.json`.
- Real Git forward/reverse replay succeeds in temporary selected-file trees.
  Forward `git apply --check` also PASSED against both actual locked VM projects,
  without changing them. Do not force-apply or change a running build's sources.
- VM evidence: `/srv/android/artifacts/lineage-23.2-arm64/` under
  `network-preflight-20261021-02/` and `dns-preflight-20261021-01/`. The first
  stats preflight failed on a missing `<cinttypes>` include; it is preserved,
  and the include was fixed without weakening compiler checks.

## Still required before these can be integrated as a complete network port

The authoritative Android 16 firewall backend and callback registration do not
exist yet. A separate `uid-policy-20261021-01` experiment now implements and
source-oracle-tests the 12-chain candidate query value, not actual kernel rules
or live owner publication. Do not gate the loaders off or claim BPF readiness
to conceal the missing backend.
Port all 12 chain semantics, per-user core-UID handling, separate metered
allow/user/admin rules, interface and VPN lockdown rules, local-network access
LPM/port/protocol rules, socket tagging/permissions/lifetime, real qtaguid quota
hooks and CLAT. Update Java readers/Connectivity APIs to query the real backend.
Account for packet-direction, loopback, DNS and TCP-control-packet differences;
the old Android 14 firewall must not simply be replayed unchanged.

Then link complete Netd/statistics modules and run Java tests, compare effective policy, validate real
networking/accounting/VPN/DNS on approved hardware, and repeat complete APEX/VINTF.
Strict actual-vendor SELinux validation still fails independently. FBE/recovery
and Android-14-only OTA guards remain unresolved and untouched.

Reproduce host checks using the local `work/network23` tree or the separate VM
`/srv/android/ports/lineage-23.2-arm64/network-work-20261020-01` tree:

```sh
python3 tools/test-qtaguid-stats.py STAGED_STATS_DIR XT_QTAGUID_C
python3 tools/test-legacy-dns-policy.py STAGED_DNS_HELPER_DIR STAGED_DNS_PROXY_CPP
python3 tools/compile-network-staging.py TOP STAGED_STATS_DIR NEW_OUTPUT
python3 tools/compile-network-staging.py --component dns TOP STAGED_DNS_HELPER_DIR NEW_OUTPUT
```
