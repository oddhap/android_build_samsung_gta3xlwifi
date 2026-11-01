# Android 17 isolated networking/kernel migration

This is the combined final experiment graph rebased against revision-bound
LineageOS 24 / Android 17 inputs. It is not applied to Android TOP, linked into
netd, installed as a kernel, or a complete working network backend.

Four combined patches cover Connectivity, DnsResolver, netd and the unchanged
Samsung kernel baseline. `source-lock.json` records the exact base and hash.
`provenance.json` records partial-source replay; it is not a full-checkout audit.

Android 17-specific changes:

- DNS resolver now directly links `ADnsHelper_*`, rather than testing an optional
  dynamic function pointer. The legacy resolver calls that direct API and blocks
  on every nonzero result, including missing-owner/negative errno errors.
- The DNS helper already includes properties and uses a different SDK-init path;
  the legacy owner-readiness gate is placed before the unchanged upstream path.
- The old version-script map has been removed upstream. No obsolete map is
  reintroduced. Android 17 provides `libdns_helper`; actual module/ABI linkage and
  callback-owner lifetime remain unvalidated.
- Native stats, cumulative Java deltas and their four Java regressions replay
  against Android 17. The Java regression suite still needs an Android module
  compile/run; a native UID oracle test is a separate evidence level.
- Kernel qtaguid-persistent02 + policy-reader + combined NNP02/FunctionFS replay
  together against the same exact Samsung base. The touch/input delta remains
  required for any new independent kernel build. No new Image is promoted.

Host checks extract real production functions but simulate maps, callbacks,
credentials, locks and kernel primitives. They cannot certify packet filtering,
whole-policy enforcement, Android services or hardware operation. Native UID
comparisons use unmodified Android 17 DNS sources, real chain definitions and
framework constants. Read the current host report for actual execution results.

Still required: a real authoritative netd owner, both-family rule transactions,
readback/rollback/restarts, permissions, tag authorization, interface/VPN/LNA,
quotas/counter sets/UID deletion/CLAT, Java module integration and live accounting.
The callback must remain unregistered until the backend is actually ready.
