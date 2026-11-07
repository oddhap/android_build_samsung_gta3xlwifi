# Selected permission/metrics requirements

Actual CP2A cache and generated Java in both common/APEX31 variants agree:
permission_map_uid_migration and loopback_access_metrics are READ_ONLY ENABLED;
collect_beta_metrics is READ_ONLY DISABLED. The existing platform source contract
is rebound by every input hash: local-network and loopback permission flags stay
READ_ONLY ENABLED. Source-derived permission propagation is enabled for Android17.
No flag/cache/property/policy input is changed; full1243/17 audits pass before/after.

Consequences for the unfinished backend: implement real dynamic NoInternet at
socket creation, real LNA and cross-profile loopback checks, and a genuine loopback
metrics producer/consumer. Do not mark metrics optional/off or supply an empty
fake stream. Static inet group protection is not the entire dynamic permission
contract. Beta local-network metrics are disabled in this selected build.
This is source/generated-code evidence, not runtime or backend readiness proof.
Attempt01 failed whitespace in the verifier's comma-separated trace paths; path
trimming fixed the tool only. Both attempts retain complete source audits/logs.
