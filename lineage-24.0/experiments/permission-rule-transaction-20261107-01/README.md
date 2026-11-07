# Combined UID rules and permission-image transaction

New explicit replaceWithPermissions combines both-family checked UID chains with
the real shared UID permission image under one exclusive held lease and mutex.
Validates all inputs and prepares caches before I/O. Reads both actual before-rule
images and permission revision/value, and checks them against any previous full
commit to detect drift. First complete publication always requires an explicit
full image. Once combined mode begins, plain replace cannot omit permissions.

Rule updates/readbacks and all six guard checks complete BEFORE permission SET.
No firewall I/O occurs after SET: NoInternet can legitimately deny even root's
new control sockets. Permission write/readback and held state must verify, then
the gate releases. Preallocated caches publish only after successful release.
A rule failure before SET restores both before-images, verifies the unchanged
permission revision/value, and may resume only a previous complete combined
commit. Initial/unpublished images never justify releasing the gate. Any SET,
readback or release uncertainty closes the lease and quarantines the session;
no guessed old state or unsafe firewall rollback is attempted after ambiguous SET.

Host55 cases passed with actual parser/lease/transaction code, fatal UBSan and
syscall/rule fixtures. The fixture prohibits any firewall I/O after SET until
another HOLD, including a UID0 NoInternet image. Both families, committed/uncommitted
write failures, initial/later rollback, malformed input, image/rule drift, failed
restoration and ambiguous SET/readback/release are covered. Original90 dual-stack
regressions and90 transport cases also pass. Attempt01 failed a fixture indentation
warning only; braces corrected, production source unchanged.

Actual three-source Android17 ARM64 CFI compile/link-to-object and complete1243/
17 before/after source audits passed. Full netd module/service integration,
Java/native authoritative publication, packet LNA/loopback/metrics/VPN/IIF/DNS/
CLAT/startup and all final image/FBE/installer checks remain. No readiness or
hardware validation is claimed. These patches are not in active Android inputs.
