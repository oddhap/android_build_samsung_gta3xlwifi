# Isolated shared-lease packet statistics transport

Reads actual storage state, frozen UID/tag/counterset/interface rows and app UID
counters; exposes real loss and sequence data. CAS swap and explicit epoch ACK
use the existing owner descriptor and mutex. Reads retry EINTR with reset output
metadata. Swap and edits never blindly retry uncertain results. Protocol errors
close the lease and rearm the gate. ACK alone can retry its idempotent receipt.
Callers must persist/read data before ACK and explicitly recover actual state
after an uncertain swap. UID statistics deletion does not delete socket tags.

Feature bit 12 proves storage only. No full poll, installed packet hooks,
production service control routing, lifecycle coordinator or networking readiness
is provided. All old lease implementation bodies remain unchanged; new methods
are appended. No production source/prebuilt/policy selection or flash candidate.
