# Selected Android17 local-network access contract

Read-only actual source expressions and Java key declarations, bound to the
selected READ_ONLY flag report and last full1243/17 Android source audit. No
packet enforcement implementation or readiness claim. Do not copy ordinary
owner-match exemptions into this independent protection.

With actual permission propagation enabled, only literal UIDs0 and1000 are
exempt. All other UIDs need AccessLocalNetwork bit0 or a permitting destination
classification/exception. Other core appIds and other-user system appIds are not
blanket exempt. Main LPM lookup defaults to allow; a false matched prefix requires
a true matching UID/interface/remote-host allowlist entry. Both keys occupy28
bytes including32-bit prefix length; compared payload is192 bits. Protocol is
native u16; remote port is network order; IPv4 uses mapped IPv6 addresses. Egress
queries destination address/port, ingress queries source address/port. The real
4.4 kernel uses direct lookup, not the5.10 socket-storage caching branch.

Attempt01 inline audit used the wrong prior-report success key and stopped before
writing a result. The reusable tool validates passed_source_contract_checks and
all prior input hashes. No flag, map, source or policy was changed to pass it.
Next work must implement the actual prefix tables, packet path and owner updates,
plus independent loopback enforcement and real metrics; these functions alone
are not an LNA backend.
