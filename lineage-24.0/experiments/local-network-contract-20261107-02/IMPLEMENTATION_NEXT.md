# Next implementation boundary: real local-network packet policy

Design candidate only. Nothing described here is selected or implemented yet.
The actual A17 source bound in report.json declares1000 entries for each of the
local_net_access_map and local_net_uid_host_allowlist_map. Its host-exception
comment says all current entries use the maximum192-bit payload prefix length;
the main map genuinely uses longest-prefix matching. Capacity and packet-time
cost must be assessed against those actual limits, not guessed small tables.

A possible way to use the existing verified rule/image transaction without new
permission-store ioctls is a checked LNA rule compiler plus private packet-key
netfilter matches. It needs an explicit review/implementation, not an activation
of the current incomplete backend:

1. A private match obtains the normalized raw socket UID and consults the real
   shared seven-bit permission image. Only literal0/1000 or AccessLocalNetwork
   bypass LNA denial. Preserve the existing separate ordinary/core behavior.
2. A second private match builds the actual main or UID-host query payload from
   parsed packet fields and the current interface index. Match a canonical byte
   prefix, not interface names or numeric address approximations. Main payload
   is native-u32 ifindex,16 address bytes,native-u16 protocol,network-u16 port.
   Host payload is native-u32 UID,native-u32 ifindex,16 address bytes. Prefix bits
   compare the in-memory byte sequence from MSB of the first byte. IPv4 addresses
   are mapped IPv6. Route changes must use current skb_dst device on OUTPUT.
3. Reuse/extract the reviewed exact A17 packet parser, including its actual
   extension-header/error behavior; get remote destination on egress and source
   on ingress. A17 skips the independent LNA block if parsing fails. Unrelated
   ordinary ESP/core exemptions must not bypass this independent rule stage.
4. Emit main entries from longest to shortest prefix. True returns; false goes
   to a bounded UID-host exception chain, where a matching true exception returns
   and absent/false drops. Main no-match returns. Distinct typed goto/call targets
   must preserve RETURN semantics in the full parent pipeline; verify both
   families' exact canonical readback. Do not accept raw arbitrary rule strings.
5. Carry the LNA values, compiled rules and permission bits through the same sole
   serialized owner. All rules verify before permission SET, then readback and
   release. Include all chains in drift checks and before-images. Kernel/rule
   errors must withdraw publication and retain the real gate, never default to
   successful empty tables. Parent attachments must actually call this stage.
6. Verified system-DNS tag exception belongs in the full pipeline. No fabricated
   tag/UID metadata or blanket DNS/process exemption. Independent loopback and
   real loopback metrics remain mandatory; beta LNA note-op metrics being disabled
   in this selected release does not disable loopback metrics.

Required proof: actual A17 expression/key serialization oracle; prefix precedence,
endianness, host exception, direction, literal-vs-multiuser core and permission
cases; actual kernel body/parser fixtures; full fresh kernel/modules/config/source
checks and actual complete xtables registration/link. Then actual netd CFI/module
integration, strict unchanged assertions, parent/callback startup and packet/device
tests. Rule-walk cost at1000 entries per table may favor a real kernel prefix store;
measure before choosing. Neither design alternative itself establishes readiness.
