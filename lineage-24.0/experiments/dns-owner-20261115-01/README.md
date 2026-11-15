# DNS decisions from the sole native policy owner

This inactive three-project delta binds the actual resolver helper to the same
SocketPolicyProjection commit/mutex as packet policy. The helper is static inside
libnetd_resolv: netd calls one append-only exported resolver wrapper, never a
second helper copy. Registration follows both held-owner verifications and real
socket-tag transport startup, before DNS/Netlink/Binder listeners. Registration
only establishes a callback; unpublished/withdrawn policy returns an error.

The real DNS helper preserves the stock BPF branch. Private queries read the
current committed policy and propagate unavailable-policy errors. DNS fast-fail
preserves upstream OEM/experiment controls and treats private negative results as
blocked when that fast-fail path is enabled. Actual packet enforcement remains
mandatory. Invalid callback responses fail with EPROTO; replacing an installed
callback is rejected. No BPF-loaded property or networking Ready is invented.

Actual original CFI flags compile the changed owner/provider/helper/proxy and
fully link netd and libnetd_resolv. The original resolver exports and DSO NEEDED
lists remain unchanged, with one append-only private export. Both complete
1243-project/17-patch audits pass. The owner/DNS UBSan fixture passes26040 checks,
including200 concurrent reads during policy updates, unpublished/withdrawn/faulted
policy, metered/core/UID decisions and callback protocol errors. The actual
provider/main fragment passes23 startup cases including DNS-registration failure,
which closes transport and stops the owner before listeners. Dependencies are
explicit host fixtures; these results are not Android/device execution.

Prerequisite: policy-client-20261114-01 and its recorded native dependencies.
The new header is staged under Connectivity's exported DNS-helper include path;
actual Soong dependency/source composition remains required. Selected Android
source, prebuilts, vendor and strict policy inputs are not promoted or replaced.
Stats/events/CLAT, private boot admission/oneshot, source composition, full build
and install validation remain. This is not a flash candidate.
