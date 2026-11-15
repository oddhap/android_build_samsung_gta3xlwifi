# Genuine held private boot preflight

This inactive delta selects a separate init action only for the gta3xlwifi
legacy_networking Soong variable. Its current value/type is bound as string true;
init_rc is a current configurable Soong base property. Other products retain the
unchanged stock netbpfload.rc. Full Soong graph selection is still pending.

The private action synchronously executes stock-critical netd1shot and starts
netd. It neither runs BPF loaders nor sets/waits for a fabricated BPF-loaded
property. The private netd1shot branch executes actual Controllers initialization
and held-provider verification, including real kernel ABI/producers, tag transport
and registration into the actual resolver DSO. It then closes transport and the
owner lease while the traffic barrier remains held. It starts no Netlink/Binder
listeners and never publishes framework policy. The normal daemon must repeat
its own actual checks; preflight success is not networking Ready. The stock
oneshot branch and stock critical failure/restart behavior remain unchanged.

Actual current main/provider CFI compilation and full netd linking pass, as do
host_init_verifier and complete1243-project/17-patch before/after audits. Host
startup fixtures pass38 cases for private and stock paths with staged faults.
Actual owner/DNS regressions pass26050 checks, including distinct preflight and
daemon owners using the SAME retained rule/kernel fixtures without reset between
lifetimes. The second owner verifies HOLD and publishes its own fresh complete
policy. Controller/syscall/rule effects are host fixtures, not device execution.

Prerequisite: dns-owner-20261115-01. Complete source/Soong/APEX integration,
statistics/events/CLAT, strict policy source integration, real full build and
installation checks remain. Selected source and prebuilts are unchanged. This
is not a flash candidate or hardware boot proof.
