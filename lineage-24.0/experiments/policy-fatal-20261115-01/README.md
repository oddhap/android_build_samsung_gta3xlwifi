# Held owner quarantine and daemon recovery

Inactive delta over stats-lifecycle-20261115-01. No selected source, policy,
prebuilt or device state changes. No installation candidate exists.

An unrecoverable native owner quarantine now dispatches a process-lifetime
startup handler only after withdrawing publication, stopping accounting, and
closing the real private lease. Controllers registers the handler before owner
creation. The production handler terminates netd with exit1; the existing init
netd onrestart actions restart zygote/zygote_secondary. A fresh daemon must pass
held-provider admission and a fresh framework must supply its complete policy.
This does not claim that every Java/session failure already has automatic recovery.
Normal stop, successful suspend/client withdrawal, and rejected input do not
invoke this handler. The free callback API does not change owner object layout.

Validation: actual Controllers/owner/lease/service compilation, CFI netd and OEM
DSO links, eleven ordinal-compatible AIDL methods, four Java sources against
original Connectivity classpaths, ARM32/64 UAPI layouts, and1243-project/17-patch
before/after audits pass (policy-fatal-native-20261115-01).

The host fixture replays the previous26286 checks and passes26321 total assertions,
including closure-before-callback, real I/O/protocol quarantine, immutable handler
registration, normal stop/suspend, and invalid-input rejection. The actual
Controllers termination handler is separately compiled with a throwing process
boundary fixture. No host/device service is restarted. Hardware recovery and
whole-product Soong composition remain unvalidated.
