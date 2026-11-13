# Published-owner statistics primitive API

All seven packet/app statistics controls use the existing four-state owner's
mutex and descriptor. They require startWithAccounting plus a complete published
policy; prepublication calls return EAGAIN and generic-only mode returns
EOPNOTSUPP before statistics I/O. Pure invalid arguments leave publication intact.
Kernel/protocol failure closes the lease and withdraws all four policy states.
Real loss/epochs are preserved, uncertain SWAP/EDIT is never blindly retried, and
ACK remains explicit/idempotent. The original owner implementation is unchanged;
new methods are appended. No descriptor or alternate writer is exposed.

This is a primitive interface, not an Android RPC or persistent polling protocol.
The caller must handle lost updates honestly, read/persist before ACK, coordinate
final UID polling and separately remove socket tags. Binder/session/reboot
recovery and actual Android caller routing remain required. No source/prebuilt
selection, global network readiness, hardware validation or flash candidate.
