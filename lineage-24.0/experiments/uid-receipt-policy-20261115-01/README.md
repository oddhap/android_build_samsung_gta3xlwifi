# Strict policy for the real UID cleanup receipt ioctl

Inactive metadata delta over the explicitly selected iface-names-policy
production/debug inputs. The sole new grant is netd ioctl0x6763 on the existing
private root-owned character-device type. All previous platform/vendor inputs,
assertions/constraints and legacy vendor symbol identities are preserved.
No automatic policy/image input replacement or device policy loading occurs.

Both production and debug pass the actual Android17 strict compiler with
neverallow checking enabled, no-N and no permissive domains. The inventories
retain5918 production and5881 debug assertion/constraint records exactly.
Each profile passes17 actual binary-policy access checks, real genfs/device
label checks,20 enabled-ioctl contradiction probes and two denied-neighbor
probes (674f and6764). System_server and apps still cannot open/ioctl this device;
netd still cannot write its char/sysfs files. Only the existing authenticated
native owner may use the new receipt control operation.

The common job uid-receipt-policy-20261115-01 exits0 and1243-project/17-patch
before/after audits pass. Reports remain under the production/debug evidence
folders. The source .te is included; compiled binary policies and unmodified
vendor CIL inputs are not published here. Kernel0xc0406763 maps to low160x6763.

This is an explicit ioctl extension to an already reviewed platform-policy port;
it does not bypass neverallows, replace old policy inputs automatically, fake
BPF/networking readiness or approve source/prebuilt/image selection. Hardware,
complete NSS recovery/lifecycle and flash packaging remain unvalidated.
