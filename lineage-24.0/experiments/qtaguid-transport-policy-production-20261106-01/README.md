# Minimal netd qtaguid transport policy — isolated

Current production/debug policy denies netd control access. This explicit proposal
adds only the required write-only control access, device open/read/getattr/ioctl,
private ioctl0x7151, and read-only access to three specifically labeled sysfs files.
It retains the complete original platform prefix and every vendor input byte;
no legacy symbol is renamed and no assertion/constraint is removed.

Actual strict compilation passes with zero diagnostic blocks for both profiles.
The respective5918 production and5881 debug assertion/constraint records are
unchanged from their baselines. Each compiled policy passes22 concrete permission
queries with no permissive domains: netd gets only the intended access; control
read, sysfs write and untrusted-app control/device ioctl remain denied. Init's
existing read/getattr access and write denial remain intact.

libsepol resolves all three actual sysfs genfs paths to the new private type.
An independent strict-compiler contradiction probe for ioctl7151 fails exactly
as expected, proving the grant; probes denying7150 and7152 compile successfully,
proving those neighboring commands are not allowed. Probe assertions are added
only to temporary test inputs, never removed from real inputs or selected into
images. Initial harness errors are preserved separately.

The transport session, caller authorization, packet policy, backend lifecycle
and truthful startup are separate requirements. The reviewed .te/genfs snippets
are source proposals, not active device policy or an automatically chosen image
input. No vendor/kernel image or device data was changed.
