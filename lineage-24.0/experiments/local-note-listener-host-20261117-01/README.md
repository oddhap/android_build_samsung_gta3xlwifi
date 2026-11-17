# Backend applicability for local-network note-op observations

The actual snapshot21 tombstone identifies LocalNetEventHandler::GetRingbuf as
the next abort after successful netstats startup. The unconditional Android17
constructor creates the BPF-only observer even for the selected legacy backend.

Current upstream netd.c produces local-network note-op events only at kernel
version >=5.10. Linux4.4 does not provide this BPF observation stream. The existing
kernel/local-network permission implementation and permission-propagation flags
remain unchanged. Snapshot22 selects the ordinary listener for the BPF backend;
it represents the legacy stream as unavailable. No dummy FD, event, readiness,
permission success or kernel capability is fabricated.

The Java regression executes the actual constructor-selection block with explicit
service collaborators. It reproduces four original unsupported-listener failures
and passes16 combinations of SDK/backend/metrics/note-op flags. The ordinary
backend still constructs its original listener with the original flags/failures.
The C regression executes the actual current upstream packet-control body with
explicit BPF map/helper fixtures. All64 cases retain permission-denial decisions;
note-op production begins at5.10 and remains absent below5.10. These are host
control-flow tests, not real packet, BPF or device validation.

The full ROM build and packaged bytecode/APEX tests are required next. Current
SELinux assertions, compiled policy, kernel, vendor, crypto and recovery stay
unchanged. Real network tests and complete CE/FBE validation remain pending.
