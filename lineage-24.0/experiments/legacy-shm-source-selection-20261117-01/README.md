# Retained vendor shared-memory compatibility

Snapshot17 establishes authenticated Android17 ADB before framework startup,
with SELinux Enforcing and a correctly labeled ION node. Its live logs identify
BootAnimation ION read denials and a fatal SystemServer ApplicationSharedMemory
allocation failure on the libcutils ashmem node. Raw device logs remain private.

Snapshot18 adds bootanim to the concrete legacy graphics clients and restores
the upstream `system/sepolicy/vendor/ashmem/ashmem_allow.te` open permission for
the libcutils API node. The actual Samsung vendor API is28, within that upstream
rule's old-vendor scope. The direct ashmem-device restriction remains enforced.
The kernel lacks the memfd_class capability file; memfd and vendor API properties
are retained as observed.

The actual source policy build and strict Samsung vendor link pass. All5,881
assertion/constraint records are retained, all20 context checks pass, and93
actual compiled-policy queries verify the legacy API interface, the observed
ION clients, and continued direct-device/generic-device denials. A fresh vendor
cache changes seven explicit metadata paths while preserving every other entry
and its security metadata. Original and previous vendor inputs are retained.

Snapshot19 binds the OTA guard to this exact reviewed cache before full ROM
packaging. Physical Android17 boot, complete graphics/network functionality and
CE/FBE validation remain pending the next installation.
