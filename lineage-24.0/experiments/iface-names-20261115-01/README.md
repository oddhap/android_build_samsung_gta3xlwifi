# Kernel-lifetime interface-name history and authenticated transport

Five exact-baseline kernel files add a real init_net netdevice notifier and
bounded1000-row ifindex/name history. Existing devices are replayed, rename/index
reuse updates the current name and unregister retains it. Loss/sequence are real;
the capability requires successful notifier registration and the existing XT
producer. Request0xc0206762 (low16 0x6762), capability1<<16, entry20/transfer32 bytes.
No BPF object/loaded flag or networking Ready is fabricated.

Actual full isolated ARM64 Image, all modules and Gator/KUTF ABI checks pass
(118/43 imported versions), with real notifier registration relocations/initcall.
Full60366 candidate/60366 baseline/60331 protected source audits and1243/17 Android
audits pass. Image SHA256:
8f18140564f9fc1d1a875163f722a59f9130f678b38e9b4274b1978474d17dac.
Configuration remains fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea.
Fresh output, MODULE_SIG disabled; no signing material/old output copied.
Registry host tests pass4061 checks/1000 concurrent snapshots, including replay,
removal, reuse, namespace filtering, capacity/loss and copy faults.

Actual Lease/owner reads require the capability and validate complete responses.
Existing readStats kind4 emits sequence/loss/count and rows of ifindex plus four
network-word groups of name[16]. No new AIDL ordinal. Product ASCII interface
names are supported explicitly; other bytes fail instead of becoming invented
replacement names. The immutable Java decoder uses the captured real session
without Java policy/client locks. Missing old-kernel support or malformed responses
withdraw the owner, with no map/proc fallback.

Actual AIDL compatibility/11 ordinals, CFI Lease/owner/service/full netd/OEM links,
all four Java sources, actual ARM32/64 UAPI and1243/17 audits pass. Owner/service
host checks pass26286, including101 new name checks and full1000-row tables.
Java passes1924 checks, replaying1467 client cases and decoding actual C++ service
name words, bounds, immutability and failures. Binder/ioctl/notifier effects remain
explicit fixtures, not Android IPC/device execution.

Both production/debug strict policy variants append ONLY ioctl0x6762. All5918/5881
assertion/constraint records and legacy vendor symbol identities remain. Strict
compilation passes without neverallow bypass/permissive domains. Each profile
passes17 real permission queries, device/genfs labels and strict contradiction
probes for19 enabled ioctls plus two denied neighbors. Staged input is never
selected automatically.

Prerequisites are in staging-lock.json. Selected source, Image/latest21-MTP vendor/
DTBO/policy remain unchanged. Actual factory/service/TrafficStats consumers and
complete serializer, durable lifecycle/metadata updates, events/CLAT, Soong/APEX/
strict policy source composition, full ROM and installation checks remain. No
flash candidate exists.
