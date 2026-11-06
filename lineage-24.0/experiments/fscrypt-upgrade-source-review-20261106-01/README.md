# Key-blob upgrade/rollback source review

This report records actual Android17 source contracts, not hardware behavior.
KeyStorage can replace an upgraded key blob and request deletion of the old key;
checkpointing controls deferral. The vendor Keymaster4 HAL specifies version/patch
binding and upgrade rules. Do not infer Samsung hardware behavior or installed
TWRP compatibility from that specification alone. The ignored-upgradedBlob
exception documented for TAG_STORAGE_KEY conversion does not apply to this
port's raw v1 session-keyring fallback.

No key file or key material was read, no operation/upgrade/delete was invoked,
and no source or recovery was modified. Android17 TEE, decryption, installer and
rollback remain validation gates. Do not fake OS/patch versions, silently remove
upgrade/security checks, or merely extend the old Android14 installer guard.
