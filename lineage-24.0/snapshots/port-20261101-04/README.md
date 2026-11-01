# Policy30 source backport — snapshot 04

1,243 locked projects, 15 exact source patches, full source audit PASS.
Device revision 236957f selects actual policy30 mapping modules. Existing
13 platform patch hunks remain, with two additional project changes:

- system/sepolicy restores 413 verbatim frozen API/private compatibility files
  from LineageOS 23.2 commit 885cc500f6078a766d1f6def5ce4c06c55841773, and
  adds 11 policy30 modules following current Android 17 policy31 generators.
- build/make adds policy30 to framework compatibility versions for gta3xlwifi
  only. It does not alter the current platform policy version or shipping API.

The import hash manifest is in experiments/policy30-20261101. The frozen API
is reference/test data; no existing current-platform allow/neverallow rule is
changed. Existing Android 17 mapping composition produces the 30.0 runtime
metadata. A dedicated build/compatibility test is pending; this snapshot is
not a strict vendor-policy pass or installation candidate. The isolated
strict actual-vendor candidate still reports 407 neverallow failures.

Snapshot03 capture was incomplete due to blank-at-EOF warnings in unchanged
upstream frozen files. Snapshot04 capture used per-command
core.whitespace=-blank-at-eof to preserve those bytes. All source revision,
patch hash, exact diff, untracked-source and alternate checks remain enforced.
