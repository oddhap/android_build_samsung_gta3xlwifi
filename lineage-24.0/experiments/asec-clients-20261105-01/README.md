# Bound old ASEC access to legacy app clients

Two old vendor allows used a complement of today's live appdomain and therefore
included new sandbox/isolated clients. This proposal retains that original source
attribute unchanged and intersects it with a new positive legacy client set.
The set combines ABI-visible app types from the actually compiled frozen API30
policy and the vendor-private appdomain list, for 43 positive client symbols.
Unmapped frozen private types mediaprovider_app, permissioncontroller_app and
vzwomatrigger_app are recorded and not imported into vendor ABI. Complete runtime
client coverage is not established; current platform grants remain unchanged.

Both target/class/permission sets remain identical. The new source is a direct
intersection with the old source; no old declaration/expression or concrete type
universe changes. The comparison tool independently checks that structural subset
witness, all fresh-attribute definitions, and complete assertion inventories.
This proves grant narrowing, not functional equivalence or runtime behavior.

Strict diagnostics **62 -> 60**, no new diagnostic assertion identity. All 5,918
assertion/constraint records remain. Full before/after audits match: 1,243 projects,
15 exact patches; every other compiler input/hash is unchanged. Secilc255 remains
failure. No -N, active-source/image/cache change, signing or device action occurs.
