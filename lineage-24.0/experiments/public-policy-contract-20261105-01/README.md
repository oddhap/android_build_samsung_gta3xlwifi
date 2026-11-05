# Current public contract audit

The official Android17 `version_policy`/`build_sepolicy filter_out` sequence was
reproduced against production public CIL, targeting API30. The resulting contract
is an audit artifact, not a compiler or image input. Its SHA-256 is
`60c463ada2d556d6a79c33ceb29b5956cb827834c0dd5d54960076cb1daad85d`.

Direct substitution is blocked: 92 of the 1,331 legacy public symbols referenced
by Samsung vendor CIL have no declaration in the generated contract plus unchanged
current inputs. In addition, 33 of 37 shared vendor-referenced attribute definition
lists differ in token expressions. Six are compiler-generated `base_typeattr_*`
name collisions. This is a syntactic comparison, not a proof that all 33 effective
memberships differ. Blind substitution or filling in missing declarations alone
would not preserve Samsung's symbol meanings.

The report pins exact inputs, tools, source revisions and the full source audit.
The attribute comparison records both expression token lists and input hashes.
No combined alternate policy is compiled by this audit, and no image, active
source, vendor assertion or enforcement setting is changed. Follow-up platform
port proposals are recorded separately after the owner's scope clarification.
