# Run scope

The pack's runner performs fourteen named join checks per case. Both adapters
implement those fourteen and nothing else. Listed neutrally, in the order the
runner evaluates them.

| # | check | what it compares |
|---|---|---|
| 1 | `bundle.artifact_bytes` | SHA-256 over each slot's base64url-decoded artifact bytes equals the pinned artifact digest |
| 2 | `subject.action_bytes` | SHA-256 over the supplied action bytes equals the subject action digest, and those bytes equal the canonical serialization of the visible action object |
| 3 | `join.digest_context` | each slot's digest context, with the representation member removed, canonicalizes to the same string as the subject's |
| 4 | `join.digest_representation` | each slot declares the same digest representation label as the subject |
| 5 | `join.protected_cross_reference` | each slot's cross-reference names a slot that exists and whose pinned artifact digest equals the reference |
| 6 | `join.additional_binding_context` | every additional binding carries string purpose, context and digest |
| 7 | `policy.binding_semantics` | every policy-required binding purpose has at least one binding declaring understood true |
| 8 | `join.field_basis` | every joined field declares a non-empty basis string |
| 9 | `join.field_mapping` | if slots declare more than one amount basis, a pinned mapping covers them; not evaluated when check 8 did not pass |
| 10 | `report.result_separation` | the reporting block declares native results separate |
| 11 | `report.result_preservation` | the reporting block declares that composition does not override native results |
| 12 | `join.exact_action` | every slot carries the same subject action digest as the bundle |
| 13 | `report.not_evaluated_preservation` | a slot whose native result is not_evaluated is still reported as not_evaluated |
| 14 | `policy.required_profile` | every required profile appears in the supported set |

Terminal status per case is a precedence fold over the fourteen: fail, then
unsupported, then indeterminate, then not_evaluated, otherwise pass. The result
vocabulary is the five values the pack declares: pass, fail, not_evaluated,
unsupported, indeterminate.

## Not exercised

- No profile-native validation. MachineMandate credential validation, EP
  authorization receipt chain rules, SCITT capsule verification, and AEP or GAR
  structures are not evaluated. The slots carry declared native result strings
  and a native detail payload; the fourteen checks read the declared strings and
  do not derive them.
- No signature verification, because the cross-slot pack contains no signatures.
  The adapters hold no key material and perform no COSE, JWS or JWT operation.
- No network access. Both adapters read only the bytes in corpus/.
- No transparency service is contacted.
- The run is against the -00 manifest pin only. The pack's manifest pins
  draft-mih-sato-agent-accountability-composition-00 and that is the revision
  recorded here.
- The second pack in corpus/, caid-aec-aeb-capsule-v1, is copied for
  completeness because the cross-slot manifest lists its bundle.json under
  implementation_sources. Its own runner requires profile-native libraries, so it
  is not executed here and contributes no cases.
