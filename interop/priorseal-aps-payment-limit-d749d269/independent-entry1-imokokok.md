# Independent runner record for entry 1, by @imokokok

A separate record for claim entry 1 of `run-report.md` in this directory (APS evidence: receipts, decision and delegation verify under the pinned test keys at the reference time). `run-report.md` and `results/` are unchanged by this file.

| field | value |
|---|---|
| who ran it | @imokokok |
| run mode | Mode A, the original APS verifier from `948f99b8` |
| author-produced or independent | independent for entry 1: the runner authored neither the APS fixtures nor the original verifier |
| what it is not | a new independent implementation. It is an independent run of the APS-authored verifier |
| source | [#139 comment 5901343345](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/139#issuecomment-5901343345), captured 2026-09-29, body sha256 `646d4b1e43442a0c7b421fa7b55dd6a454167ae27e8090f052fded915626d530` |
| agreement with the aeoess run | the 114 stdout lines are identical to `results/03-original-aps-verifier-948f99b8.txt`, excluding that file's command and exit lines |

Entries 3, 5 and 6 still have no independent record. The offline synthetic claim ceiling in `run-report.md` is unchanged.

## The runner's comment, verbatim

I reviewed the six claim entries and their attribution. The split between the PriorSeal signature and exact call checks, the APS decision correlation, and the separate cap comparison matches the pinned pair. Entries 2 and 4 are independent Mode A records from your run under the lab rule. Entries 3, 5 and 6 remain author produced. The record correctly avoids an aggregate verdict.

Here is a fresh Mode A run for entry 1 from my side. I authored neither the APS fixtures nor the original APS verifier, so this supplies an independent runner record for that entry under CONTRIBUTING.md. It is a run of the original verifier, not a new independent implementation.

Inputs: APS fixtures at `948f99b85343bef2c6fa677c8543965caacfc087` as copied into PriorSeal `d749d2691c3e6be139de4020e7b27cdafca2c428`. My clean checkout has no changes to `aps-inputs` relative to that PriorSeal commit. Original `verify-from-package-root.mjs` fetched from the APS commit, SHA 256 `833b7de7563c26fbfe5d9a33b5935cebb3d68dad417c6f15ab3d84519d93a6f0`. I ran it with the pair's installed `agent-passport-system` 6.0.1 dependency on macOS arm64, Node.js v25.2.1. Command from the pair directory: `node /private/tmp/aps-independent-run/verify-from-package-root.mjs aps-inputs`. The temporary script directory used a symbolic link to the pair directory's installed `node_modules`. Exit status: `0`. Raw stdout SHA 256: `c31448196e8a5817d51690000f6ad814820c0cefda2a11eaa112d9e014f90dc3`.

Verbatim stdout:

```text
ok   manifest cases/deny/action-intent-receipt.json
ok   manifest cases/deny/case.json
ok   manifest cases/deny/decision-evidence.json
ok   manifest cases/deny/policy-decision-receipt.json
ok   manifest cases/expired/action-intent-receipt.json
ok   manifest cases/expired/case.json
ok   manifest cases/expired/decision-evidence.json
ok   manifest cases/expired/policy-decision-receipt.json
ok   manifest cases/narrow/action-intent-receipt.json
ok   manifest cases/narrow/case.json
ok   manifest cases/narrow/decision-evidence.json
ok   manifest cases/narrow/policy-decision-receipt.json
ok   manifest cases/permit/action-intent-receipt.json
ok   manifest cases/permit/case.json
ok   manifest cases/permit/decision-evidence.json
ok   manifest cases/permit/policy-decision-receipt.json
ok   manifest keys.json
ok   keys.json receipt signers equal the pinned keys
ok   keys.json delegation key equals the pinned key
ok   permit: intent receipt verifies from its committed bytes
ok   permit: decision receipt verifies from its committed bytes
ok   permit: intent receipt_type is aps:action-intent:v1
ok   permit: intent issuer equals subject_agent
ok   permit: intent has no prev and no decision_ref
ok   permit: intent result is exactly the declared result
ok   permit: intent is signed by the agent
ok   permit: decision receipt_type is aps:policy-decision:v1
ok   permit: decision issuer is not the agent
ok   permit: decision prev is the intent receipt_id
ok   permit: decision_ref is present
ok   permit: both receipts name one agent, action_ref and delegation_ref
ok   permit: decision is issued after the intent
ok   permit: decision result equals decision_evidence.decision_output
ok   permit: decision verdict is permit
ok   permit: authority_state has the four required members
ok   permit: composite valid is true
ok   permit: decision_ref_bound is true
ok   permit: errors are []  []
ok   permit: selected delegation chain verifies at the decision time  []
ok   permit: delegation_ref is the leaf delegation_id and the leaf subject is the agent
ok   permit: unexpired at reference time is true
ok   narrow: intent receipt verifies from its committed bytes
ok   narrow: decision receipt verifies from its committed bytes
ok   narrow: intent receipt_type is aps:action-intent:v1
ok   narrow: intent issuer equals subject_agent
ok   narrow: intent has no prev and no decision_ref
ok   narrow: intent result is exactly the declared result
ok   narrow: intent is signed by the agent
ok   narrow: decision receipt_type is aps:policy-decision:v1
ok   narrow: decision issuer is not the agent
ok   narrow: decision prev is the intent receipt_id
ok   narrow: decision_ref is present
ok   narrow: both receipts name one agent, action_ref and delegation_ref
ok   narrow: decision is issued after the intent
ok   narrow: decision result equals decision_evidence.decision_output
ok   narrow: decision verdict is narrow
ok   narrow: authority_state has the four required members
ok   narrow: composite valid is true
ok   narrow: decision_ref_bound is true
ok   narrow: errors are []  []
ok   narrow: selected delegation chain verifies at the decision time  []
ok   narrow: delegation_ref is the leaf delegation_id and the leaf subject is the agent
ok   narrow: unexpired at reference time is true
ok   deny: intent receipt verifies from its committed bytes
ok   deny: decision receipt verifies from its committed bytes
ok   deny: intent receipt_type is aps:action-intent:v1
ok   deny: intent issuer equals subject_agent
ok   deny: intent has no prev and no decision_ref
ok   deny: intent result is exactly the declared result
ok   deny: intent is signed by the agent
ok   deny: decision receipt_type is aps:policy-decision:v1
ok   deny: decision issuer is not the agent
ok   deny: decision prev is the intent receipt_id
ok   deny: decision_ref is present
ok   deny: both receipts name one agent, action_ref and delegation_ref
ok   deny: decision is issued after the intent
ok   deny: decision result equals decision_evidence.decision_output
ok   deny: decision verdict is deny
ok   deny: authority_state has the four required members
ok   deny: composite valid is false
ok   deny: decision_ref_bound is true
ok   deny: errors are ["valid_until_absent"]  ["valid_until_absent"]
ok   deny: selected delegation chain verifies at the decision time  []
ok   deny: delegation_ref is the leaf delegation_id and the leaf subject is the agent
ok   deny: unexpired at reference time is null
ok   expired: intent receipt verifies from its committed bytes
ok   expired: decision receipt verifies from its committed bytes
ok   expired: intent receipt_type is aps:action-intent:v1
ok   expired: intent issuer equals subject_agent
ok   expired: intent has no prev and no decision_ref
ok   expired: intent result is exactly the declared result
ok   expired: intent is signed by the agent
ok   expired: decision receipt_type is aps:policy-decision:v1
ok   expired: decision issuer is not the agent
ok   expired: decision prev is the intent receipt_id
ok   expired: decision_ref is present
ok   expired: both receipts name one agent, action_ref and delegation_ref
ok   expired: decision is issued after the intent
ok   expired: decision result equals decision_evidence.decision_output
ok   expired: decision verdict is permit
ok   expired: authority_state has the four required members
ok   expired: composite valid is true
ok   expired: decision_ref_bound is true
ok   expired: errors are []  []
ok   expired: selected delegation chain verifies at the decision time  []
ok   expired: delegation_ref is the leaf delegation_id and the leaf subject is the agent
ok   expired: unexpired at reference time is false
ok   negative: unresolved key fails at receipt_invalid
ok   negative: the agent key does not verify a boundary signature
ok   negative: evidence from another case fails at decision_ref_mismatch
ok   negative setup: the clean receipt opens with its profile, and the mutation adds exactly one top-level copy
ok   negative: a duplicated top-level member in the bytes fails at parse_error  ["parse_error","$: duplicate object member"]
ok   the four decision_ref values are distinct
ALL CHECKS PASSED
```

Please append this as a separate entry 1 record if it fits the lab format. It leaves entries 3, 5 and 6 without independent records and does not change the offline synthetic claim ceiling. No attachment is needed; the full stdout is above.

## Clarification, 2026-09-30

The `body sha256` value recorded above, `646d4b1e43442a0c7b421fa7b55dd6a454167ae27e8090f052fded915626d530`, is the SHA-256 of the GitHub API `body` bytes plus one trailing LF. The SHA-256 of the API `body` bytes alone is `a8b69e5861f995efadd0c7f97c60a0be1a9f1129d210ab0bcf4e7c899e2ab5ce`. This clarification affects only that provenance label. The 114 stdout lines and their SHA-256 `c31448196e8a5817d51690000f6ad814820c0cefda2a11eaa112d9e014f90dc3` are unchanged. Raised by @imokokok in #139 comment 5906962778.
