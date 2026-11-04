# Results — per-vector, transcribed from the recording

All rows transcribe `run-output.txt` (uncut recording). 47/47 vectors passed, 11/11 negative controls passed, 14/14 unit tests passed, regeneration byte-identical, exit 0.

## Native — draft-kroehl-agentic-trust-aae-00 (15/15)

| # | Vector | Expected / observed |
|---|---|---|
| 01 | `valid-root-aae` | `ACCEPT` @ step 7 [structural] |
| 02 | `expired-not-after` | `REJECT` @ step 3 [runtime] `expired_not_after` |
| 03 | `too-early-not-before` | `REJECT` @ step 3 [runtime] `not_yet_valid_not_before` |
| 04 | `revocation-endpoint-5xx` | `REJECT` @ step 8 [runtime] `revocation_status_indeterminate` |
| 05 | `single-use-replay` | `REJECT` @ step 5 [runtime] `single_use_already_consumed` |
| 06 | `delegation-valid-depth-2` | `ACCEPT` @ step 9 [structural] |
| 07 | `delegation-action-superset` | `REJECT` @ step 9 [structural] `delegated_actions_not_subset` |
| 08 | `delegation-constraint-relaxation` | `REJECT` @ step 9 [structural] `delegated_constraint_relaxed` |
| 09 | `delegation-depth-exceeded` | `REJECT` @ step 9 [structural] `delegation_depth_exceeded` |
| 10 | `delegation-cycle-detection` | `REJECT` @ step 9 [structural] `delegation_cycle_detected` |
| 11 | `delegation-cascade-revocation` | `REJECT` @ step 9 [runtime] `ancestor_revoked` |
| 12 | `signing-authority-mismatch` | `REJECT` @ step 1 [structural] `signing_authority_mismatch` |
| 13 | `unrecognized-required-constraint` | `REJECT` @ step 7 [structural] `unrecognized_required_constraint` |
| 14 | `cty-header-wrong` | `REJECT` @ step 2 [structural] `cty_not_aae_json` |
| 15 | `currency-mismatch-delegation` | `REJECT` @ step 9 [structural] `delegation_currency_mismatch` |

Unit tests: `14 passed in 0.07s`.

## Enforce — draft-kroehl-agentic-trust-aae-02, kernel 3.0 (26/26)

| # | Vector | Verdict |
|---|---|---|
| 01 | `type-form-matches-permit` | `PERMIT` |
| 02 | `instance-value-inside-the-action-deny` | `DENY` |
| 03 | `type-field-missing-from-the-action-deny` | `DENY` |
| 04 | `action-is-a-string-deny` | `DENY` |
| 05 | `action-is-an-array-deny` | `DENY` |
| 06 | `action-is-a-number-deny` | `DENY` |
| 07 | `action-is-null-deny` | `DENY` |
| 08 | `grant-without-type_fields-deny` | `DENY` |
| 09 | `type_fields-without-verb-deny` | `DENY` |
| 10 | `duplicate-name-in-type_fields-deny` | `DENY` |
| 11 | `exact-holds-permit` | `PERMIT` |
| 12 | `exact-fails-on-a-vanity-prefix-deny` | `DENY` |
| 13 | `enum-holds-permit` | `PERMIT` |
| 14 | `enum-fails-deny` | `DENY` |
| 15 | `range-holds-at-the-upper-bound-permit` | `PERMIT` |
| 16 | `range-fails-one-over-the-bound-deny` | `DENY` |
| 17 | `unknown-constraint-type-deny` | `DENY` |
| 18 | `field-path-with-an-empty-segment-deny` | `DENY` |
| 19 | `explicit-hold-pending` | `PENDING` |
| 20 | `unaddressed-action-is-never-pending-deny` | `DENY` |
| 21 | `forbid-outranks-an-allowing-grant-deny` | `DENY` |
| 22 | `ratified-by-the-issuing-principal` | `RATIFIED` |
| 23 | `stranger-with-a-valid-signature-rejected` | `REJECTED` |
| 24 | `a-permit-is-not-ratifiable-caller-error` | `RatifyError` |
| 25 | `chain-link-pointing-elsewhere-caller-error` | `RatifyError` |
| 26 | `chain-link-set-explicitly-to-the-ratified-record` | `RATIFIED` |

## Composition — draft-kroehl-agentic-trust-aae-00 × draft-yossif-psea-02 (6/6)

Eight staged rows per case (`aae_native | action_linkage | principal_linkage | evidence_satisfaction | freshness | decision | admission | outcome`); final stages shown.

| # | Vector | Outcome |
|---|---|---|
| XP-1 | `aligned-principal` | `AUTHORIZED` (all stages clean) |
| XP-2 | `principal-divergence` | `REFUSED(principal_divergence)` |
| XP-3 | `unresolved-binding` | `REFUSED(unresolved_binding)` |
| XP-5a | `enrollment-pending` | `REFUSED(unresolved_binding)` |
| XP-5b | `enrollment-complete` | `AUTHORIZED` |
| XP-6 | `alias-convergence` | `AUTHORIZED` |

## Negative controls (11/11)

| # | Mutation | Refused stage / reason |
|---|---|---|
| C1 | secondary-side digest flipped | `REFUSED(join_mismatch)` |
| C2 | principal table entry resolves elsewhere | `REFUSED(principal_divergence)` |
| C3 | PSEA proof signature tampered | `REFUSED(secondary_native_reject)` |
| C4 | clock past the AAE not_after | `REFUSED(aae_native_reject)` |
| C5 | another instant inside both windows | `AUTHORIZED` (sanity control) |
| C6 | declared digest differs from signed action_binding | `REFUSED(action_linkage_unestablished)` |
| C7 | envelope carries no action_binding | `REFUSED(action_linkage_unestablished)` |
| C8 | payload does not hash to declared digest | `REFUSED(payload_digest_mismatch)` |
| C9 | payload leaves the I-JSON subset | `REFUSED(action_linkage_unestablished)` |
| C10 | token carries own key material, claims enrolled kid | `REFUSED(secondary_native_reject)` |
| C11 | psea_counter absent | `REFUSED(counter_malformed)` |
