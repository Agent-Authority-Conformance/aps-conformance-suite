# lifecycle-credential-events

Candidate cases from the **Credential events** section of the Authority
Lifecycle case list, built as one family. A compromise disclosure arrives from
outside the organization that issued the credential. A rotation covers the list
someone maintained instead of the set the authority graph reaches. A signature
verifies while the separate question it was taken to answer has no evidence at
all. A key reaches a declared cryptoperiod end with nothing to investigate, and
a different key is found exposed two years before anyone noticed.

Nothing here is merged specification text and nothing here is a conformance
claim about APS or any other protocol. The harness is protocol neutral: a
synthetic verifier in front of a set of synthetic event records, with no APS
type, no APS receipt, no network call and no wall-clock read anywhere in it.

## Status

**candidate_against_proposed.** Every vector carries that label in
`vectors.json`, names the CASES.md case id it was built for, and names the
sections of the proposed text it tests.

| field | value |
|---|---|
| repository | `aeoess/agent-authority-lifecycle` |
| `CASES.md` commit | `2bf5c7e` (version 0.2-draft) |
| `AUTHORITY-LIFECYCLE.md` commit | `7796e22` or later (version 0.1.2-draft) |
| status of the text itself | proposed. Every case in the Credential events section is marked `Status: proposed` and the case list says no runnable fixture exists for any case yet |

That repository is the text under test, not an external source for any factual
claim in this README. Where this README makes a claim about a standard or an
incident, the source was fetched in the session that wrote this fixture and is
quoted below.

## The one idea

A boundary declares which checks its policy requires. Each required check
resolves, from its own input records only, to one of three results.

| check result | meaning |
|---|---|
| `established_valid` | a record with a declared attestor settles the question in the affirmative |
| `established_invalid` | a record settles it in the negative. The claim is false, not merely unevidenced |
| `not_established` | no record settles it. This is not the same as false |

The boundary verdict is the join, in the settled verdict vocabulary: one
`established_invalid` makes the boundary `invalid`, otherwise one
`not_established` makes it `not established`, otherwise `valid`. Two rules ride
on top and are what most of the vectors exercise.

1. No check's answer is inferred from another check's answer.
2. A declared check with no input record is `not_established`, never passed.

The settled vocabulary is `valid`, `invalid`, `not established`, `not yet
effective`, `suspended`, `restricted`. This family reaches the first three for a
credential at a boundary. `not yet effective` is used for the state of a
revocation record that cannot take effect for a credential class before that
credential expires, which is LC-F-035. No vector here reaches `suspended` or
`restricted`, which belong to suspension and external-restriction families.

## Case coverage

Nineteen cases sit under **Credential events** in `CASES.md` at `2bf5c7e`.
Sixteen are built here. Three are already covered by an existing fixture.

| case | decision | vectors, or the fixture that covers it |
|---|---|---|
| LC-D-001 | VECTOR | `LC-D-001-a`, `-b`, `-c`, `-d` |
| LC-D-003 | VECTOR | `LC-D-003-a`, `-b` |
| LC-D-004 | VECTOR | `LC-D-004-a`, `-b` |
| LC-D-009 | VECTOR | `LC-D-009-a`, `-b`, `-c` |
| LC-D-010 | COVERED | `lifecycle-purpose-exhaustion`, `PXE-03-reject-second-purchase-wednesday` and `PXE-12-reject-after-grant-not_after-expiry-and-exhaustion-coexist` |
| LC-D-011 | VECTOR | `LC-D-011-a`, `-b`, `-c` |
| LC-D-014 | VECTOR | `LC-D-014-a`, `-b`, `-c` |
| LC-D-025 | VECTOR | `LC-D-025-a`, `-b` |
| LC-D-029 | VECTOR | `LC-D-029-a`, `-b`, `-c` |
| LC-D-033 | VECTOR | `LC-D-033-a`, `-b`, `-c` |
| LC-D-034 | COVERED | `lifecycle-purpose-exhaustion`, `PXE-03` and `PXE-08-reject-unauthenticated-completion` |
| LC-F-008 | COVERED | `conflicting-status-sources`, `CSS-09-offline-snapshot-within-declared-bound-admits`, `CSS-10-offline-snapshot-past-declared-bound-not-established`, `CSS-11-offline-snapshot-revoked-denies` |
| LC-F-013 | VECTOR | `LC-F-013-a`, `-b`, `-c` |
| LC-F-033 | VECTOR | `LC-F-033-a`, `-b` |
| LC-F-035 | VECTOR | `LC-F-035-a`, `-b` |
| LC-G-001 | VECTOR | `LC-G-001-a` |
| LC-G-002 | VECTOR | `LC-G-002-a`, `-b` |
| LC-G-003 | VECTOR | `LC-G-003-a`, `-b`, `-c` |
| LC-G-004 | VECTOR | `LC-G-004-a`, `-b`, `-c` |

### Why the three COVERED cases are covered, and what is left over

**LC-D-010** and **LC-D-034** are both a purpose-bound credential outliving the
purpose. `lifecycle-purpose-exhaustion` already tests the decidable half: a
grant whose declared purpose has an authenticated completion record stops
authorizing new use, is not revoked, and is not expired. What neither that
fixture nor this one tests is the half LC-D-010 actually names, a credential that
was never given any bound at all. There is no record at the boundary to check,
because the absence of a bound is not an event. That residue is recorded under
**Where the proposed text was too vague to test** rather than turned into a
vector, because a vector for it would have to invent an issuance-time policy
this fixture has no standing to declare.

**LC-F-008** is an offline verifier admitting on a pre-synced snapshot inside a
bound it declared in advance, and recording the snapshot and its age.
`conflicting-status-sources` tests exactly that, including the negative control
`offline-admit-without-recording` for a verifier that reaches the same verdicts
without writing what it admitted on. Adding it here would duplicate that family.

No case in this section was decided RESEARCH_ONLY. Every one of the nineteen ends
in something a verifier could read from records, once the record set is declared.

## The proposed text each vector tests

Per-vector section lists are in `vectors.json` under `cases[].proposed_text`.
The load-bearing entries, quoted from `AUTHORITY-LIFECYCLE.md` at `7796e22`:

| section | quoted |
|---|---|
| Lifecycle concepts are separate > Verification and evidence > **Status observation** | "What authority state a verifier could establish, from which source, at what time and with what freshness. Current authority and observed authority can differ." |
| Verification and evidence > **Verifier trust policy** | "Which issuers, roots, status sources and rules a verifier accepts. A verifier can stop trusting an issuer without anything being revoked." |
| Verification and evidence > **Evidence attestor** | "Who produced or signed a piece of evidence, and in what role. A gateway attesting an execution makes a different claim from an issuer signing a grant, and its key has its own lifecycle." |
| Verification and evidence > **Coverage and completeness** | "Showing that individual records are authentic is weaker than establishing that all relevant events were observed." |
| Verification and evidence > **Notice** | "Recording a transition and observing it are different events." |
| Parties and standing > **Issuer standing** | "A valid signature establishes who signed. It does not by itself establish standing." |
| Parties and standing > **Lifecycle standing** | "Who may suspend, revoke, replace or reaffirm an authority artifact. This is not always the issuer." |
| Authority lifecycle state > **Authority epoch** | "Where a system uses generations, separates current authority from stale authority surviving in sessions, queues, replicas, snapshots or restored state." |
| Authority and dependencies > **Action or capability binding** | "A tool can keep its name while what it does changes, which widens effective authority without any change to the grant." |
| Invariants > **L12. Completeness is a separate and stronger claim** | "A claim that all descendants were processed needs a defined basis for which set was complete." |

## What draft-03 does and does not state

`draft-pidlisnyi-aps-03`, fetched from
`https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt` on 2026-09-23.

What it states, and this family relies on:

- Section 2.4, on a key-retirement boundary: "When key retirement makes the
  result depend on whether an artifact was signed before a boundary, a profile
  MUST identify an acceptable timestamp, transparency-log, or equivalent evidence
  source." And: "Without that evidence the key-authority result is indeterminate,
  even when the artifact signature is cryptographically valid." That is the
  shape LC-G-003 pins for a compromise partition.
- Section 2.6: "A signal's provenance tier and its verification status are
  independent axes ... and a verifier MUST NOT infer verification from tier."
  That is the shape LC-D-029 pins for build provenance.
- Section 3.3: "A caller MUST NOT collapse indeterminate or unsupported into
  valid."
- Section 3.5.1: "The model separates two questions that MUST NOT collapse into
  one mutable lookup: whether a delegation is currently valid, answerable from
  state, and whether and why a revocation occurred, verifiable from signed
  records." That is the shape LC-D-025 pins.
- Section 3.5.1, on completeness: "a partially revoked subtree is
  indistinguishable, record by record, from a completed one."
- Section 7, on an imported grant's audience: "The grant's audience is carried
  in the binding but not enforced by it; the relying party at the point of use
  MUST reject an audience mismatch." That is the shape LC-G-004 pins.

What it does not state, which is why every vector here is labelled
candidate_against_proposed and none is labelled a draft-03 conformance case:

- No per-boundary required-check set, and no per-check result vocabulary. The
  three-valued check result and the join in this family are the fixture's own.
- No reachable set for a compromised subject, and no notion of an identity that
  is reachable to a chain without appearing in it. Section 3.3 verifies one
  root-to-leaf chain.
- No ingestion path for another party's compromise disclosure as a status input.
- No clock tolerance and no skew outcome. Current validity is a step in Section
  3.3 and nothing separates a clock disagreement from an expiry.
- No revocation effectiveness per credential format. Section 3.5 makes
  revocation irreversible and requires a recheck at execution time, and says
  nothing about a class that cannot be looked up.
- No finding about an issuer's own issuance records over a window, and no
  escalation from revoking named artifacts to questioning an issuer's whole
  population.
- No coverage basis for what was exercised under a credential, and no rule for a
  root that entered a trust policy by inheritance.
- No record of how an additional authorizer came to be attached to an identity.

Each vector carries its own `draft_03` note in `vectors.json` saying which of
these applies to it.

## Sources

Every claim below about a standard or an incident was fetched in the session
that wrote this fixture and is quoted verbatim. Each one is here because it
carries design weight for a vector, not as decoration. The precedents for the
remaining cases are recorded in `CASES.md` with their own sources, which this
fixture does not restate and makes no independent claim about.

**A compromise disclosure can arrive from the integrator, with the credential
issuer having revoked nothing.** GitHub's 2022 disclosure about OAuth tokens
issued to two third-party integrators.
[GitHub blog](https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/):
"The attacker authenticated to the GitHub API using the stolen OAuth tokens
issued to Heroku and Travis CI." The same post separates the trigger from the
issuer's own systems: "We do not believe the attacker obtained these tokens via
a compromise of GitHub or its systems". LC-D-001.

**A rotation measured over what someone believed was live leaves a live
descendant standing.**
[Cloudflare blog](https://blog.cloudflare.com/thanksgiving-2023-security-incident):
"The one service token and three accounts were not rotated because mistakenly it
was believed they were unused. This was incorrect and was how the threat actor
first got into our systems." LC-D-003.

**A compromised operator identity is an ancestor over trees its own session
never touched.**
[CircleCI incident report](https://circleci.com/blog/jan-4-2023-incident-report/):
"Because the targeted employee had privileges to generate production access
tokens as part of the employee's regular duties, the unauthorized third party
was able to access and exfiltrate data." LC-D-004.

**A documented scope and a reachable scope can differ for years.** Fazio
Mechanical's own description of its connection to Target, quoted by
[Krebs on Security](https://krebsonsecurity.com/2014/02/target-hackers-broke-in-via-hvac-company/):
"Our data connection with Target was exclusively for electronic billing,
contract submission and project management". LC-D-009.

**An inherited environment can run for years on the acquired entity's own
assumptions.**
[CSO Online](https://www.csoonline.com/article/567795/marriott-data-breach-faq-how-did-it-happen-and-what-was-the-impact.html):
"Marriott purchased Starwood in 2016, but nearly two years later, the former
Starwood hotels hadn't been migrated to Marriott's own reservation system and
were still using IT infrastructure inherited from Starwood." LC-D-011.

**An issuer can be unable to establish what it issued.**
[Threatpost](https://threatpost.com/final-report-diginotar-hack-shows-total-compromise-ca-servers-103112/77170/):
"Serial numbers for certificates that did not match the official records of
DigiNotar were recovered on multiple CA servers ... indicating that these
servers may have been used to issue additional and currently unknown rogue
certificates". LC-D-014.

**Authority validly held and correctly scoped can still be misused for its whole
active duration.**
[The Hacker News](https://thehackernews.com/2025/05/coinbase-agents-bribed-data-of-1-users.html),
quoting Coinbase's chief security officer: "What these attackers were doing was
finding Coinbase employees and contractors based in India who were associated
with our business process outsourcing or support operations, that kind of thing,
and bribing them in order to obtain customer data." LC-D-025.

**A correct signature can cover an artifact the process itself made
illegitimate.**
[ReversingLabs](https://www.reversinglabs.com/blog/sunburst-the-next-level-of-stealth):
"What is certain is that the build infrastructure was compromised. In addition,
the digital signing system was forced to sign untrusted code." LC-D-029.

**An authorizer can be attached to an identity through the provider's own
internal path.**
[BleepingComputer](https://www.bleepingcomputer.com/news/security/twilio-breach-let-hackers-gain-access-to-authy-2fa-accounts/):
"On Thursday, Twilio announced that the threat actor that gained access to its
infrastructure on August 4 has also accessed accounts of 93 Authy users and
linked devices to those accounts." LC-D-033.

**Rejecting on clock skew is deployed practice with its own configured
tolerance.**
[MIT Kerberos documentation](https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5.4/doc/krb5-admin/Clock-Skew.html):
"Kerberos V5 is set up to reject ticket requests from any host whose clock is not
within the specified maximum clock skew of the KDC". The same page gives the
default: "The default value for maximum clock skew is 300 seconds, or five
minutes." The 300 second tolerance in this family's vectors is that number.
LC-F-013.

**Systemic mis-issuance found from outside escalates past the instances that
were caught.**
[arkadiyt.com](https://arkadiyt.com/2018/02/04/quantifying-untrusted-symantec-certificates/):
"In January 2017, it came to light that Symantec had misissued at least 30,000
certificates over a period of several years." The same analysis describes the
response as a population-wide cut rather than a per-chain one: "Starting with the
release of Chrome 66 on April 17th 2018, Symantec certificates issued before June
1st 2016 or after December 1st 2017 will no longer be considered trusted."
LC-F-033.

**A cryptoperiod is a boundary declared in advance, and a compromise is a
separate event that ends it early.** NIST SP 800-57 Part 1 Revision 5, Section
5.3,
[PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf):
"A cryptoperiod is the time span during which a specific key is authorized for
use by legitimate entities or the keys for a given system will remain in
effect." And, in the same section: "If a key is compromised, its cryptoperiod
shall no longer be considered valid." LC-G-001.

**Where exploitation leaves no trace, the window cannot start at discovery.**
[heartbleed.com](https://heartbleed.com/), the coordinated-disclosure site:
"Exploitation of this bug does not leave any trace of anything abnormal happening
to the logs." LC-G-002.

**A partition through a compromised signer's own output can be drawn with an
independent log's timestamps.**
[How to distrust a CA without any certificate errors, dadrian.io](https://dadrian.io/blog/posts/sct-not-after/):
"Setting an SCTNotAfter date of P - 1 allows every existing certificate from
before the compromise to live out its remaining lifecycle, while limiting the
distrust to only certificates from after the compromise." The same post names
why the signer's own claim will not do: the mechanism gives "cryptographic
assurance about the NotBefore date ... without risking a CA backdating a
certificate to get around the distrust". LC-G-003.

**A key scoped to one population can be accepted for a broader one when the
scope is not checked separately from the signature.**
[Microsoft, Analysis of Storm-0558 techniques for unauthorized email access](https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/):
"Though the key was intended only for MSA accounts, a validation issue allowed
this key to be trusted for signing Azure AD tokens." LC-G-004.

**LC-F-035 has no source and claims none.** `CASES.md` labels it hypothetical:
it names a structural property of a signature-only bearer artifact rather than a
documented incident. This fixture keeps it hypothetical and cites nothing for it.

**The canonicalization.** RFC 8785,
[JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785.txt),
June 2020: "This document describes the JSON Canonicalization Scheme (JCS)."

## The model

`harness.ts` holds the checks, the axes and the join. `verify.ts` replays the
vectors against it. `validate.py` is a second implementation of the same stated
rule. The record is `aac.credential-event-record.v0`, named so it cannot be
mistaken for APS vocabulary.

### The thirteen checks

| check id | what its own records have to settle |
|---|---|
| `signature_and_key_version` | that the signature verifies under the key version authorized at the artifact's own issuance instant. Always established in this family, so it is available to be the thing other checks must not be satisfied by |
| `key_scope_containment` | that the signing key's declared population covers the audience the artifact claims |
| `enforced_scope_containment` | that what the enforcement boundary actually reaches is inside the scope the credential declares |
| `artifact_provenance` | that an attestor independent of the signing key says how the artifact was produced |
| `authorizer_addition_provenance` | that every authorizer attached to the identity has a record of its addition from a party with declared standing |
| `compromise_reach` | whether the credential is reachable from a disclosed compromised subject, over the declared authority graph, and whether it has been re-attested since |
| `issuance_log_integrity` | whether a finding about the issuer's own issuance records covers the window the credential claims to have been issued in |
| `issuer_population_trust` | whether an externally discovered systemic finding about the issuer has been answered for the population, not chain by chain |
| `suspect_window_partition` | where a key finding's suspect window starts, and which side of it the artifact is independently dated on |
| `revocation_effectiveness` | whether a recorded revocation is effective for this credential class at this boundary |
| `clock_agreement` | whether this boundary's clock and an attested reference clock agree inside the declared tolerance, before any window comparison is believed |
| `inherited_root_reattestation` | whether a root that entered the trust policy by inheritance was re-established under the inheriting party's own root by the declared deadline |
| `exercised_authority_accounting` | whether a coverage basis claims completeness over the interval the credential was valid |

A boundary declares a subset in `trust_policy.required_checks`, in precedence
order. A check outside that list is absent from the record rather than recorded
as unchecked, which is where this family's three-valued check result differs from
the reference SDKs' four-valued one.

### Event records

Each event carries an `attestor` and an `attestor_standing` of `declared` or
`not_declared`. Standing is a separate field because a valid signature would
establish who signed and not that the signer may say this. Fifteen event types
appear across the vectors, from `compromise_disclosure` and `reattestation` to
`independent_timestamp_attestation` and `accounting_coverage_basis`. Every one is
listed in `vectors.json` inside the boundary that uses it.

## Vectors

Forty-two vectors, forty-three boundaries. One vector per row, with the
verdict the reference verifier reaches.

| vector | verdict | what it covers |
|---|---|---|
| `CE-00-positive-control-every-check-established` | valid | all thirteen checks declared and every input record present |
| `LC-D-001-a-third-party-disclosure-is-a-trigger` | not established | the integrator discloses, the org revoked nothing, the credential is in reach |
| `LC-D-001-b-reattested-after-disclosure` | valid | a re-attestation from a party with declared standing |
| `LC-D-001-c-unattributed-compromise-claim-is-not-a-trigger` | valid | a claim from a party with no declared standing is recorded and is not a trigger |
| `LC-D-001-d-later-finding-does-not-rewrite-the-earlier-record` | valid, then not established | two boundaries, the later one referencing the earlier record by digest |
| `LC-D-003-a-reach-over-the-graph-not-the-believed-list` | not established | reachable over the graph, absent from the maintained list |
| `LC-D-003-b-both-bases-agree-so-agreement-establishes-nothing` | not established | on the list as well, so the verdict alone cannot tell the bases apart |
| `LC-D-004-a-operator-identity-reaches-an-independent-tree` | not established | an identity reachable to the chain without appearing in it |
| `LC-D-004-b-operator-identity-with-no-edge-to-this-tree` | valid | reach over the graph is not reach over everything |
| `LC-D-009-a-enforced-scope-exceeds-declared-scope` | invalid | the attested reachable scope is wider than the declared scope |
| `LC-D-009-b-no-reachable-scope-attestation` | not established | nothing attests what the boundary reaches |
| `LC-D-009-c-enforced-scope-contained` | valid | contained, established from the attestation |
| `LC-D-011-a-inherited-root-past-its-reattestation-deadline` | not established | an inherited root past the declared deadline with no record |
| `LC-D-011-b-inherited-root-inside-its-deadline` | valid | inheritance alone is not the failure |
| `LC-D-011-c-inherited-root-reestablished` | valid | re-established under the inheriting party's own root |
| `LC-D-014-a-issuance-log-integrity-unestablished-for-the-window` | not established | issued inside the covered window, with a revocation naming a different credential |
| `LC-D-014-b-issued-outside-the-covered-window` | valid | the finding does not reach everything the issuer signed |
| `LC-D-014-c-reestablished-from-a-reverified-root` | valid | a record about the window, not per-artifact revocation |
| `LC-D-025-a-revoked-and-accounting-not-established` | invalid | two answers in one record, the second not established |
| `LC-D-025-b-revoked-and-accounting-established` | invalid | the same first answer with the second now established |
| `LC-D-029-a-no-provenance-attestation` | not established | the signature check is established and the provenance check is not |
| `LC-D-029-b-provenance-attestor-is-the-signing-key-holder` | not established | an attestation that restates the signature's own claim |
| `LC-D-029-c-independent-provenance-attestation` | valid | an attestor independent of the signing key |
| `LC-D-033-a-authorizer-with-no-addition-record` | not established | presence on the authorizer list with no record of the addition |
| `LC-D-033-b-addition-attestor-standing-not-declared` | not established | an addition through a path with no declared standing |
| `LC-D-033-c-every-authorizer-attested` | valid | every authorizer has an attested addition |
| `LC-F-013-a-clock-disagreement-is-its-own-outcome` | not established | skew past tolerance, with the artifact inside its window on the reference clock |
| `LC-F-013-b-expiry-with-clocks-agreeing` | invalid | the outcome a skew rejection must stay distinct from |
| `LC-F-013-c-clocks-agree-inside-the-window` | valid | clocks agree, artifact inside its window |
| `LC-F-033-a-issuer-population-trust-not-established` | not established | an external finding about the issuer, this chain never caught |
| `LC-F-033-b-issuer-population-reattested` | valid | the population re-attested |
| `LC-F-035-a-revocation-not-yet-effective-for-this-credential-class` | valid | a recorded revocation that cannot take effect before the credential expires |
| `LC-F-035-b-revocation-effective-where-status-is-looked-up` | invalid | the same record at a boundary that looks status up |
| `LC-G-001-a-planned-rotation-opens-no-suspect-window` | valid | a declared cryptoperiod end is not an investigation trigger |
| `LC-G-002-a-window-starts-at-exposure-not-discovery` | not established | issued between exposure and discovery |
| `LC-G-002-b-issued-before-the-exposure-start` | valid | the window has a start and an artifact before it keeps its standing |
| `LC-G-003-a-independently-dated-before-the-compromise-point` | valid | partition drawn with an independent attestor |
| `LC-G-003-b-only-the-compromised-keys-own-claim-dates-the-artifact` | not established | the only date available is the one the suspect key signed |
| `LC-G-003-c-independently-dated-inside-the-window` | not established | independently dated after the point, which is not a finding of forgery |
| `LC-G-004-a-key-scope-does-not-cover-the-claimed-audience` | invalid | a consumer-scoped key on an enterprise-scoped claim |
| `LC-G-004-b-no-key-scope-declared` | not established | nothing says what population the key was scoped to |
| `LC-G-004-c-key-scope-covers-the-claimed-audience` | valid | covered, established from the key-scope record |

### The negative control a naive implementation passes wrongly

`LC-D-003-a`. An upstream compromise is disclosed and the org raises its own
rotation. An implementation that computes reach from the list it maintains of
grants it believes are live finds this credential absent from that list, leaves
it alone, and looks correct doing it: it reacted to the trigger, it enumerated
descendants, it wrote a clean record. The credential is reachable from the
compromised subject over the authority graph the same deployment declared.

The `enumerated-reach-basis` control is exactly that implementation. It changes
the verdict on `LC-D-003-a` and on `LC-D-004-a`, and it agrees with the
reference on `LC-D-003-b`, where the list happens to contain the credential.
`LC-D-003-b` is in the fixture so that agreement on one case cannot be mistaken
for the two bases being the same rule.

`skip-unestablished-checks` is the broader version of the same mistake: it treats
every declared check with no input record as passed. It runs against all
forty-two vectors and changes the verdict on seventeen of them.

## Negative controls

Fourteen controls, each changing one axis of the reference policy, each run
against a declared scope rather than only the vectors predicted to diverge.
Two sets are declared per control. `must_fail` is where the written record
differs at all. `must_change_verdict` is the subset where the verdict itself
differs, which is the stronger claim. A control that only changes the record is
not a weaker control: it is one whose mistake is invisible in the verdict, which
is the harder kind to find in a deployment.

| control | axis changed | scope | record diverges | verdict changes |
|---|---|---|---|---|
| `self-initiated-triggers-only` | whether another party's disclosure is ingested as a trigger at all | 6 | 4 | 2 |
| `enumerated-reach-basis` | what reachability is computed over | 4 | 4 | 2 |
| `signature-satisfies-other-checks` | whether a valid signature stands in for a separately declared check | 9 | 9 | 6 |
| `grandfather-inherited-root` | whether an inherited root needs its own record | 3 | 3 | 1 |
| `per-artifact-revocation-settles-log-integrity` | what settles an issuance-log finding | 3 | 2 | 1 |
| `issuer-population-from-caught-chains` | whether a systemic finding is answered chain by chain | 2 | 2 | 1 |
| `revocation-closes-accounting` | whether accounting is inferred from authority status | 2 | 2 | 0 |
| `presence-implies-authorized-addition` | whether presence on the list establishes the addition | 3 | 3 | 2 |
| `skew-is-expiry` | how a clock disagreement is categorized | 3 | 1 | 1 |
| `revocation-is-universal` | whether revocation effectiveness is a class property | 2 | 2 | 1 |
| `every-rotation-is-a-trigger` | whether a planned rotation opens a suspect window | 4 | 1 | 1 |
| `discovery-dated-window` | where a suspect window starts | 2 | 2 | 1 |
| `trust-claimed-issued-at` | which timestamp partitions the window | 3 | 3 | 1 |
| `skip-unestablished-checks` | what a declared check with no record resolves to | 42 | 18 | 17 |

`revocation-closes-accounting` changes no verdict anywhere in its scope. It
reaches `invalid` on both `LC-D-025` vectors, exactly as the reference does, and
writes a record claiming the second question was answered when it was not. That
is the whole point of the case, and it is why the runner checks the record and
not only the verdict.

## Results

Both runners produced the same table.

| runner | vectors | boundaries | reference verifier | controls |
|---|---|---|---|---|
| `verify.ts` (TypeScript) | 42 | 43 | matched every pinned record | each diverged on exactly its declared set |
| `validate.py` (Python) | 42 | 43 | matched every pinned record | each diverged on exactly its declared set |

The two agree on every verdict, every reason and every RFC 8785 canonical
digest. SDK results, with the exact commands, exit codes and verbatim output,
are in `SDK-RUNS.md`.

| claim | `agent-passport-system` 7.1.0 (npm) | `agent-passport-system` 4.1.0 (PyPI) |
|---|---|---|
| chain verdict under the projected single revocation answer | supported, 43/43 | supported, 43/43 |
| a declared recipient scope checked as its own facet | supported, 2 of 3 outcomes exact | not_supported |
| scope containment arithmetic | supported, 2/2 | supported, 2/2 |
| per-check results in a fixed enum, attestor independence from trust context | supported, 43/43 | supported, 43/43 |
| a signing key checked for its authorized purpose | supported, narrower vocabulary | not_supported |
| clock disagreement as an outcome distinct from expiry | partial | not_supported |
| compromise reach over a declared authority graph | not_supported | not_supported |
| revocation effectiveness as a credential-class property | not_supported | not_supported |
| an issuance-window finding, or issuer-population trust | not_supported | not_supported |
| a coverage basis for exercised authority | not_supported | not_supported |

Three of those rows are findings rather than plumbing.

- **The SDKs already carry the family's core shape.** Both export a
  composition-check verifier whose per-check result enum is
  `["pass","fail","indeterminate","not_checked"]`, which returns no aggregate
  verdict of its own, and which corroborates an attestor's claimed independence
  from the verifier's trust context instead of from the receipt. That last
  property is what `LC-D-029-b` turns on, and it is already implemented.
- **The `not established` outcome does not survive the npm SDK's audience
  lattice.** `checkAudience` has four values and reserves `unknown` for a policy
  carrying no recipient identifier, mapping "binding required and absent" to
  `fail`. This family returns `not established` there. Recorded as a divergence
  in the bridge output, not smoothed over.
- **A clock disagreement has no denial category in either SDK.** The npm SDK can
  say two clock readings are not definitely ordered, which is real support for
  half of `LC-F-013`. Neither SDK has an outcome that distinguishes a skew
  rejection from the expiry in `LC-F-013-b`, which is the confusion the case
  exists to prevent.

## Determinism

- Seed input `aac-lifecycle-credential-events-v0`, recorded in `vectors.json`
  with its SHA-256. Every key in `chain.json` is an Ed25519 seed derived from
  that string, so the file carries no secret material.
- Every instant is a literal in `generate.ts`. No wall clock, no random source,
  no network, in the generator, the harness or either runner.
- Records are canonicalized under RFC 8785 JCS and pinned by SHA-256 over those
  bytes plus the byte length. `verify.ts` uses the suite's vendored
  canonicalizer. `validate.py` uses the Python reference SDK's independent RFC
  8785 implementation, so the digests it recomputes are cross-language digests.
- `vectors.json` is generated, never hand-edited. The pinned `record` object is
  the record the reference verifier writes, and `validate.py` additionally checks
  the pinned object byte for byte against its own.
- `CHECKSUMS.sha256` pins `vectors.json` and `chain.json`. The suite's
  `test:digest-integrity` gate recomputes it.
- One cross-language constant is pinned inside the SDK bridges: the Ed25519
  signature over a composition-check receipt built from `vectors.json`. Both
  bridges check it, so a divergence in either package's canonicalizer or domain
  tag fails both runs.

## Running

```
npm ci --include=dev
npm run generate:lifecycle-credential-events     # rewrites vectors.json
npm run verify:lifecycle-credential-events       # TypeScript runner
npm run verify:lifecycle-credential-events:sdk-ts  # npm SDK bridge
python3 fixtures/lifecycle-credential-events/mint.py       # rewrites chain.json
python3 fixtures/lifecycle-credential-events/validate.py   # Python runner
python3 fixtures/lifecycle-credential-events/sdk_bridge.py # PyPI SDK bridge
```

The two `verify:` scripts are wired into `npm test`. The Python scripts need
`agent-passport-system` 4.1.0 or later from PyPI and are run separately, the same
way the other families' Python side is.

## Verification split

One entry per distinct verification claim, using the definitions in
`CONTRIBUTING.md`.

- **Vectors and reference records / the reference verifier reproduces every
  pinned verdict, reason and RFC 8785 digest; `verify.ts`; Mode A;
  author-produced; `harness.ts` in this directory.** Authorship relationship:
  the runner, the vectors and the implementation being exercised were all
  written in this lab, in the same change.
- **Vectors and reference records / the same verdicts, reasons and digests
  recomputed by a second implementation; `validate.py`; Mode B;
  author-produced; an independent Python implementation of the decision
  procedure in this directory, over the Python reference SDK's RFC 8785
  canonicalizer.** Authorship relationship: written from this README and
  `vectors.json` rather than ported line by line, but by the same author as the
  TypeScript side, so agreement is agreement between two implementations from
  one author, not independent corroboration. The canonicalizer it uses is
  maintained by this lab as well.
- **The join / the verdict recomputed from each record's own check list rather
  than taken from the harness; `verify.ts` and `validate.py`; Mode A;
  author-produced; the runners themselves.** Authorship relationship: the rule
  and its restatement in the runner were written together in this lab. This
  entry is a consistency check on the record, not a second opinion about it.
- **Negative controls / each control diverges on exactly its declared record set
  and changes exactly its declared verdict set; `verify.ts` and `validate.py`;
  Mode A; author-produced; the control policies in `harness.ts` and
  `validate.py`.** Authorship relationship: the declared sets and the control
  policies were written together in this lab. One declared set was corrected
  during the run after the runner reported an entry the prediction had missed.
- **SDK claim 1, chain verdict under the projected revocation answer / the SDK
  never answers valid for a boundary this family does not call valid;
  `sdk-bridge.ts`; Mode B; author-produced; `agent-passport-system` 7.1.0
  (npm).** Authorship relationship: the bridge and the vectors are this lab's,
  and this lab also maintains the SDK being exercised.
- **SDK claim 1 / the same, recomputed by the second reference SDK;
  `sdk_bridge.py`; Mode B; author-produced; `agent-passport-system` 4.1.0
  (PyPI).** Authorship relationship: as above.
- **SDK claims 2, 3 and 5 / a declared scope or purpose checked as its own facet
  places each vector on the same side as this family, with one recorded
  divergence; `sdk-bridge.ts` and `sdk_bridge.py`; Mode B; author-produced;
  both reference SDKs.** Authorship relationship: as above.
- **SDK claim 4 / both SDKs verify a composition-check receipt carrying this
  family's per-check results, echo them without aggregating, and downgrade a
  self-declared independence the trust context does not back; `sdk-bridge.ts`
  and `sdk_bridge.py`; Mode B; author-produced; both reference SDKs.**
  Authorship relationship: as above. The receipt shape and the trust context are
  the SDKs' own, and the projection from this family's three check results onto
  the SDKs' four-member enum is the bridge's.
- **SDK claim 4, cross-language / one pinned Ed25519 signature over the same
  receipt matches in both packages; `sdk-bridge.ts` and `sdk_bridge.py`; Mode B;
  author-produced; both reference SDKs.** Authorship relationship: as above.
  What this establishes is byte agreement between the two packages'
  canonicalizers and domain tags, not that either is correct.
- **SDK claim 6 / partial support, with the supported half exercised and the
  missing half named; `sdk-bridge.ts`; Mode B; author-produced;
  `agent-passport-system` 7.1.0 (npm).** Authorship relationship: as above.
- **SDK claims 7 to 10, and claims 2, 5 and 6 on the Python side / recorded
  not_supported with the missing API named and the absence asserted against the
  installed package; `sdk-bridge.ts` and `sdk_bridge.py`; Mode A;
  author-produced; both reference SDKs.** Authorship relationship: as above. A
  not_supported entry records an absence, not a verification.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## What a pass establishes

- The reference decision procedure, as stated in **The one idea** above, produces
  the pinned verdict and the pinned record bytes for all forty-three boundaries,
  in two implementations, with RFC 8785 digests that agree across languages.
- Each of the fourteen single-axis changes diverges on exactly the set declared
  for it, so a divergence is attributable to the named axis and not to anything
  else in the boundary.
- No boundary whose declared verdict is `invalid` or `not established` comes out
  `valid`, checked as its own assertion.
- No check resolves to `established_valid` on a basis naming an absent record.
- The verdict at each boundary is the join of that record's own check list,
  recomputed from the record.
- A later boundary references the earlier record by digest, and the earlier
  record's digest is unchanged after the later boundary ran.
- Both reference SDKs, given the narrowest projection of each verdict onto their
  single revocation answer, never answer valid where this family does not.

## What a pass does not establish

- That any of this is specification text. Every vector is
  candidate_against_proposed, and the text it tests is marked proposed in its own
  repository.
- That `aac.credential-event-record.v0` is the record shape a specification will
  adopt. It is this fixture's working definition.
- That the thirteen checks are the right set, or that a real deployment's policy
  would declare them. They are the smallest set that makes the sixteen cases
  decidable from records.
- That the synthetic event records correspond to anything a real system emits.
  No protocol is spoken and no network call is made.
- Anything about the incidents in the Sources section beyond the quoted
  sentences. The quotes establish that the situation each case describes has
  occurred. They say nothing about AI agents, and no legal doctrine is claimed to
  apply to one.
- That the attested facts a check reads are true. `reachable_scope_attestation`
  is believed because an attestor with declared standing signed it. Whether the
  network is actually segmented that way is outside every record here.

## Where the proposed text was too vague to test

This is a finding of the fixture, not a caveat on it. Seven places where the text
at `7796e22` and the cases at `2bf5c7e` do not decide an outcome, so the fixture
had to choose and label the choice.

1. **A check with no record has no declared outcome.** The text distinguishes
   what a verifier could establish from what is currently true, and L7 rules
   unavailable and stale revocation answers. Nothing says what a boundary
   returns when a check its policy requires has no input record at all. `not
   established` and `invalid` are both defensible, and they differ in what a
   caller may do next. This fixture returns `not established` throughout, which
   is the reading the Distinguish-false-from-not-established rule implies, and
   the text should say so, because `skip-unestablished-checks` is a coherent
   implementation under the text as written.

2. **Reach has no declared basis.** L12 says a completeness claim needs a defined
   basis for which set was complete. It does not say what a compromise-reach
   claim is computed over. This fixture uses a declared authority graph with a
   `could_mint_credentials_for` edge, which is the only basis under which
   LC-D-004 is decidable at all. Who declares that graph, and what makes an edge
   belong in it, the text does not say. Without an answer, LC-D-003 and LC-D-004
   are testable only against a basis the fixture invented.

3. **What standing a compromise disclosure needs is not stated.** LC-D-001's
   trigger comes from the compromised party itself. This fixture treats a
   disclosure from a party with declared standing as a trigger and one without as
   a recorded claim that is not a trigger. Whether a party has inherent standing
   to report its own compromise, whether a regulator or a monitor has it, and
   whether a verifier may act on an unattributed report, are all open. LC-D-001-c
   is the vector that will change if the text decides differently.

4. **No deadline shape for an inherited root.** LC-D-011 turns on a
   re-attestation deadline. The Verifier trust policy concept names which roots a
   verifier accepts and says nothing about a root that entered the policy by
   inheritance, let alone a deadline for re-establishing it. The deadline in
   `LC-D-011-a` and `-b` is a number this fixture made up. What the text needs to
   say is whether a deadline exists at all, and what the boundary returns before
   and after it.

5. **Revocation effectiveness is not modelled anywhere.** L8 distinguishes
   suspension from revocation as two states an implementation can produce. The
   text assumes both are producible. LC-F-035 is about a credential class for
   which neither can be produced early. This fixture returns `valid` with a
   `revocation_effectiveness` block saying the revocation is `not yet effective`
   until the credential's own expiry. The other defensible reading returns
   `invalid` and is what an operator who called a revocation API would expect. The
   two differ on what a holder-side verifier should do, and the text does not
   choose. The SDK run makes the cost concrete: neither reference SDK can express
   the difference, so both boundaries of LC-F-035 look identical to them.

6. **A clock disagreement has no place in the vocabulary.** L10 separates expiry
   from revocation. Nothing names a third condition where the verifier's own
   clock is the thing in question. This fixture returns `not established` with
   reason `clock_disagreement_beyond_tolerance` and records the skew and the
   tolerance, and it says explicitly that the artifact is not invalidated. Whether
   the settled vocabulary should gain a term for this, or whether `not
   established` with a reason code is enough, is a decision the text has to make
   before two implementations can agree.

7. **A credential that was never given a bound has no record to check.** This is
   the residue of LC-D-010 and LC-D-034 named in the coverage table. The cases
   are about a purpose-bound credential that was never given an expiry, and the
   absence of a bound is not an event a boundary can read. Making it decidable
   needs an issuance-time rule, something like "a grant issued for a stated
   purpose carries an expiry or is not established", which is a statement about
   issuance rather than about verification. The text has no issuance-side
   invariant of that shape, and this fixture did not invent one.

An eighth, smaller one. The text says a verdict follows from what a verifier can
establish and does not say in what order checks are evaluated or how their
results combine. This fixture fixes a precedence (`established_invalid` over
`not_established` over `valid`) and reports which check carried the verdict. A
different precedence would change no verdict in this family, because no vector
has both an `established_invalid` and a `not_established` check except
`LC-D-025-a`, which is the vector that shows why the record has to carry both
results rather than only the join.

## Boundary

A run of this family does not establish:

- anything about a real revocation service, a real status list, a real
  transparency log, a real gateway or any protocol.
- that the synthetic subjects (`lce-principal`, `lce-integrator`, `lce-agent`,
  `lce-operator`) are representative of how authority is deployed. They are the
  smallest set that makes an implicit ancestor distinguishable from a chain
  ancestor.
- that the projection from this family's verdicts onto the SDKs' single
  revocation answer is the projection a deployment should use. It is the only one
  the SDK vocabulary allows, which is itself a finding recorded in `SDK-RUNS.md`.
- that the three COVERED cases are covered by anything merged. Both fixtures
  named in the coverage table are candidate families on local branches, not text
  on `main`.
