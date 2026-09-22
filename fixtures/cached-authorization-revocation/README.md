# cached-authorization-revocation

Candidate cases for revocation enforcement at an MCP server's authorization
boundary, written against proposed text that has not merged.

Every case here is a candidate against that text. None of them is a conformance
claim, about MCP or about anything else, and if the proposal changes or is
closed the cases go with it.

## Source

| field | value |
|---|---|
| repository | `OWASP/www-project-mcp-top-10` |
| pull request | #63 |
| head SHA read | `89fd8d9d` |
| file | `2025/MCP07-2025–Insufficient-Authentication&Authorization.md` |
| status | **proposed, not merged** |

Read from that head: the mitigation bullets added under token handling,
Scenario 5 (revocation bypassed by cached authorization), and the five numbered
checks under "Validating Revocation Enforcement".

The text is a draft in review. It is paraphrased throughout this family rather
than quoted, and the head SHA is recorded so a later reader can tell which
revision the cases were built against. A case that stops matching the source
after an edit to the pull request is a stale case, not a finding.

## Case

Nine timeline cases in `vectors.json`. Each is a list of events, such as a grant
issued, an authorized call, a cache warmed, a grant revoked with its
acknowledgement time, a call on a retained session, a call after reconnecting, a
call on a second worker, the authority taken offline and the clock advanced. Each
call carries the outcome the source requires: allowed or denied,
`downstream_reached` true or false, and a reason.

Two parameters stand in for the limits a deployment defines:

| parameter | value | meaning |
|---|---|---|
| `propagation_limit_ms` | 5000 | maximum delay between a revocation being acknowledged and denial of subsequent protected operations |
| `freshness_limit_ms` | 2000 | maximum age of a cached authorization decision usable without consulting the authority |

Expected outcomes follow from the source's rules **together with these declared
limits**. That matters in two places. `CAR-03-r2` is denied 2101 ms after
acknowledgement, well inside the propagation limit: the source does not require
denial that early, the declared freshness limit does. `CAR-04-r4` is a call on a
grant that was never revoked, and it must still reach the authority, because its
cached decision is past the freshness limit. Naming the limits is what makes
those two determinate instead of a matter of taste.

| case | covers | what it exercises |
|---|---|---|
| `CAR-01-warm-cache-and-independent-grant` | check 1 | an authorized call warms the caches, a second call is served inside the freshness limit, and an independent grant performs its own operation |
| `CAR-02-revoked-credential-across-reuse-surfaces` | check 2 | after revocation and past the propagation limit, the same credential on the retained session, after reconnecting, and on a second worker, while the independent grant still works |
| `CAR-03-denied-before-downstream-after-propagation-limit` | check 3 | denial past the freshness limit and again past the propagation limit, with the downstream test double recording no attempt for either |
| `CAR-04-independent-grant-unaffected-by-revocation` | check 3 | the independent grant, warmed before the revocation, still performs its operation afterwards |
| `CAR-05-inside-propagation-window-residual-exposure` | check 3 | a call 400 ms after acknowledgement, inside the window, recorded as residual exposure |
| `CAR-06-revocation-acknowledged-after-tool-executed` | check 3 | a denial returned to the caller after the downstream double already recorded the operation |
| `CAR-07-authority-unavailable-beyond-freshness-limit` | check 4 | the authority taken offline after warming, served inside the freshness limit, denied past it, downstream never reached |
| `CAR-08-audit-correlation-without-credentials` | check 5 | correlation fields per call, and no credential values in the trail |
| `CAR-09-unresolvable-grant-state-is-denied` | stated principle | a grant with no usable state is denied, cold and after a cached allow existed |

`CAR-09` is not one of the five numbered checks. The source states it as a
principle in its mitigation text: an unexpired token or an existing session is
not proof that access is still authorized, and a protected operation is denied
rather than continued on an old allow decision when freshness cannot be
established. A grant state that cannot be resolved is therefore a denial, never
an allow by default.

### Where the source does not determine an outcome

`CAR-05-r2` is made 400 ms after acknowledgement, inside the propagation limit.
The source does not require that call to be denied. It asks that a successful
call inside the window be recorded as residual exposure. Its expected block
carries `outcome: unconstrained_by_source`, and the runner asserts the recording
instead of the outcome: every call it labels residual exposure must be one the
fixture declared, and every declared one that was allowed must be labelled.
Both directions.

The labelling is done by the runner from the timeline's own ground truth, not by
the implementation under test. An enforcement point serving a stale cached allow
does not know it is inside a propagation window, and asking it to say so would
be asking the defect to report itself.

## Controls

`CAR-01` is the family's positive control: no revocation appears anywhere in its
timeline, so it establishes that the allow path works before anything is taken
away. `CAR-02-r6` and `CAR-04` are the independent-grant controls the source's
checks 1 and 3 call for. Revoking one grant must not deny an unrelated one.

Negative cases isolate one defect: a cached authorization decision that keeps
answering after the grant behind it is gone.

## Failure stage

Every denial in this family is expected **before downstream execution**. The
harness carries a downstream test double that records attempted operations, and
`downstream_reached` is read from that record rather than from anything the
enforcement point reports about itself. A denial with an attempt recorded
against the double is a different event from a denial with none, and the
fixture distinguishes them.

`CAR-06` is the case where that distinction is the whole point. The call is
authorized, the double records the operation, the grant is then revoked, and the
enforcement point returns a revocation error to the caller at response time. The
caller sees a denial. The tool already ran. The source says an error returned
after the tool has already executed is insufficient evidence of revocation
enforcement, so the case declares
`counts_as_revocation_enforcement_evidence: false` and the runner prints it as
excluded rather than counting it as a pass.

## Indeterminate cases

Three of the nine cases match under both implementations and are excluded from
the enforcement tally by declaration in `vectors.json`:

- `CAR-01`, a control with no revocation in it
- `CAR-05`, unconstrained by the source inside the propagation window
- `CAR-06`, a denial the source calls insufficient evidence

The runner prints two numbers that are deliberately not the same: how many cases
matched, and how many of those count as revocation-enforcement evidence. A case
that matches and establishes nothing is reported as exactly that.

Reasons are asserted exactly where the model determines them and as a set where
it does not. On a call whose cached decision is inside the freshness limit,
serving it and re-consulting the authority are both permitted, so the expected
block carries `reason_any_of` rather than a single value.

## Provenance

The vectors and the harness were both authored in this lab. Neither came from
the author of pull request #63, and nothing here was reviewed or endorsed by
them. The cases are one reading of proposed text by a party that did not write
it.

The harness is a reference model, not a tested MCP server. It implements a
synthetic enforcement point so the checks can be executed against something.
The runs record its behaviour and no one else's.

The vectors are hand-authored timelines with no generation step. They are fully
deterministic. The clock is synthetic and nothing reads wall time, touches the
network, or uses randomness, so replaying the runner is the reproduction.

## Running

From the repository root:

    npm ci --include=dev
    npm run verify:cached-authorization-revocation

It also runs as the last step of `npm test`.

The runner replays all nine cases against a reference harness and a deliberately
stale-cache variant of it, used as a negative control. They differ only in their
cache policy. Neither is an independent implementation, and neither result is a
verdict on any real server:

- `correct` is the reference harness. It keeps a bounded cache lifetime, refuses a cached decision past the
  freshness limit, consults the authority, and denies when freshness cannot be
  established
- `stale-cache` is the negative control. It serves any cached allow it holds for the session, which is
  the behaviour Scenario 5 describes

`correct` must match every expected outcome. `stale-cache` must fail exactly the
cases the fixture declares it fails, checked in both directions: an undeclared
failure appearing and a declared failure quietly starting to pass are both loud.
That second half is what the family is for. Vectors a known defect also
satisfies do not discriminate, so the defective implementation is run on purpose
and its failures are pinned by name:

    CAR-02  CAR-03  CAR-04  CAR-07  CAR-08  CAR-09

`CAR-01`, `CAR-05` and `CAR-06` pass under both, by construction, for the
reasons given above.

Expected final line:

    PASSED: correct matched every case, stale-cache failed exactly the declared set

## Audit checks

Check 5's assertions run over every case's audit trail, not only over `CAR-08`.
Each record must carry the request, grant, client, session, worker, operation,
decision, reason, downstream outcome, revocation identifier and decision time,
and the correlation field must equal the acknowledged revocation for that grant at
decision time and be null when there is none, and no credential value may appear
anywhere in the serialized trail.

The scan has something real to fail on. The grant credentials and the refresh
credential sit in the enforcement point's grant registry, and the downstream
credential is handed to the test double on every allowed call. A writer that
serialized the grant record would put those values in the trail.

`CAR-08` cites check 5 because its timeline is the one built to exercise
correlation: a record decided before the revocation is acknowledged, a record
decided after it, and a record for a grant with no revocation at all.

The revocation identifier written into an audit record is read from the
revocation ledger, not from the authorization path. That is a modelling
decision and worth stating: a deployment's audit pipeline holds the revocation
record whether or not the enforcement point consulted the authority for that
call. Sourcing it from the authorization path would make check 5 fail for the
same reason check 2 fails, and the two would stop being separate observations.

## Boundary

A run of this family does not establish:

- anything about a real MCP server. No MCP server is started, no protocol is
  spoken, and nothing is tested over a wire.
- anything about an OAuth authorization server, a token introspection endpoint,
  or a remote policy service. The authority here is an in-process test double.
- that access tokens, refresh tokens or downstream credentials behave as
  modelled. No token is minted, signed, presented or validated. A grant is an
  identifier with a state.
- that the source's text is correct, complete, or will merge in this form.
- cancellation or rollback of work already in progress. The source says that
  needs separate application-specific controls, and this family does not attempt
  it. `CAR-06` exercises the boundary of that gap, not a control for it.
- that any particular propagation or freshness limit is the right one. 5000 ms
  and 2000 ms are fixture parameters, not a recommendation.

One more limit, on the modelled design. The source permits an enforcement point
to **either** invalidate cached authorization decisions on revocation **or**
bound their lifetime to meet the propagation limit. This family models the
second. An invalidation-based implementation with a longer cache lifetime for
grants that were never revoked could be compliant with the source and still not
match the `reason` values these cases expect on cache-served allows --
`CAR-04-r4` is where that would show. Those cases would need their own
parameters and their own expected reasons, and they are not here.

What a passing run does record is narrower than any of that: for this reference
model at this revision, the cases separate a bounded-lifetime authorization
cache from one that keeps answering after the grant behind it is gone, and they
name which cases do the separating and which do not.
