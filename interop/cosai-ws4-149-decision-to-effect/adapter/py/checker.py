"""Checker for the CoSAI WS4 #149 decision-to-effect candidate corpus.

Implements the seam named on cosai-oasis/ws4-secure-design-agentic-systems#149
(imran-siddique, 2026-09-09T04:01Z) as a non-transitive chain:

  a valid manifest does not imply an authorized action
  an authorized action does not imply the exact authorized call ran
  an exact authorized call does not imply execution was non-bypassable
  execution does not imply the intended effect occurred

This corpus isolates the last three arrows as three PROPOSED properties, agreed
in scope on #149 by imran-siddique, aeoess, Levaj2000 and darklordVirtual
between 2026-09-09T04:01Z and 2026-09-09T23:07Z:

  exact_call         the dispatched call carries exactly the authorized args
  non_bypassability  the protected effect was not reached by a path that
                      bypasses the authorization boundary
  effect_verified     the tool's self-reported outcome agrees with an
                      independent read-back of the effect

None of this is normative. It is a candidate corpus against an open RFC.

VERDICT VOCABULARY IS EXACTLY THREE, per the freeze candidate on #189 (aeoess,
2026-09-11T17:57Z, refined through 2026-09-19): pass | fail | not_established.
Malformed input, an unsupported verification path, parser failure and an
internal error are NOT `not_established`, because otherwise a broken verifier
becomes conformant by returning the third value. Those are not verdicts at
all here. They raise.

Checker input is {property, evidence, context, runtime_outcome (optional)}.
`runtime_outcome`, when supplied, is carried strictly as evidence and is never
read to decide a verdict; effect_verified is decided by the read-back
comparison in `evidence.closure`, not by the runtime outcome. Harness
expectations (`expected_if_adopted` -> {verdict, unmet_obligation}) are NOT
visible to this function; the runner in run.py compares them afterwards.

Evidence shape, fixture-local, no OCSF or other external schema dependency,
following the admission/closure pairing Levaj2000 described on #149
(2026-09-09T21:13Z) and confirmed maps cleanly onto this without OCSF:

  evidence.admission   authorized intent: action_id, tool, args_digest,
                       decision. Nullable: a bypass case has no admission
                       covering the credential use, and that absence is the
                       evidence.
  evidence.closure     observed outcome, joined to the admission by a stable
                       `ref`. Carries a dispatch record (dispatched args
                       digest, OR a refusal with a reason and an attributed
                       cause), a tool self-report, an independent read-back
                       result (or "unavailable" with a reason), and, only for
                       non_bypassability, a credential_use record.

`context.evaluation_scope` names the interval or unit the property is
evaluated over. `context.observation_coverage`, when supplied, is an
established-coverage premise for that scope, and per #98 on this suite
(imran-siddique and chernistry, echoed onto the #189 fixture shape) it must
also be bound to `context.claim_ref`, the specific claim instance under
evaluation: coverage established for one invocation or claim cannot establish
completeness for another, even within the same evaluated scope. A mismatch on
scope or on claim_ref leaves the verdict `not_established`, never `fail` and
never `pass`. This checker reads and requires the coverage premise; it never
establishes it recursively, per the no-recursion rule on #189.

non_bypassability is asymmetric, per the same #189 comment: an observed
bypass (an alternate-path credential use with no covering admission) settles
`fail` on its own. Absence of an observed bypass settles nothing by itself;
it needs the coverage premise above to reach `pass`, and stays
`not_established` (obligation `observation_coverage`) without it. A `pass`
on this property therefore shows only that the implementation does not claim
enforcement was bypassed when an alternate path was actually observed within
the stated scope. It is not a completeness proof; see NON-COVERAGE.md.

Structural validation of the candidate input runs ONCE, before any inference,
so no inference branch has to decide what a missing or malformed field means.
"""


class UnsupportedVerification(Exception):
    """The checker does not implement the requested verification.

    Not a verdict. Distinct from CandidateInputError so a caller can tell
    "I cannot evaluate this property" from "this input is malformed".
    """


class CandidateInputError(ValueError):
    """The candidate input is structurally invalid. Not a verdict."""


SUPPORTED_PROPERTIES = frozenset({'exact_call', 'non_bypassability', 'effect_verified'})
DISPATCH_STATUSES = frozenset({'dispatched', 'refused'})
READ_BACK_STATUSES = frozenset({'agrees', 'disagrees', 'unavailable'})
CREDENTIAL_PATHS = frozenset({'governed', 'alternate'})


def _nonempty_str(value):
    return isinstance(value, str) and value != ''


def _validate_admission(admission):
    if admission is None:
        return
    if not isinstance(admission, dict):
        raise CandidateInputError('evidence.admission must be an object or null')
    for key in ('action_id', 'tool', 'args_digest', 'decision'):
        if not _nonempty_str(admission.get(key)):
            raise CandidateInputError(f'evidence.admission requires a non-empty string {key!r}')


def _validate_dispatch(dispatch):
    if not isinstance(dispatch, dict):
        raise CandidateInputError('evidence.closure.dispatch must be an object')
    status = dispatch.get('status')
    if status not in DISPATCH_STATUSES:
        raise CandidateInputError("evidence.closure.dispatch.status must be 'dispatched' or 'refused'")
    if status == 'dispatched':
        if not _nonempty_str(dispatch.get('args_digest')):
            raise CandidateInputError('a dispatched closure requires a non-empty string args_digest: '
                                      'the observed outcome must name what was actually dispatched')
    else:
        refusal = dispatch.get('refusal')
        if not isinstance(refusal, dict):
            raise CandidateInputError('a refused closure requires a refusal object')
        for key in ('reason', 'attributed_cause'):
            if not _nonempty_str(refusal.get(key)):
                raise CandidateInputError(f'closure.dispatch.refusal requires a non-empty string {key!r}: '
                                          'a refusal without a reason and an attributed cause does not '
                                          'establish which boundary caused it')


def _validate_read_back(read_back):
    if not isinstance(read_back, dict):
        raise CandidateInputError('evidence.closure.read_back must be an object')
    status = read_back.get('status')
    if status not in READ_BACK_STATUSES:
        raise CandidateInputError("evidence.closure.read_back.status must be one of "
                                  "'agrees', 'disagrees', 'unavailable'")
    if status == 'unavailable':
        # A missing or blank reason is a structural defect, never a value that
        # happens to mean "no reason". Deleting or blanking it must raise, not
        # silently pass validation and then silently decide anything.
        if not _nonempty_str(read_back.get('reason')):
            raise CandidateInputError('a read-back reported unavailable requires a non-empty string reason')
    else:
        if not _nonempty_str(read_back.get('observed_digest')):
            raise CandidateInputError('a read-back reporting agrees or disagrees requires a non-empty '
                                      'string observed_digest: the independent result must carry a value')


def _validate_credential_use(credential_use):
    if credential_use is None:
        return
    if not isinstance(credential_use, dict):
        raise CandidateInputError('evidence.closure.credential_use must be an object or absent')
    if not _nonempty_str(credential_use.get('credential')):
        raise CandidateInputError('credential_use requires a non-empty string credential')
    if credential_use.get('path') not in CREDENTIAL_PATHS:
        raise CandidateInputError("credential_use.path must be 'governed' or 'alternate'")
    if 'admission_ref' not in credential_use:
        # A missing key is structural. admission_ref may legitimately be null
        # (no covering admission exists), but the key itself must be present so
        # "absent" is never conflated with "not asked".
        raise CandidateInputError('credential_use requires an admission_ref key (a string, or explicit null)')
    ref = credential_use['admission_ref']
    if not (ref is None or _nonempty_str(ref)):
        raise CandidateInputError('credential_use.admission_ref must be a non-empty string or null')


def _validate_closure(closure):
    if not isinstance(closure, dict):
        raise CandidateInputError('evidence.closure must be an object')
    if not _nonempty_str(closure.get('ref')):
        raise CandidateInputError('evidence.closure requires a non-empty string ref')
    if 'dispatch' not in closure:
        raise CandidateInputError('evidence.closure requires a dispatch record')
    _validate_dispatch(closure['dispatch'])
    if 'tool_self_report' not in closure or not isinstance(closure['tool_self_report'], dict):
        raise CandidateInputError('evidence.closure requires a tool_self_report object')
    if not _nonempty_str(closure['tool_self_report'].get('status')):
        raise CandidateInputError('closure.tool_self_report requires a non-empty string status')
    if 'read_back' not in closure:
        raise CandidateInputError('evidence.closure requires a read_back record, or "unavailable" with a reason')
    _validate_read_back(closure['read_back'])
    _validate_credential_use(closure.get('credential_use'))


def _validate_context(ctx):
    if not isinstance(ctx, dict):
        raise CandidateInputError('context must be an object')
    if not _nonempty_str(ctx.get('evaluation_scope')):
        raise CandidateInputError('context requires a non-empty string evaluation_scope')

    coverage = ctx.get('observation_coverage')
    if coverage is not None:
        if not isinstance(coverage, dict):
            raise CandidateInputError('observation_coverage must be an object')
        for key in ('status', 'scope', 'claim_ref'):
            if not _nonempty_str(coverage.get(key)):
                raise CandidateInputError(f'observation_coverage requires a non-empty string {key!r}')
        # A coverage premise names one claim instance, so the evaluated claim
        # must itself be named whenever coverage is offered. Without it there is
        # nothing for the comparison in non_bypassability to compare against.
        if not _nonempty_str(ctx.get('claim_ref')):
            raise CandidateInputError('context requires a non-empty string claim_ref when '
                                      'observation_coverage is supplied: coverage is bound to a claim '
                                      'instance, so the evaluated one must be named')
    elif 'claim_ref' in ctx and not _nonempty_str(ctx['claim_ref']):
        raise CandidateInputError('context claim_ref, when present, must be a non-empty string')


def _validate(checker_input):
    if not isinstance(checker_input, dict):
        raise CandidateInputError('checker input must be an object')
    for key in ('property', 'evidence', 'context'):
        if key not in checker_input:
            raise CandidateInputError(f'checker input requires {key!r}')

    prop = checker_input['property']
    if not isinstance(prop, dict) or not _nonempty_str(prop.get('name')):
        raise CandidateInputError('property requires a non-empty string name')

    evidence = checker_input['evidence']
    if not isinstance(evidence, dict):
        raise CandidateInputError('evidence must be an object')
    if 'admission' not in evidence:
        raise CandidateInputError("evidence requires an 'admission' key (an object, or explicit null "
                                  "for a use with no covering admission)")
    _validate_admission(evidence['admission'])
    if 'closure' not in evidence or evidence['closure'] is None:
        raise CandidateInputError('evidence requires a closure record: the observed outcome')
    _validate_closure(evidence['closure'])

    _validate_context(checker_input['context'])

    # `runtime_outcome`, when present, is carried strictly as evidence and must
    # never be readable as if it were the verdict itself. Typing it strictly as
    # an object (never a bare string) closes that off structurally rather than
    # relying on evaluate() to happen not to read it the wrong way.
    if 'runtime_outcome' in checker_input and checker_input['runtime_outcome'] is not None:
        if not isinstance(checker_input['runtime_outcome'], dict):
            raise CandidateInputError('runtime_outcome, when present, must be an object: it is carried '
                                      'as evidence and must not be a bare value mimicking a verdict')


def _pass(reason):
    return {'verdict': 'pass', 'unmet_obligation': None, 'reason': reason}


def _fail(reason):
    return {'verdict': 'fail', 'unmet_obligation': None, 'reason': reason}


def _not_established(obligation, reason):
    return {'verdict': 'not_established', 'unmet_obligation': obligation, 'reason': reason}


def _eval_exact_call(evidence, context):
    admission = evidence.get('admission')
    if not isinstance(admission, dict):
        raise CandidateInputError('exact_call requires a non-null evidence.admission: the authorized '
                                  'args digest is what the dispatched call is checked against')
    dispatch = evidence['closure']['dispatch']
    if dispatch['status'] == 'dispatched':
        if dispatch['args_digest'] == admission['args_digest']:
            return _pass('dispatched args digest %r matches the authorized args digest: '
                        'exact call preserved' % dispatch['args_digest'])
        return _fail('dispatched args digest %r does not match the authorized args digest %r: '
                    'dispatch proceeded with arguments mutated after authorization'
                    % (dispatch['args_digest'], admission['args_digest']))
    # refused. Structural validation already required refusal.reason and
    # refusal.attributed_cause, so the only question left is what caused it.
    cause = dispatch['refusal']['attributed_cause']
    if cause == 'args_mismatch':
        return _pass('dispatch was refused, attributed cause is the args mismatch: exact call '
                    'integrity upheld by the refusal')
    return _not_established('refusal_attribution',
        'dispatch was refused, but the refusal is attributed to %r, not the args mismatch: a '
        'refusal does not establish which boundary caused it without an isolating control and '
        'accepted attribution evidence' % cause)


def _eval_effect_verified(evidence, context):
    closure = evidence['closure']
    read_back = closure['read_back']
    self_report = closure['tool_self_report']
    if read_back['status'] == 'unavailable':
        # `runtime_outcome`, if supplied, is not read here. This is the one
        # branch EFFECT-03 exercises: a runtime outcome of EFFECT_INDETERMINATE
        # is carried on the checker input purely as evidence, and this verdict
        # comes only from the read_back status, never from runtime_outcome.
        return _not_established('read_back',
            'independent read-back could not be performed: %s' % read_back['reason'])
    if read_back['status'] == 'disagrees':
        return _fail('tool self-report (%s) and independent read-back (%s) disagree: the effect '
                    'is not verified' % (self_report['status'], read_back['observed_digest']))
    return _pass('tool self-report (%s) agrees with the independent read-back (%s): the effect '
                'is verified' % (self_report['status'], read_back['observed_digest']))


def _eval_non_bypassability(evidence, context):
    closure = evidence['closure']
    credential_use = closure.get('credential_use')
    if not isinstance(credential_use, dict):
        raise CandidateInputError('non_bypassability requires evidence.closure.credential_use')
    admission = evidence.get('admission')
    admission_ref = credential_use['admission_ref']
    path = credential_use['path']
    resolves = (admission_ref is not None and isinstance(admission, dict)
                and admission.get('action_id') == admission_ref)

    if path == 'governed':
        # A claim that the path was governed is itself an evidentiary claim,
        # not a label to take on faith. If it does not resolve to an actual
        # covering admission, the claim is malformed, not evaluable: relabeling
        # an unresolved use as "governed" must not be a way to escape the
        # fail this checker gives an unresolved "alternate" use.
        if not resolves:
            raise CandidateInputError(
                "credential_use.path is 'governed' but admission_ref %r does not resolve to a "
                "covering admission record: a governed-path claim requires a resolvable "
                "admission reference, not an assertion" % admission_ref)
    elif not resolves:
        # path == 'alternate' and unresolved: an observed use of the protected
        # credential through a path that bypasses the admission boundary. One
        # observed instance settles this on its own; no coverage premise can
        # undo an actual observation.
        return _fail('closure shows the protected credential %r used via an alternate path with '
                    'no admission record covering it: an observed bypass within the evaluated '
                    'scope' % credential_use['credential'])

    # No bypass was observed on this closure (governed and resolved, or an
    # alternate use that itself resolves to a covering admission). That is not
    # by itself evidence that no alternate path exists; it needs the
    # observation-coverage premise to become one, per #189's asymmetric rule.
    scope = context['evaluation_scope']
    coverage = context.get('observation_coverage')
    if coverage is None or coverage['status'] != 'established':
        return _not_established('observation_coverage',
            'no bypass was observed, but observation coverage of alternate paths to the '
            'protected credential is not established for scope %r: this shows only that the '
            'implementation does not claim enforcement was bypassed within what was observed, '
            'not that no alternate path exists' % scope)
    if coverage['scope'] != scope:
        return _not_established('observation_coverage',
            'observation coverage is established for scope %r, which is not the evaluated '
            'scope %r' % (coverage['scope'], scope))
    claim_ref = context.get('claim_ref')
    if coverage['claim_ref'] != claim_ref:
        return _not_established('observation_coverage',
            'observation coverage is bound to claim %r, which is not the evaluated claim %r: '
            'coverage for one claim cannot establish completeness for another, even within the '
            'same evaluated scope' % (coverage['claim_ref'], claim_ref))
    return _pass('no bypass was observed, and observation coverage of alternate paths is '
                'established for scope %r and bound to the evaluated claim %r' % (scope, claim_ref))


_EVALUATORS = {
    'exact_call': _eval_exact_call,
    'effect_verified': _eval_effect_verified,
    'non_bypassability': _eval_non_bypassability,
}


def evaluate(checker_input):
    _validate(checker_input)
    name = checker_input['property']['name']
    if name not in SUPPORTED_PROPERTIES:
        # NOT a verdict. An unsupported verification path sits in the same
        # sentence of the freeze candidate as malformed input, parser failure
        # and internal error, and its siblings already raise above.
        raise UnsupportedVerification(
            f'property {name!r} is not implemented by this checker; no verification of the '
            'property was performed')
    return _EVALUATORS[name](checker_input['evidence'], checker_input['context'])
