"""Checker for the CoSAI WS4 #189 evidence-sufficiency freeze candidate.

Implements the rule as stated in the freeze-candidate comment on
cosai-oasis/ws4-secure-design-agentic-systems#189 (2026-09-11), which is a
PROPOSED rule, not a normative one:

  Where declared capability and gating establish that the producer would have
  emitted the field for the evaluated event, an absent field is evidence of
  absence and can support the narrow property. Where that production coverage
  was never established, the same missing field is absence of evidence. The
  verdict is `not_established` and the obligation is
  `producer_capability_coverage`. Absence only counts when the coverage that
  would have produced the evidence is established.

Two premises, kept apart. `producer_capability_coverage` is field visibility for
a processed invocation. `observation_coverage` is completeness of the evaluated
interval, required for a negative quantified over a session, supplied as context
by a separate verifier surface and never verified recursively here.

Checker input is {property, evidence, context, runtime_outcome}. Harness
expectations (expected_verdict, expected_unmet_obligation) are NOT visible to
this function; the runner compares them afterwards.

VERDICT VOCABULARY IS EXACTLY THREE: pass | fail | not_established. The same
freeze candidate states that malformed input, an unsupported verification path,
parser failure and an internal error are NOT `not_established`, because
otherwise a broken verifier becomes conformant by returning the third value.
Those four are therefore not verdicts at all here. They raise.

Structural validation of the candidate input runs ONCE, before any inference.
Inference never decides what a missing descriptor means.
"""


class UnsupportedVerification(Exception):
    """The checker does not implement the requested verification.

    Not a verdict. Distinct from CandidateInputError so a caller can tell
    "I cannot evaluate this property" from "this input is malformed".
    """


class CandidateInputError(ValueError):
    """The candidate input is structurally invalid. Not a verdict."""


SUPPORTED_PROPERTIES = frozenset({'no_delegation_occurred'})
REQUIRED_DESCRIPTOR_KEYS = ('present', 'gated_on')


def _validate(checker_input: dict) -> None:
    """Structural gate. Everything inference relies on is checked here, so no
    inference branch has to decide what an absent key means."""
    if not isinstance(checker_input, dict):
        raise CandidateInputError('checker input must be an object')
    for key in ('property', 'evidence', 'context'):
        if key not in checker_input:
            raise CandidateInputError(f'checker input requires {key!r}')

    prop = checker_input['property']
    if not isinstance(prop, dict) or not isinstance(prop.get('name'), str):
        raise CandidateInputError('property requires a string name')

    evidence = checker_input['evidence']
    if not isinstance(evidence, dict):
        raise CandidateInputError('evidence must be an object of field descriptors')
    for name, desc in evidence.items():
        if not isinstance(desc, dict):
            raise CandidateInputError(f'evidence.{name} must be a descriptor object')
        for k in REQUIRED_DESCRIPTOR_KEYS:
            # A MISSING descriptor key is a structural defect, never an
            # evidential state. Defaulting a missing `gated_on` to "ungated"
            # let deletion of the key move a verdict to pass, a fail-open.
            if k not in desc:
                raise CandidateInputError(f'evidence.{name} requires {k!r}; '
                                          'a missing descriptor key is not a value')
        if not isinstance(desc['present'], bool):
            raise CandidateInputError(f'evidence.{name}.present must be a bool')
        gate = desc['gated_on']
        # Accepted forms: a capability string, or explicit null for ungated.
        if not (gate is None or isinstance(gate, str)):
            raise CandidateInputError(f'evidence.{name}.gated_on must be a capability '
                                      'string or explicit null')

    ctx = checker_input['context']
    if not isinstance(ctx, dict):
        raise CandidateInputError('context must be an object')
    declared = ctx.get('producer_declared_capabilities')
    # None means unknown (never declared); [] means an explicit empty
    # declaration. Both fail to establish coverage for a gated field, but they
    # are recorded distinctly because the author drew the distinction.
    if not (declared is None or isinstance(declared, list)):
        raise CandidateInputError('producer_declared_capabilities must be a list or null')

    # The property is quantified over an interval, so the interval has to be
    # declared. Without it there is nothing for a completeness premise to be
    # about, and `observation_coverage` becomes an unbound assertion.
    if not isinstance(ctx.get('evaluation_scope'), str) or not ctx['evaluation_scope']:
        raise CandidateInputError('context requires a non-empty string evaluation_scope: '
                                  'a negative quantified over an interval must name the interval')

    # `observation_coverage` is an inference input, so it is validated here like
    # every other one. A descriptor that reaches inference half-formed is how the
    # premise stops being load-bearing.
    coverage = ctx.get('observation_coverage')
    if coverage is not None:
        if not isinstance(coverage, dict):
            raise CandidateInputError('observation_coverage must be an object')
        for k in ('status', 'scope'):
            if not isinstance(coverage.get(k), str) or not coverage[k]:
                raise CandidateInputError(f'observation_coverage requires a non-empty '
                                          f'string {k!r}')


def evaluate(checker_input: dict) -> dict:
    _validate(checker_input)

    prop = checker_input['property']
    evidence = checker_input['evidence']
    ctx = checker_input['context']
    declared = ctx.get('producer_declared_capabilities')

    if prop['name'] not in SUPPORTED_PROPERTIES:
        # NOT a verdict. An unsupported verification path sits in the same
        # sentence of the freeze candidate as malformed input, parser failure
        # and internal error, and its three siblings already raise here.
        raise UnsupportedVerification(
            f'property {prop["name"]!r} is not implemented by this checker; '
            'no verification of the property was performed')

    field = evidence.get('delegation')
    if field is None:
        return {'verdict': 'not_established', 'unmet_obligation': 'evidence_field_declared',
                'reason': 'evidence carries no delegation field descriptor'}

    # OUTCOMES ARE ASYMMETRIC, and this is the whole reason the paths converge.
    # One observed event is a witness and settles `fail` on its own. A NEGATIVE
    # quantified over an interval is never settled by one record, whether the
    # record is an empty delegation block or an absent one. Both no-event paths
    # therefore fall through to the same completeness requirement below.
    if field['present']:
        value = field.get('value')
        if not isinstance(value, dict):
            raise CandidateInputError('present delegation evidence requires an object value')
        if 'events' not in value or not isinstance(value['events'], list):
            raise CandidateInputError('present delegation evidence requires value.events list')
        events = value['events']
        if events:
            return {'verdict': 'fail', 'unmet_obligation': None,
                    'reason': 'delegation block present with %d event(s); one witness settles '
                              'the positive and needs no completeness premise' % len(events)}
        visibility = 'delegation block present and empty'
    else:
        gate = field['gated_on']
        if gate is not None and not (declared is not None and gate in declared):
            return {'verdict': 'not_established', 'unmet_obligation': 'producer_capability_coverage',
                    'reason': 'field gated on %r, producer declared %s: absence of evidence, not evidence of absence'
                              % (gate, 'nothing' if not declared else declared)}
        visibility = 'absent field, capability %s' % ('ungated' if gate is None else f'{gate} declared')

    # Capability establishes VISIBILITY, not COMPLETENESS, and the two are
    # separate premises for a negative quantified over a session.
    #
    # Source check against the modelled implementation, praxis-proxy/policy
    # 5b76fa6: `filter_extensions` clones the delegation slot into the sink's
    # view only when the capability is held, and that capability comes from the
    # sink's operator-controlled `plugins:` entry, fixed before the sink sees the
    # extensions. So a declared capability genuinely establishes that an absent
    # delegation block means no delegation was visible ON A PROCESSED
    # INVOCATION. The capability set is carried in no emitted record, which is
    # why it is context and not evidence.
    #
    # It says nothing about whether every relevant invocation in the session is
    # represented in the evaluated record set. A failing audit sink is logged and
    # skipped rather than failing the request, so a record can be lost. Praxis
    # tracks completeness separately with `epoch`, `stream_id` and dense
    # `stream_seq`, and dense sequence detects an internal gap without
    # establishing the boundaries of the evaluated interval.
    #
    # Per the freeze candidate, no recursion is needed: this checker READS AND
    # REQUIRES the premise, and a separate verifier surface establishes it.
    scope = ctx['evaluation_scope']
    coverage = ctx.get('observation_coverage')
    if coverage is None or coverage['status'] != 'established':
        return {'verdict': 'not_established', 'unmet_obligation': 'observation_coverage',
                'reason': '%s establishes visibility, but completeness of the evaluated '
                          'interval %r is not established: the negative is absence of evidence'
                          % (visibility, scope)}
    # Established for WHAT. A completeness premise that does not name the
    # evaluated interval, or names a smaller one, cannot authorise a negative
    # over that interval.
    if coverage['scope'] != scope:
        return {'verdict': 'not_established', 'unmet_obligation': 'observation_coverage',
                'reason': 'observation coverage is established for scope %r, which is not the '
                          'evaluated interval %r: the negative over the evaluated interval '
                          'remains absence of evidence' % (coverage['scope'], scope)}
    return {'verdict': 'pass', 'unmet_obligation': None,
            'reason': '%s, and observation coverage is established for the evaluated interval '
                      '%r; absence is evidence of absence' % (visibility, scope)}
