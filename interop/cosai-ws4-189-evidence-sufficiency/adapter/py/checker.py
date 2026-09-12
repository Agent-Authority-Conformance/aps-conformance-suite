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

Checker input is {property, evidence, context, runtime_outcome}. Harness
expectations (expected_verdict, expected_unmet_obligation) are NOT visible to
this function; the runner compares them afterwards.

Verdict vocabulary: pass | fail | not_established. This is the candidate's
own vocabulary and not a conformance verdict on any implementation.
"""


def evaluate(checker_input: dict) -> dict:
    prop = checker_input['property']
    evidence = checker_input['evidence']            # {field: {"gated_on": cap|None, "present": bool, "value": ...}}
    ctx = checker_input['context']
    # None means unknown (never declared); [] means an explicit empty
    # declaration. Both fail to establish coverage for a gated field, but they
    # are recorded distinctly because the author drew the distinction.
    declared = ctx.get('producer_declared_capabilities')
    if not (declared is None or isinstance(declared, list)):
        raise ValueError('producer_declared_capabilities must be a list or null')

    if prop['name'] != 'no_delegation_occurred':
        return {'verdict': 'not_established', 'unmet_obligation': 'checker_supports_property',
                'reason': f'property {prop["name"]!r} not implemented by this checker'}

    field = evidence.get('delegation')
    if field is None:
        return {'verdict': 'not_established', 'unmet_obligation': 'evidence_field_declared',
                'reason': 'evidence carries no delegation field descriptor'}
    if not isinstance(field.get('present'), bool):
        raise ValueError('evidence.delegation.present must be a bool')

    if field['present']:
        # A delegation block is present. The narrow property asks whether any
        # delegation event occurred in the session. Malformed present evidence
        # is a checker input error, never a verdict: #189 keeps not_established
        # apart from parser and malformed-input failures, and a missing events
        # member cannot prove zero events.
        value = field.get('value')
        if not isinstance(value, dict):
            raise ValueError('present delegation evidence requires an object value')
        if 'events' not in value or not isinstance(value['events'], list):
            raise ValueError('present delegation evidence requires value.events list')
        events = value['events']
        return {'verdict': 'fail' if events else 'pass',
                'unmet_obligation': None,
                'reason': 'delegation block present; events=%d' % len(events)}

    gate = field.get('gated_on')
    covered = (gate is None) or (declared is not None and gate in declared)
    if covered:
        return {'verdict': 'pass', 'unmet_obligation': None,
                'reason': 'production coverage established (%s), absent field is evidence of absence'
                          % ('ungated' if gate is None else f'{gate} declared')}
    return {'verdict': 'not_established', 'unmet_obligation': 'producer_capability_coverage',
            'reason': 'field gated on %r, producer declared %s: absence of evidence, not evidence of absence'
                      % (gate, 'nothing' if not declared else declared)}
