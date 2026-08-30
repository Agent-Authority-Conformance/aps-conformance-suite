# attenu-guard 0.8.0: successor observation to the 0.6.1 record, both directions

Package: attenu-guard 0.8.0 from PyPI, wheel attenu_guard-0.8.0-py3-none-any.whl,
sha256 3c1a72562f5d0bca841c977ba90f29d99a9b1bcb5de62b11ab2ab21830678d49, Apache-2.0. Source repository
attenu-io/attenu-guard, tag v0.8.0. Installed into a clean venv from the wheel; no
clone. The package ships 19 vectors in attenu_guard.vectors. Checked against the
0.7.1 wheel: the 17 shared vector files are byte-identical; new in 0.8.0:
reject_bare_wildcard.json and reject_nonterminal_wildcard.json.

The runners are the version-agnostic scripts recorded in interop/attenu-guard-0.6.1/;
they read whatever attenu_guard version the environment provides. This record pins
the environment at 0.8.0. Run date 2026-08-30.

## Direction 1: package canonicalization over this corpus's canonical-bytes cases

    python3 -m venv v && v/bin/pip install attenu-guard==0.8.0
    v/bin/python interop/attenu-guard-0.6.1/jcs-byte-diff.py

Result (results-jcs-byte-diff.txt, verbatim): 10 distinct cases, 10 byte-identical.
The runner prints DRIFTED because it compares against the 0.6.1 record's 5/10 match
set; the movement is the package's adoption of RFC 8785 announced for 0.7.1. The
0.6.1 record stays as observed at 0.6.1.

## Direction 2: clean-room draft -00 verifier over the package's 19 vectors

    v/bin/python interop/attenu-guard-0.6.1/cleanroom/verify_asor00.py

Result (results-cleanroom-verify-asor00.txt, verbatim): 15 ok, 4 mismatches, exit 1.
The four: reject_bare_wildcard (want malformed, got not_narrower),
reject_nonterminal_wildcard (want malformed, got accept), reject_non_finite (want
non_finite, got accept), reject_duplicate_member (want duplicate_member, got accept).
The verifier was written from draft -00 and is unchanged; all four vectors pin rules
that postdate -00 (the -01 wildcard grammar and the JCS strictness rules), so the
mismatches measure the distance between -00 and the 0.8.0 vector set, not a defect
in either.

## Verification split

- Package canonicalization over this corpus's cases (direction 1); runner: aeoess via
  jcs-byte-diff.py; Mode B; author-produced; implementation: attenu-guard 0.8.0. The
  implementation is independently authored, but the runner authored the vectors, so
  the row is author-produced under this corpus's definition.
- Draft-semantics recomputation over the package's vectors (direction 2); runner:
  aeoess via cleanroom/verify_asor00.py; Mode B; author-produced; implementation: the
  clean-room -00 verifier, authored by the runner.
- No independent record exists for either layer of this family at 0.8.0; both layers
  are queued in docs/OPEN-RUNS.md.

## Draft -01 reading

Read from the raw repository file docs/draft-asor-wimse-agent-delegation-chain-01.md
at attenu-io/attenu-guard main, not the rendered page. The wildcard rule is stated
for the agent_delegation authorization detail: lowercase dot-separated scopes of at
least two segments; a wildcard only as the complete final segment after a dot; bare
"*", "crm.re*" and "crm.*.read" invalid, producer must not emit, verifier must
reject; "crm.*" covers "crm.read", "crm.x.y.z" and "crm.x.*", not "crm" and not
"crmx.read". One presentation defect, reproduced against the raw file: the rendered
page drops the literal asterisk in the bare-value example and the crm.re example,
while "crm.*.read" and the ABNF survive. The source is correct. Reported on
a2aproject/A2A issue 1575.
